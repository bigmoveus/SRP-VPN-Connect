// The OpenVPN of the Android app: OpenVPN 3 Core (the iOS app's vendored release/3.11.7 in iOS/OpenVPN, built with the
// flags of iOS/OpenVPN/build_openvpn.sh) with an external TUN. The settings a server pushes go to OpenVpnClient.kt as an
// event; it brings the tunnel up and attaches its fd, and the packets then go between that fd and the core here. The
// core's UDP and TCP transports are its own; for stunnel, OpenVpnClient.kt runs the outer TLS itself (StunnelRelay.kt)
// and the core connects over TCP to its local end. OpenVpnClient.kt decides on reconnects from the core's events, as
// SRPOpenVPNClient.mm does. The home screen's ping flows (probe flows, as in ssh_jni.c) come back to it instead of the
// tunnel. The app stays outside its own tunnel, so the core's sockets need no protect().

#include <errno.h>
#include <fcntl.h>
#include <jni.h>
#include <poll.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "ovpncli.hpp"
#include <openvpn/tun/client/tunbase.hpp>
#include <openvpn/tun/extern/config.hpp>
#include <openvpn/transport/client/transbase.hpp>
#include <openvpn/transport/client/extern/config.hpp>
#include <openvpn/transport/client/udpcli.hpp>
#include <openvpn/transport/client/tcpcli.hpp>

namespace openvpn::logging {
void srp_log_sink(const std::string &s);
}

namespace {

constexpr size_t kMaxEvents = 1024;
constexpr size_t kMaxPacket = 65535;
constexpr size_t kMaxProbeQueue = 64;
constexpr int kMaxInFlight = 2048;   // packets read from the tunnel and not yet taken by the core

// Events for OpenVpnClient.kt: "session|type|text". Types: L (a log line), E (a core event: NAME|error|fatal|info),
// S (settings to apply: "request\nserver address\noption words separated by tabs\n..."), X (the core stopped: message).
std::mutex event_lock;
std::condition_variable event_ready;
std::deque<std::string> event_queue;
std::atomic<int> current_session{0};

void push_event(int session, char type, const std::string &text) {
    std::lock_guard<std::mutex> guard(event_lock);
    if (event_queue.size() >= kMaxEvents) event_queue.pop_front();
    event_queue.push_back(std::to_string(session) + "|" + type + "|" + text);
    event_ready.notify_one();
}

// Probe flows: answers to the home screen's ping go to OpenVpnClient.kt, not to the tunnel
struct ProbeFlow {
    int protocol;
    uint8_t source[4];
    uint16_t destination_port;
};
std::mutex probe_lock;
std::condition_variable probe_ready;
std::vector<ProbeFlow> probe_flows;
std::deque<std::vector<uint8_t>> probe_queue;

bool matches_probe_flow(const uint8_t *packet, size_t length) {
    if (length < 24 || (packet[0] >> 4) != 4) return false;
    size_t ihl = (size_t)(packet[0] & 0x0f) * 4;
    if (ihl < 20 || length < ihl + 4) return false;
    uint16_t port = (uint16_t)((packet[ihl + 2] << 8) | packet[ihl + 3]);
    std::lock_guard<std::mutex> guard(probe_lock);
    for (const ProbeFlow &flow : probe_flows) {
        if (flow.protocol == packet[9] && memcmp(flow.source, packet + 12, 4) == 0 && flow.destination_port == port) return true;
    }
    return false;
}

void queue_probe(const uint8_t *packet, size_t length) {
    std::lock_guard<std::mutex> guard(probe_lock);
    if (probe_queue.size() >= kMaxProbeQueue) probe_queue.pop_front();   // nobody reads them: keep the newest
    probe_queue.emplace_back(packet, packet + length);
    probe_ready.notify_one();
}

class AndroidTun;

// The running core's io_context (once it made a TUN) and its TUN; the io_context is guarded by io_lock, the TUN is the
// core thread's
std::mutex io_lock;
openvpn_io::io_context *core_io = nullptr;
AndroidTun *core_tun = nullptr;
std::atomic<int> in_flight{0};

// The settings exchange: a TUN waits until OpenVpnClient.kt has applied the request it sent
std::mutex tun_lock;
std::condition_variable tun_answered;
int tun_request = 0;
int tun_answer = 0;
bool tun_stopping = false;

// The tunnel's fd and the thread that reads it
std::atomic<int> tun_fd{-1};
int wake_pipe[2] = {-1, -1};
std::thread reader;

class AndroidTun : public openvpn::TunClient {
  public:
    AndroidTun(openvpn_io::io_context &io, openvpn::TunClientParent &parent, int session, openvpn::Frame::Ptr frame)
        : parent_(parent), session_(session), frame_(std::move(frame)) {
        {
            std::lock_guard<std::mutex> guard(io_lock);
            core_io = &io;
        }
        core_tun = this;
    }

    ~AndroidTun() override {
        if (core_tun == this) core_tun = nullptr;
    }

    void tun_start(const openvpn::OptionList &opt, openvpn::TransportClient &transcli, openvpn::CryptoDCSettings &) override {
        openvpn::IP::Addr server = transcli.server_endpoint_addr();
        std::string text = server.defined() ? server.to_string() : "";
        for (const auto &option : opt) {
            text += '\n';
            for (size_t i = 0; i < option.size(); i++) {
                if (i) text += '\t';
                text += option.get(i, 256);
            }
        }
        int request;
        {
            std::lock_guard<std::mutex> guard(tun_lock);
            request = ++tun_request;
        }
        push_event(session_, 'S', std::to_string(request) + "\n" + text);
        // The core requires the TUN to be up when tun_start returns
        std::unique_lock<std::mutex> lock(tun_lock);
        if (!tun_answered.wait_for(lock, std::chrono::seconds(10), [request] { return tun_answer >= request || tun_stopping; })) {
            openvpn::logging::srp_log_sink("OpenVPN: the tunnel settings were not confirmed within 10 seconds");
        }
        lock.unlock();
        parent_.tun_connected();
    }

    void stop() override { stopped_ = true; }
    void set_disconnect() override {}

    bool tun_send(openvpn::BufferAllocated &buf) override {
        const uint8_t *data = buf.c_data();
        size_t length = buf.size();
        if (stopped_ || length == 0) return true;
        if (matches_probe_flow(data, length)) {
            queue_probe(data, length);
            return true;
        }
        int fd = tun_fd.load();
        if (fd >= 0) (void)write(fd, data, length);   // a full tunnel queue drops it, as a network would
        return true;
    }

    // A packet from the tunnel or a probe, on the core thread. The buffer has the frame's room around the packet:
    // encryption writes its header (and CBC's IV and HMAC) in front of it
    void deliver(const uint8_t *data, size_t length) {
        if (stopped_) return;
        openvpn::BufferAllocated buf;
        frame_->prepare(openvpn::Frame::READ_TUN, buf);
        if (length > buf.remaining(0)) return;
        buf.write(data, length);
        parent_.tun_recv(buf);
    }

    std::string tun_name() const override { return "tun"; }
    std::string vpn_ip4() const override { return ""; }
    std::string vpn_ip6() const override { return ""; }
    int vpn_mtu() const override { return 1500; }

  private:
    openvpn::TunClientParent &parent_;
    int session_;
    openvpn::Frame::Ptr frame_;
    bool stopped_ = false;
};

class AndroidTunFactory : public openvpn::TunClientFactory {
  public:
    AndroidTunFactory(int session, openvpn::Frame::Ptr frame) : session_(session), frame_(std::move(frame)) {}

    openvpn::TunClient::Ptr new_tun_client_obj(openvpn_io::io_context &io, openvpn::TunClientParent &parent,
                                               openvpn::TransportClient *) override {
        return openvpn::TunClient::Ptr(new AndroidTun(io, parent, session_, frame_));
    }

    bool supports_epoch_data() override { return false; }

  private:
    int session_;
    openvpn::Frame::Ptr frame_;
};

// A packet into the core: posted to its thread, where its current TUN takes it
int post_packet(const uint8_t *data, size_t length) {
    std::lock_guard<std::mutex> guard(io_lock);
    if (core_io == nullptr) return -ENOTCONN;
    in_flight++;
    openvpn_io::post(*core_io, [packet = std::vector<uint8_t>(data, data + length)]() {
        in_flight--;
        if (core_tun != nullptr) core_tun->deliver(packet.data(), packet.size());
    });
    return 0;
}

// The tunnel -> the core. Reading waits while the core has many packets queued: backpressure instead of a queue that grows
void read_tunnel() {
    std::vector<uint8_t> packet(kMaxPacket);
    while (true) {
        int fd = tun_fd.load();
        struct pollfd fds[2] = {{wake_pipe[0], POLLIN, 0}, {fd, POLLIN, 0}};
        if (poll(fds, fd >= 0 ? 2 : 1, -1) < 0) {
            if (errno == EINTR) continue;
            return;
        }
        if (fds[0].revents & POLLIN) {
            char drain[16];
            ssize_t got = read(wake_pipe[0], drain, sizeof(drain));
            if (got > 0 && memchr(drain, 'q', (size_t)got) != nullptr) return;
            continue;   // the tunnel's fd changed
        }
        if (fd < 0 || !(fds[1].revents & POLLIN)) {
            if (fd >= 0 && (fds[1].revents & (POLLERR | POLLHUP | POLLNVAL))) std::this_thread::sleep_for(std::chrono::milliseconds(20));
            continue;
        }
        for (int i = 0; i < 64; i++) {
            while (in_flight.load() > kMaxInFlight) std::this_thread::sleep_for(std::chrono::milliseconds(1));
            ssize_t length = read(fd, packet.data(), packet.size());
            if (length <= 0) break;
            int version = packet[0] >> 4;
            if (version != 4 && version != 6) continue;
            (void)post_packet(packet.data(), (size_t)length);
        }
    }
}

void wake_reader(char byte) {
    if (wake_pipe[1] >= 0) (void)write(wake_pipe[1], &byte, 1);
}

class Client : public openvpn::ClientAPI::OpenVPNClient {
  public:
    explicit Client(int session) : session_(session) {}

    openvpn::TunClientFactory *new_tun_factory(const openvpn::ExternalTun::Config &conf, const openvpn::OptionList &) override {
        return new AndroidTunFactory(session_, conf.frame);
    }

    // The core's own UDP and TCP transports, as on iOS (the external factory keeps both builds of the core the same)
    openvpn::TransportClientFactory *new_transport_factory(const openvpn::ExternalTransport::Config &conf) override {
        if (conf.protocol.is_udp()) {
            openvpn::UDPTransport::ClientConfig::Ptr c = openvpn::UDPTransport::ClientConfig::new_obj();
            c->remote_list = conf.remote_list;
            c->frame = conf.frame;
            c->stats = conf.stats;
            c->socket_protect = conf.socket_protect;
            c->server_addr_float = conf.server_addr_float;
            transport_ = c;
            return transport_.get();
        }
        openvpn::TCPTransport::ClientConfig::Ptr c = openvpn::TCPTransport::ClientConfig::new_obj();
        c->remote_list = conf.remote_list;
        c->frame = conf.frame;
        c->stats = conf.stats;
        c->socket_protect = conf.socket_protect;
        transport_ = c;
        return transport_.get();
    }

    void log(const openvpn::ClientAPI::LogInfo &info) override {
        std::string text = info.text;
        while (!text.empty() && (text.back() == '\n' || text.back() == '\r')) text.pop_back();
        push_event(session_, 'L', text);
    }

    void event(const openvpn::ClientAPI::Event &ev) override {
        push_event(session_, 'E', ev.name + "|" + (ev.error ? "1" : "0") + "|" + (ev.fatal ? "1" : "0") + "|" + ev.info);
    }

    void acc_event(const openvpn::ClientAPI::AppCustomControlMessageEvent &) override {}
    bool pause_on_connection_timeout() override { return false; }
    void external_pki_cert_request(openvpn::ClientAPI::ExternalPKICertRequest &) override {}
    void external_pki_sign_request(openvpn::ClientAPI::ExternalPKISignRequest &) override {}

  private:
    int session_;
    openvpn::TransportClientFactory::Ptr transport_;
};

std::mutex session_lock;
Client *client = nullptr;
std::thread core_thread;
std::mutex exit_lock;
std::condition_variable exit_signal;
bool core_exited = true;

// Stops the running core and waits for its thread (up to 15 s; a core that does not stop is left alone)
void stop_locked() {
    if (client == nullptr) return;
    {
        std::lock_guard<std::mutex> guard(io_lock);
        core_io = nullptr;
    }
    {
        std::lock_guard<std::mutex> guard(tun_lock);
        tun_stopping = true;
    }
    tun_answered.notify_all();
    bool exited = false;
    for (int i = 0; i < 150 && !exited; i++) {
        client->stop();   // repeated: a stop before connect() is ready does nothing
        std::unique_lock<std::mutex> lock(exit_lock);
        exited = exit_signal.wait_for(lock, std::chrono::milliseconds(100), [] { return core_exited; });
    }
    if (exited) {
        core_thread.join();
        delete client;
    } else {
        openvpn::logging::srp_log_sink("OpenVPN: the core thread did not stop within 15 seconds; leaving it");
        core_thread.detach();
    }
    client = nullptr;
    in_flight = 0;
}

std::string utf(JNIEnv *env, jstring text) {
    if (text == nullptr) return "";
    const char *chars = env->GetStringUTFChars(text, nullptr);
    std::string value = chars != nullptr ? chars : "";
    if (chars != nullptr) env->ReleaseStringUTFChars(text, chars);
    return value;
}

}  // namespace

namespace openvpn::logging {
/// Backend for the OPENVPN_LOG fallback defined in logger.hpp (SRP build)
void srp_log_sink(const std::string &s) {
    std::string text = s;
    while (!text.empty() && (text.back() == '\n' || text.back() == '\r')) text.pop_back();
    push_event(current_session.load(), 'L', text);
}
}  // namespace openvpn::logging

extern "C" {

// A new core (the previous one stops first). Returns "OK\tremote host\tremote port\tremote proto" when it runs,
// "ERR\tmessage" for a profile the core refuses, "CREDS" when the profile needs a username the call did not give.
JNIEXPORT jstring JNICALL Java_tr_com_srp_vpn_OpenVpnNative_start(JNIEnv *env, jclass, jint session, jstring profile,
                                                                 jstring username, jstring password, jstring server,
                                                                 jstring port, jstring proto, jboolean disableClientCert) {
    std::lock_guard<std::mutex> guard(session_lock);
    stop_locked();
    if (wake_pipe[0] < 0) {
        if (pipe(wake_pipe) != 0) return env->NewStringUTF("ERR\tinternal error: no pipe");
        fcntl(wake_pipe[0], F_SETFL, O_NONBLOCK);
        reader = std::thread(read_tunnel);
        reader.detach();
    }
    current_session = session;
    openvpn::ClientAPI::Config conf;
    conf.content = utf(env, profile);
    conf.serverOverride = utf(env, server);
    conf.portOverride = utf(env, port);
    conf.protoOverride = utf(env, proto);
    conf.disableClientCert = disableClientCert;
    // AES-CBC with HMAC as well as the AEAD ciphers: older servers offer only CBC (the legacy BF-CBC and DES stay off)
    conf.enableNonPreferredDCAlgorithms = true;
    conf.platformVersion = "Android";
    Client *next = new Client(session);
    openvpn::ClientAPI::EvalConfig eval = next->eval_config(conf);
    if (eval.error) {
        delete next;
        return env->NewStringUTF(("ERR\t" + eval.message).c_str());
    }
    if (!eval.autologin) {
        std::string user = utf(env, username);
        if (user.empty()) {
            delete next;
            return env->NewStringUTF("CREDS");
        }
        openvpn::ClientAPI::ProvideCreds creds;
        creds.username = user;
        creds.password = utf(env, password);
        openvpn::ClientAPI::Status status = next->provide_creds(creds);
        if (status.error) {
            delete next;
            return env->NewStringUTF(("ERR\tOpenVPN credentials rejected by the profile: " + status.message).c_str());
        }
    }
    {
        std::lock_guard<std::mutex> lock(tun_lock);
        tun_stopping = false;
    }
    {
        std::lock_guard<std::mutex> lock(exit_lock);
        core_exited = false;
    }
    client = next;
    core_thread = std::thread([next, session]() {
        openvpn::ClientAPI::Status status;
        try {
            status = next->connect();
        } catch (const std::exception &e) {
            status.error = true;
            status.message = std::string("exception: ") + e.what();
        } catch (...) {
            status.error = true;
            status.message = "unknown exception";
        }
        {
            std::lock_guard<std::mutex> lock(io_lock);
            core_io = nullptr;
        }
        push_event(session, 'X', status.error ? status.message : "");
        std::lock_guard<std::mutex> lock(exit_lock);
        core_exited = true;
        exit_signal.notify_all();
    });
    return env->NewStringUTF(("OK\t" + eval.remoteHost + "\t" + eval.remotePort + "\t" + eval.remoteProto).c_str());
}

// Ends the core; no event of it counts after this returns
JNIEXPORT void JNICALL Java_tr_com_srp_vpn_OpenVpnNative_stop(JNIEnv *, jclass) {
    std::lock_guard<std::mutex> guard(session_lock);
    stop_locked();
}

// The core moves its connection to the current network path (Switch to Wi-Fi)
JNIEXPORT void JNICALL Java_tr_com_srp_vpn_OpenVpnNative_reconnect(JNIEnv *, jclass) {
    std::lock_guard<std::mutex> guard(session_lock);
    if (client != nullptr) client->reconnect(0);
}

// The tunnel's fd for a settings request (-1: none); the previous fd can close once this returns
JNIEXPORT void JNICALL Java_tr_com_srp_vpn_OpenVpnNative_attachTun(JNIEnv *, jclass, jint fd, jint request) {
    if (fd >= 0) fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
    tun_fd = fd;
    wake_reader('c');
    {
        std::lock_guard<std::mutex> guard(tun_lock);
        if (request > tun_answer) tun_answer = request;
    }
    tun_answered.notify_all();
}

// A probe packet into the tunnel: 0 when sent, a negative errno otherwise
JNIEXPORT jint JNICALL Java_tr_com_srp_vpn_OpenVpnNative_submit(JNIEnv *env, jclass, jbyteArray packet) {
    jsize length = env->GetArrayLength(packet);
    if (length <= 0 || (size_t)length > kMaxPacket) return -EINVAL;
    std::vector<uint8_t> bytes((size_t)length);
    env->GetByteArrayRegion(packet, 0, length, reinterpret_cast<jbyte *>(bytes.data()));
    return post_packet(bytes.data(), bytes.size());
}

// Answers of these flows come back through nextProbe: triples of protocol, source IPv4 (as an int), destination port
JNIEXPORT void JNICALL Java_tr_com_srp_vpn_OpenVpnNative_setProbeFlows(JNIEnv *env, jclass, jintArray flows) {
    jsize count = flows != nullptr ? env->GetArrayLength(flows) : 0;
    std::vector<jint> values((size_t)count);
    if (count > 0) env->GetIntArrayRegion(flows, 0, count, values.data());
    std::lock_guard<std::mutex> guard(probe_lock);
    probe_flows.clear();
    probe_queue.clear();
    for (jsize i = 0; i + 2 < count; i += 3) {
        ProbeFlow flow{};
        flow.protocol = values[(size_t)i];
        uint32_t source = (uint32_t)values[(size_t)i + 1];
        flow.source[0] = (uint8_t)(source >> 24);
        flow.source[1] = (uint8_t)(source >> 16);
        flow.source[2] = (uint8_t)(source >> 8);
        flow.source[3] = (uint8_t)source;
        flow.destination_port = (uint16_t)values[(size_t)i + 2];
        probe_flows.push_back(flow);
    }
}

JNIEXPORT jbyteArray JNICALL Java_tr_com_srp_vpn_OpenVpnNative_nextProbe(JNIEnv *env, jclass, jint timeout_ms) {
    std::unique_lock<std::mutex> lock(probe_lock);
    if (!probe_ready.wait_for(lock, std::chrono::milliseconds(timeout_ms), [] { return !probe_queue.empty(); })) return nullptr;
    std::vector<uint8_t> packet = std::move(probe_queue.front());
    probe_queue.pop_front();
    lock.unlock();
    jbyteArray result = env->NewByteArray((jsize)packet.size());
    env->SetByteArrayRegion(result, 0, (jsize)packet.size(), reinterpret_cast<const jbyte *>(packet.data()));
    return result;
}

// The next event as UTF-8 bytes (the core's texts may hold any bytes; NewStringUTF would refuse some), or null
JNIEXPORT jbyteArray JNICALL Java_tr_com_srp_vpn_OpenVpnNative_nextEvent(JNIEnv *env, jclass, jint timeout_ms) {
    std::unique_lock<std::mutex> lock(event_lock);
    if (!event_ready.wait_for(lock, std::chrono::milliseconds(timeout_ms), [] { return !event_queue.empty(); })) return nullptr;
    std::string text = std::move(event_queue.front());
    event_queue.pop_front();
    lock.unlock();
    jbyteArray result = env->NewByteArray((jsize)text.size());
    env->SetByteArrayRegion(result, 0, (jsize)text.size(), reinterpret_cast<const jbyte *>(text.data()));
    return result;
}

}  // extern "C"
