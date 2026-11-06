package tr.com.srp.vpn

import android.os.Build
import android.util.Base64
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.webkit.JavascriptInterface
import android.webkit.WebView
import java.net.Inet4Address
import java.net.InetAddress
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.net.URL

/** Why the outer connection could not be made, in the iOS app's words. */
class SstpConnectFailure(message: String) : Exception(message)

/**
 * The outer TCP connection of an SSTP profile, direct or through its proxy, as SSProxyResolver and SSTCPClient make it on
 * iOS: a manual proxy's protocol is found by negotiation (SOCKS5 first, then HTTP CONNECT on a fresh connection), and an
 * Auto proxy comes from the PAC script, whose entries are tried in order. Blocking; it runs on SstpClient's connect thread.
 */
internal object SstpConnector {
    private const val CONNECT_TIMEOUT_MS = 15000
    private const val NEGOTIATION_TIMEOUT_MS = 10000
    private const val PAC_TIMEOUT_MS = 15000

    /** null type = DIRECT, true = SOCKS5, false = HTTP CONNECT. */
    private data class Hop(val socks: Boolean?, val host: String, val port: Int)

    fun connect(profile: Profile, host: String, port: Int, context: Context, cancelled: () -> Boolean): Socket = when (profile.proxyMode) {
        1 -> {
            ConnectionLog.m("Proxy mode: Manual")
            val proxyHost = profile.proxyAddress.trim()
            val proxyPort = profile.proxyPort.trim().toIntOrNull() ?: 0
            if (proxyHost.isEmpty() || proxyPort !in 1..65535) throw SstpConnectFailure("Proxy configuration incomplete (address and port are required)")
            detect(proxyHost, proxyPort, profile.proxyUsername, profile.proxyPassword, host, port)
        }
        2 -> throughPac(profile, host, port, context, cancelled)
        else -> direct(host, port)
    }

    private fun direct(host: String, port: Int): Socket {
        val socket = Socket()
        try {
            socket.connect(InetSocketAddress(host, port), CONNECT_TIMEOUT_MS)
        } catch (error: Exception) {
            socket.close()
            throw SstpConnectFailure("Cannot reach the server (DNS/TCP/TLS failed). Check the host, port and certificate settings.")
        }
        return socket
    }

    private fun openProxy(host: String, port: Int): Socket {
        val socket = Socket()
        try {
            socket.connect(InetSocketAddress(host, port), CONNECT_TIMEOUT_MS)
        } catch (error: Exception) {
            socket.close()
            val reason = when (error) {
                is SocketTimeoutException -> "no answer"
                else -> error.message?.substringAfterLast(": ")?.substringBefore(" (")?.ifEmpty { null } ?: "no answer"
            }
            throw SstpConnectFailure("Cannot reach the proxy $host:$port ($reason). Check the proxy address and port.")
        }
        socket.soTimeout = NEGOTIATION_TIMEOUT_MS
        return socket
    }

    /** SOCKS5 first; a proxy that does not answer as SOCKS5 gets HTTP CONNECT on a fresh connection. */
    private fun detect(proxyHost: String, proxyPort: Int, username: String, password: String, host: String, port: Int): Socket {
        ConnectionLog.m("Proxy server: $proxyHost:$proxyPort")
        val socks = openProxy(proxyHost, proxyPort)
        val notSocks = try {
            socks5(socks, username, password, host, port)
            ConnectionLog.m("Detected proxy protocol: SOCKS5")
            socks.soTimeout = 0
            return socks
        } catch (failure: SstpConnectFailure) {
            socks.close()
            throw failure
        } catch (error: Exception) {
            socks.close()
            if (error is SocketTimeoutException) "SOCKS5 negotiation timed out" else "no SOCKS5 answer"
        }
        ConnectionLog.m("SOCKS5 negotiation did not complete ($notSocks); retrying as HTTP CONNECT on a fresh connection")
        val http = openProxy(proxyHost, proxyPort)
        try {
            httpConnect(http, username, password, host, port)
            ConnectionLog.m("Detected proxy protocol: HTTP CONNECT")
            http.soTimeout = 0
            return http
        } catch (failure: SstpConnectFailure) {
            http.close()
            throw failure
        } catch (error: Exception) {
            http.close()
            if (error is SocketTimeoutException) throw SstpConnectFailure("HTTP CONNECT timed out")
            throw SstpConnectFailure("Unsupported proxy protocol (neither SOCKS5 nor HTTP CONNECT answered)")
        }
    }

    private fun readFully(input: InputStream, count: Int): ByteArray {
        val bytes = ByteArray(count)
        var read = 0
        while (read < count) {
            val n = input.read(bytes, read, count - read)
            if (n < 0) throw java.io.EOFException()
            read += n
        }
        return bytes
    }

    /** A SOCKS5 verdict is final once the proxy has answered as SOCKS5; anything else throws a plain exception. */
    private fun socks5(socket: Socket, username: String, password: String, host: String, port: Int) {
        val output = socket.getOutputStream()
        val input = socket.getInputStream()
        val credentials = username.isNotEmpty()
        output.write(if (credentials) byteArrayOf(5, 2, 0, 2) else byteArrayOf(5, 1, 0))
        output.flush()
        val reply = readFully(input, 2)
        if (reply[0].toInt() != 5) throw IllegalStateException("not SOCKS5")
        when (reply[1].toInt() and 0xff) {
            0 -> Unit
            2 -> {
                if (!credentials) throw SstpConnectFailure("Proxy authentication required (SOCKS5)")
                val user = username.toByteArray().take(255).toByteArray()
                val pass = password.toByteArray().take(255).toByteArray()
                output.write(byteArrayOf(1, user.size.toByte()) + user + byteArrayOf(pass.size.toByte()) + pass)
                output.flush()
                val verdict = readFully(input, 2)
                if (verdict[1].toInt() != 0) throw SstpConnectFailure("Proxy authentication failed (SOCKS5)")
            }
            else -> throw SstpConnectFailure("SOCKS5 negotiation failed (no acceptable authentication method)")
        }
        val name = host.toByteArray().take(255).toByteArray()
        output.write(byteArrayOf(5, 1, 0, 3, name.size.toByte()) + name + byteArrayOf((port shr 8).toByte(), port.toByte()))
        output.flush()
        val head = readFully(input, 4)
        val code = head[1].toInt() and 0xff
        if (code != 0) throw SstpConnectFailure("SOCKS5 negotiation failed (reply code $code)")
        val rest = when (head[3].toInt()) {
            1 -> 4 + 2
            4 -> 16 + 2
            3 -> (readFully(input, 1)[0].toInt() and 0xff) + 2
            else -> throw SstpConnectFailure("SOCKS5 negotiation failed (reply code $code)")
        }
        readFully(input, rest)
    }

    private fun httpConnect(socket: Socket, username: String, password: String, host: String, port: Int) {
        val request = buildString {
            append("CONNECT $host:$port HTTP/1.1\r\nHost: $host:$port\r\nProxy-Connection: Keep-Alive\r\n")
            if (username.isNotEmpty()) append("Proxy-Authorization: Basic ${Base64.encodeToString("$username:$password".toByteArray(), Base64.NO_WRAP)}\r\n")
            append("\r\n")
        }
        socket.getOutputStream().apply {
            write(request.toByteArray())
            flush()
        }
        // Up to the end of the response header, one byte at a time so nothing after it is taken from the TLS stream
        val input = socket.getInputStream()
        val header = StringBuilder()
        while (!header.endsWith("\r\n\r\n")) {
            val byte = input.read()
            if (byte < 0) throw java.io.EOFException()
            header.append(byte.toChar())
            if (header.length > 8192) throw IllegalStateException("header too long")
        }
        val status = header.lineSequence().first().split(' ').getOrNull(1)?.toIntOrNull() ?: throw IllegalStateException("not HTTP")
        when {
            status == 200 -> Unit
            status == 407 -> throw SstpConnectFailure(if (username.isNotEmpty()) "Proxy authentication failed (HTTP $status)" else "Proxy authentication required (HTTP $status)")
            else -> throw SstpConnectFailure("HTTP CONNECT failed (status $status)")
        }
    }

    private fun throughPac(profile: Profile, host: String, port: Int, context: Context, cancelled: () -> Boolean): Socket {
        ConnectionLog.m("Proxy mode: Auto")
        ConnectionLog.m("PAC URL: ${profile.pacUrl}")
        val url = runCatching { URL(profile.pacUrl.trim()) }.getOrNull()
        if (url == null || (url.protocol != "http" && url.protocol != "https") || url.host.isNullOrEmpty()) {
            throw SstpConnectFailure("Invalid PAC configuration (the PAC URL must be a http(s) URL)")
        }
        val script = runCatching { if (url.protocol == "http") plainGet(url) else httpsGet(url) }.getOrNull()
        if (script == null || script.isEmpty()) throw SstpConnectFailure("Unable to download PAC configuration")
        val text = runCatching { Charsets.UTF_8.newDecoder().decode(java.nio.ByteBuffer.wrap(script)).toString() }.getOrNull()
        if (text.isNullOrEmpty()) throw SstpConnectFailure("Invalid PAC configuration (not a text script)")
        val result = PacEvaluator.findProxy(context, text, host)
        ConnectionLog.m("PAC result: $result")
        val hops = hops(result)
        if (hops.isEmpty()) throw SstpConnectFailure("No usable proxy returned by PAC")
        var failure: SstpConnectFailure? = null
        for ((index, hop) in hops.withIndex()) {
            if (cancelled()) break
            try {
                if (hop.socks == null) return direct(host, port)
                ConnectionLog.m("trying proxy hop ${index + 1}/${hops.size}: ${if (hop.socks) "SOCKS5" else "HTTP CONNECT"} ${hop.host}:${hop.port}")
                val socket = openProxy(hop.host, hop.port)
                try {
                    if (hop.socks) socks5(socket, profile.proxyUsername, profile.proxyPassword, host, port)
                    else httpConnect(socket, profile.proxyUsername, profile.proxyPassword, host, port)
                    socket.soTimeout = 0
                    return socket
                } catch (error: Exception) {
                    socket.close()
                    throw error as? SstpConnectFailure ?: SstpConnectFailure(if (error is SocketTimeoutException) "proxy hop timed out" else "Proxy connection failed")
                }
            } catch (error: SstpConnectFailure) {
                ConnectionLog.m("proxy hop ${index + 1} failed: ${error.message}")
                failure = error
            }
        }
        throw failure ?: SstpConnectFailure("Proxy connection failed (no usable proxy path)")
    }

    private fun httpsGet(url: URL): ByteArray? {
        val connection = url.openConnection() as HttpURLConnection
        connection.connectTimeout = PAC_TIMEOUT_MS
        connection.readTimeout = PAC_TIMEOUT_MS
        return try {
            if (connection.responseCode != 200) null else connection.inputStream.use { it.readBytes() }
        } finally {
            connection.disconnect()
        }
    }

    /**
     * An http:// PAC file over a plain socket: Android's HTTP stack refuses cleartext for apps, and PAC files are often
     * served without TLS. Only a 200 answer counts, with a Content-Length, chunked encoding or the end of the connection.
     */
    private fun plainGet(url: URL): ByteArray? {
        val port = if (url.port > 0) url.port else 80
        Socket().use { socket ->
            socket.connect(InetSocketAddress(url.host, port), PAC_TIMEOUT_MS)
            socket.soTimeout = PAC_TIMEOUT_MS
            val path = (url.path.ifEmpty { "/" }) + (url.query?.let { "?$it" } ?: "")
            val host = if (url.port > 0) "${url.host}:${url.port}" else url.host
            socket.getOutputStream().apply {
                write("GET $path HTTP/1.1\r\nHost: $host\r\nConnection: close\r\nAccept: */*\r\n\r\n".toByteArray())
                flush()
            }
            val input = java.io.BufferedInputStream(socket.getInputStream())
            fun line(): String {
                val text = StringBuilder()
                while (true) {
                    val byte = input.read()
                    if (byte < 0 || byte == '\n'.code) break
                    if (byte != '\r'.code) text.append(byte.toChar())
                    if (text.length > 8192) throw IllegalStateException("line too long")
                }
                return text.toString()
            }
            if (line().split(' ').getOrNull(1) != "200") return null
            val headers = generateSequence { line().takeIf { it.isNotEmpty() } }.associate {
                it.substringBefore(':').trim().lowercase() to it.substringAfter(':').trim()
            }
            val body = java.io.ByteArrayOutputStream()
            when {
                headers["transfer-encoding"]?.lowercase()?.contains("chunked") == true -> while (true) {
                    val size = line().substringBefore(';').trim().toIntOrNull(16) ?: return null
                    if (size == 0) break
                    body.write(readFully(input, size))
                    line()
                }
                headers["content-length"] != null -> body.write(readFully(input, headers["content-length"]!!.toInt()))
                else -> body.write(input.readBytes())
            }
            return body.toByteArray()
        }
    }

    /** The entries of a FindProxyForURL result (SSProxySupport hopsFromPACResultString). */
    private fun hops(result: String): List<Hop> = result.split(';').mapNotNull { entry ->
        val tokens = entry.trim().split(Regex("\\s+")).filter { it.isNotEmpty() }
        if (tokens.isEmpty()) return@mapNotNull null
        when (val keyword = tokens[0].uppercase()) {
            "DIRECT" -> Hop(null, "", 0)
            "PROXY", "SOCKS", "SOCKS5" -> {
                val address = tokens.getOrNull(1) ?: return@mapNotNull null
                val colon = address.lastIndexOf(':')
                if (colon <= 0) return@mapNotNull null
                val port = address.substring(colon + 1).toIntOrNull()?.takeIf { it in 1..65535 } ?: return@mapNotNull null
                Hop(keyword != "PROXY", address.substring(0, colon), port)
            }
            else -> null
        }
    }
}

/**
 * FindProxyForURL in a WebView's JavaScript, with the PAC helper functions SSProxyResolver installs on iOS: the pure ones in
 * JavaScript, and DNS resolution and the device's address through a bridge. Android has no PAC evaluator for apps.
 */
internal object PacEvaluator {
    private const val TIMEOUT_SECONDS = 10L

    private val helpers = """
        function isPlainHostName(host) { return String(host).indexOf('.') < 0; }
        function dnsDomainIs(host, domain) { host = String(host); domain = String(domain); return host.length >= domain.length && host.substring(host.length - domain.length) === domain; }
        function localHostOrDomainIs(host, hostdom) { host = String(host); hostdom = String(hostdom); return host === hostdom || hostdom.indexOf(host + '.') === 0; }
        function shExpMatch(str, pattern) {
            pattern = String(pattern);
            var source = '^';
            for (var i = 0; i < pattern.length; i++) {
                var c = pattern.charAt(i);
                if (c === '*') source += '.*';
                else if (c === '?') source += '.';
                else if ('\\^${'$'}.|+()[]{}/'.indexOf(c) >= 0) source += '\\' + c;
                else source += c;
            }
            return new RegExp(source + '${'$'}').test(String(str));
        }
        function dnsResolve(host) { var address = SRPPac.dnsResolve(String(host)); return address === '' ? null : address; }
        function isResolvable(host) { return SRPPac.dnsResolve(String(host)) !== ''; }
        function myIpAddress() { var address = SRPPac.myIpAddress(); return address === '' ? null : address; }
        function __srpAddress(text) {
            var parts = String(text).split('.');
            if (parts.length !== 4) return null;
            var value = 0;
            for (var i = 0; i < 4; i++) { var part = parseInt(parts[i], 10); if (isNaN(part) || part < 0 || part > 255) return null; value = value * 256 + part; }
            return value;
        }
        function isInNet(ip, network, mask) {
            var a = __srpAddress(ip), n = __srpAddress(network), m = __srpAddress(mask);
            if (a === null || n === null || m === null) return false;
            for (var bit = 2147483648; bit >= 1; bit /= 2) {
                var inMask = Math.floor(m / bit) % 2 === 1;
                if (inMask && (Math.floor(a / bit) % 2) !== (Math.floor(n / bit) % 2)) return false;
            }
            return true;
        }
    """.trimIndent()

    class Bridge {
        @JavascriptInterface
        fun dnsResolve(host: String): String =
            runCatching { InetAddress.getAllByName(host).firstOrNull { it is Inet4Address }?.hostAddress }.getOrNull().orEmpty()

        // Best effort: the local address of a UDP "connection" to a public address (no traffic is sent)
        @JavascriptInterface
        fun myIpAddress(): String = runCatching {
            java.net.DatagramSocket().use {
                it.connect(InetSocketAddress("8.8.8.8", 53))
                it.localAddress.hostAddress.orEmpty()
            }
        }.getOrDefault("")
    }

    /** FindProxyForURL("https://<host>/", host) of [script]; throws the iOS app's PAC messages. Blocking, not on the main thread. */
    fun findProxy(context: Context, script: String, host: String): String {
        val code = buildString {
            append(helpers)
            append("\n(function () {\n")
            append("try { (0, eval)(").append(org.json.JSONObject.quote(script)).append("); } catch (e) { return 'ERR:script'; }\n")
            append("if (typeof FindProxyForURL !== 'function') return 'ERR:function';\n")
            append("try { var result = FindProxyForURL(").append(org.json.JSONObject.quote("https://$host/")).append(", ")
                .append(org.json.JSONObject.quote(host)).append("); } catch (e) { return 'ERR:evaluation'; }\n")
            append("return result === null || result === undefined ? 'ERR:evaluation' : String(result);\n})()")
        }
        val done = CountDownLatch(1)
        var answer: String? = null
        var view: WebView? = null
        val main = Handler(Looper.getMainLooper())
        main.post {
            runCatching {
                val webView = WebView(context.applicationContext)
                view = webView
                @Suppress("SetJavaScriptEnabled")
                webView.settings.javaScriptEnabled = true
                // The PAC script comes from the network: it gets the two PAC helpers and nothing else to reach
                webView.settings.blockNetworkLoads = true
                webView.settings.allowFileAccess = false
                webView.settings.allowContentAccess = false
                webView.addJavascriptInterface(Bridge(), "SRPPac")
                webView.loadUrl("about:blank")
                webView.evaluateJavascript(code) { value ->
                    answer = runCatching { org.json.JSONTokener(value).nextValue() as? String }.getOrNull()
                    done.countDown()
                }
            }.onFailure { done.countDown() }
        }
        val finished = done.await(TIMEOUT_SECONDS, TimeUnit.SECONDS)
        main.post { view?.destroy() }
        val result = answer
        when {
            !finished || result == null || result == "ERR:evaluation" -> throw SstpConnectFailure("PAC evaluation failed")
            result == "ERR:script" -> throw SstpConnectFailure("Invalid PAC configuration (script error)")
            result == "ERR:function" -> throw SstpConnectFailure("Invalid PAC configuration (no FindProxyForURL function)")
            result.isEmpty() -> throw SstpConnectFailure("PAC evaluation failed")
        }
        return result!!
    }
}

/**
 * The certificate check before an SSTP connection starts (PDVPNManager connectUsing on iOS): when the server's certificate
 * is not trusted for the name the tunnel verifies, the user decides. Direct, like iOS's check; a network error says nothing
 * about the certificate, so the connection goes ahead and the tunnel checks again.
 */
internal object SstpCertificateCheck {
    /** The text of the warning, or null when the certificate is trusted or TLS could not start. Blocking. */
    fun issue(profile: Profile): String? {
        val host = profile.server.trim()
        val port = profile.effectivePort.toIntOrNull() ?: 443
        val verifyHost = if (profile.customSniEnabled && profile.customSni.trim().isNotEmpty()) profile.customSni.trim() else host
        var chain: Array<java.security.cert.X509Certificate>? = null
        val capture = object : javax.net.ssl.X509TrustManager {
            override fun checkClientTrusted(certificates: Array<java.security.cert.X509Certificate>, authType: String) = Unit
            override fun checkServerTrusted(certificates: Array<java.security.cert.X509Certificate>, authType: String) {
                chain = certificates
            }
            override fun getAcceptedIssuers() = emptyArray<java.security.cert.X509Certificate>()
        }
        val context = javax.net.ssl.SSLContext.getInstance("TLS").apply { init(null, arrayOf(capture), null) }
        val session = try {
            val socket = context.socketFactory.createSocket() as javax.net.ssl.SSLSocket
            socket.use {
                it.connect(InetSocketAddress(host, port), 10000)
                it.soTimeout = 10000
                if (ProbePackets.ipv4(verifyHost) == null && ':' !in verifyHost) {
                    it.sslParameters = it.sslParameters.apply { serverNames = listOf(javax.net.ssl.SNIHostName(verifyHost)) }
                }
                it.startHandshake()
                it.session
            }
        } catch (error: Exception) {
            return null
        }
        val certificates = chain ?: return null
        val leafErrors = ArrayList<String>()
        if (!javax.net.ssl.HttpsURLConnection.getDefaultHostnameVerifier().verify(verifyHost, session)) leafErrors += "Hostname does not match the certificate"
        val validity = certificates.map { certificate ->
            try {
                certificate.checkValidity()
                null
            } catch (expired: java.security.cert.CertificateExpiredException) {
                "Certificate has expired"
            } catch (early: java.security.cert.CertificateNotYetValidException) {
                "Certificate is not valid yet"
            }
        }
        val trustError = Sstp.trustChain(certificates.map { it.encoded }.toTypedArray())
        if (leafErrors.isEmpty() && validity.all { it == null } && trustError == null) return null
        val text = StringBuilder("TLS verification on the server certificate ($verifyHost) has failed due to the following error. As such, the identity of the server can't be verified at the moment.\n\n")
        for ((index, certificate) in certificates.withIndex()) {
            val subject = certificate.subjectX500Principal.name.split(',').map { it.trim() }.firstOrNull { it.startsWith("CN=") }?.removePrefix("CN=")
                ?: certificate.subjectX500Principal.name
            text.append("Certificate $index \"$subject\"")
            val errors = ArrayList<String>()
            if (index == 0) errors += leafErrors
            validity[index]?.let { errors += it }
            if (index == certificates.lastIndex && trustError != null && validity.all { it == null }) errors += "Root is not trusted"
            if (errors.isNotEmpty()) text.append(" has errors: ${errors.joinToString("; ")};")
            text.append('\n')
        }
        text.append("\nThis may indicate a server misconfiguration or an ongoing MITM attack. Do you want to trust the server certificate and continue? Choose Cancel if you are unsure.")
        return text.toString()
    }
}
