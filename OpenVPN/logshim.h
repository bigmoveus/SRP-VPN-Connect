/* Force-included at the very top of the ovpncli.cpp build.
 * ovpncli.cpp defines OPENVPN_LOG only at ~line 66 (before including
 * logthread.hpp), but several core headers pulled in earlier (via
 * ovpncli.hpp) already use OPENVPN_LOG in eagerly-compiled code paths.
 * Defining the logthread variant from line 0 keeps those paths valid.
 * LogReceiver only needs to be complete when the macro is *used* (after
 * ovpncli.hpp), a forward declaration is enough for logthread_class.hpp. */
namespace openvpn::ClientAPI { struct LogReceiver; }
#define OPENVPN_LOG_CLASS openvpn::ClientAPI::LogReceiver
#define OPENVPN_LOG_INFO openvpn::ClientAPI::LogInfo
#include <openvpn/log/logthread.hpp>
