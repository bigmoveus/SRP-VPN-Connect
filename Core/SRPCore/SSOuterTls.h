//
//  SSOuterTls.h
//  SRPCore
//
//  TLS options for the OUTER SSTP connection (Network.framework).
//  Extracted so SSTCPClient and the knob test binary share one code path.
//  Note: the EAP inner TLS tunnels (PEAP/TTLS/TEAP) have their own knobs in
//  EAP Configuration (eap_tls13 / eap_disable_legacy_tls); this helper only
//  affects the outer SSTP TLS session.
//

#import <Foundation/Foundation.h>
#import <Network/Network.h>

NS_ASSUME_NONNULL_BEGIN

/// Configure TLS options for the outer SSTP connection.
///   sni:           TLS server name (may be NULL — endpoint host is used)
///   allowInsecure: skip certificate verification (user accepted the risk)
///   disableLegacy: require TLS >= 1.2 (the "Disable TLS 1.0 & 1.1" switch)
///   queue:         queue for the verify block (insecure mode)
void SSConfigureOuterTLSOptions(nw_protocol_options_t options,
                                const char * _Nullable sni,
                                BOOL allowInsecure,
                                BOOL disableLegacy,
                                dispatch_queue_t queue);

NS_ASSUME_NONNULL_END
