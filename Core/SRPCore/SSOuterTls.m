//
//  SSOuterTls.m
//  SRPCore
//

#import "SSOuterTls.h"

void SSConfigureOuterTLSOptions(nw_protocol_options_t options,
                                const char *sni,
                                BOOL allowInsecure,
                                BOOL disableLegacy,
                                dispatch_queue_t queue) {
    sec_protocol_options_t option = nw_tls_copy_sec_protocol_options(options);

    if (disableLegacy) {
        // Require TLS 1.2+ on the outer SSTP connection
        sec_protocol_options_set_min_tls_protocol_version(option, tls_protocol_version_TLSv12);
    }
    if (sni != NULL) {
        sec_protocol_options_set_tls_server_name(option, sni);
    }
    if (allowInsecure) {
        // User accepted the risk — verification is skipped
        sec_protocol_options_set_verify_block(option, ^(sec_protocol_metadata_t metadata,
                                                        sec_trust_t trust_ref,
                                                        sec_protocol_verify_complete_t complete) {
            complete(true);
        }, queue);
    }
}
