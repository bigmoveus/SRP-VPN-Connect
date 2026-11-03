
#import "CCCodec.h"

NS_ASSUME_NONNULL_BEGIN

typedef enum : UInt8 {
    CCWebSocketOpCodeContinueFrame = 0x00,
    CCWebSocketOpCodeText = 0x01,
    CCWebSocketOpCodeBinary = 0x02,
    
    // 3-7 are reserved.
    CCWebSocketOpCodeClose = 0x08,
    CCWebSocketOpCodePing = 0x09,
    CCWebSocketOpCodePong = 0x0A
    // B-F reserved.
} CCWebSocketOpCode;


typedef enum CCCloseCode : NSInteger {
    // 0–999: Reserved and not used.
    CCCloseCodeNormal = 1000,
    CCCloseCodeGoingAway = 1001,
    CCCloseCodeProtocolError = 1002,
    CCCloseCodeUnhandledType = 1003,
    // 1004 reserved.
    CCCloseCodeNoStatusReceived = 1005,
    CCCloseCodeAbnormal = 1006,
    CCCloseCodeInvalidUTF8 = 1007,
    CCCloseCodePolicyViolated = 1008,
    CCCloseCodeMessageTooBig = 1009,
    CCCloseCodeMissingExtension = 1010,
    CCCloseCodeInternalError = 1011,
    CCCloseCodeServiceRestart = 1012,
    CCCloseCodeTryAgainLater = 1013,
    // 1014: Reserved for future use by the WebSocket standard.
    CCCloseCodeTLSHandshake = 1015,
    // 1016–1999: Reserved for future use by the WebSocket standard.
    // 2000–2999: Reserved for use by WebSocket extensions.
    // 3000–3999: Available for use by libraries and frameworks. May not be used by applications. Available for registration at the IANA via first-come, first-serve.
    // 4000–4999: Available for use by applications.
} CCCloseCode;

@interface CCWebSocket : CCCodec
-(instancetype)initWithURL:(NSURL *)url;

-(instancetype)initWithRequest:(NSURLRequest *)request protocols:(nullable NSArray <NSString *> *)protocols;

@property (nonatomic, strong)NSDictionary *allHTTPHeaderFields;

@property (nonatomic)BOOL auto_reply_ping;

@end

NS_ASSUME_NONNULL_END
