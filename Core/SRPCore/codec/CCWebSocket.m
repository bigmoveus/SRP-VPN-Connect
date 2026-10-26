
#import "CCWebSocket.h"
#import <CommonCrypto/CommonHMAC.h>
#import "SRSIMDHelpers.h"

static uint8_t const DMFinMask                = 0x80;
static uint8_t const DMOpCodeMask             = 0x0F;
static uint8_t const DMMaskMask               = 0x80;
static uint8_t const DMRSVMask                = 0x70;
static uint8_t const DMPayloadLenMask         = 0x7F;
static int const DMHttpSwitchProtocolCode     = 101;
static int const DMSRFrameHeaderOverhead          = 32;
static uint8_t const DMFrameHeaderLength      = 2;
static uint8_t const DMMAXHeaderLength        = 2 + 8 + 4;


struct cc_websocket_header {
    uint8_t fin         :1;
    uint8_t rsv1        :1;
    uint8_t rsv2        :1;
    uint8_t rsv3        :1;
    uint8_t opcode      :4;
    
    uint8_t mask        :1;
    uint8_t payload_len :7;
};


/*
 
https://datatracker.ietf.org/doc/html/rfc6455
 
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-------+-+-------------+-------------------------------+
|F|R|R|R| opcode|M| Payload len |    Extended payload length    |
|I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
|N|V|V|V|       |S|             |   (if payload len==126/127)   |
| |1|2|3|       |K|             |                               |
+-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
|     Extended payload length continued, if payload len == 127  |
+ - - - - - - - - - - - - - - - +-------------------------------+
|                               |Masking-key, if MASK set to 1  |
+-------------------------------+-------------------------------+
| Masking-key (continued)       |          Payload Data         |
+-------------------------------- - - - - - - - - - - - - - - - +
:                     Payload Data continued ...                :
+ - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
|                     Payload Data continued ...                |
+---------------------------------------------------------------+
 
 */

static NSString *const IMWebSocketAppendToSecKeyString = @"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

@implementation NSURL (IMWebSocket)

- (NSString *)origin;
{
    NSString *scheme = [self.scheme lowercaseString];
    if ([scheme isEqualToString:@"wss"]) {
        scheme = @"https";
    } else if ([scheme isEqualToString:@"ws"]) {
        scheme = @"http";
    }
    BOOL portIsDefault = !self.port ||
    ([scheme isEqualToString:@"http"] && self.port.integerValue == 80) ||
    ([scheme isEqualToString:@"https"] && self.port.integerValue == 443);
    if (!portIsDefault) {
        return [NSString stringWithFormat:@"%@://%@:%@", scheme, self.host, self.port];
    } else {
        return [NSString stringWithFormat:@"%@://%@", scheme, self.host];
    }
}

@end

@implementation CCWebSocket
{
    NSString *_securityKey;
    NSURLRequest *_request;
    NSArray *_protocols;
    CCCodecStatus _status;
    NSMutableData *_balance;
}

-(instancetype)initWithRequest:(NSURLRequest *)request protocols:(NSArray <NSString *> *)protocols {
    self = [super init];
    if (self) {
        NSMutableData *keyBytes = [[NSMutableData alloc] initWithLength:16];
        int rc = SecRandomCopyBytes(kSecRandomDefault, keyBytes.length, keyBytes.mutableBytes);
        if (rc) NSLog(@"SecRandomCopyBytes failure: %d", rc);
        _request = request;
        _protocols = protocols;
        _securityKey = [keyBytes base64EncodedStringWithOptions:0];
        _status = CCCodecStatusIDLE;
        _balance = [NSMutableData new];
    }
    return self;
}

-(instancetype)initWithURL:(NSURL *)url{
    return [self initWithRequest:[NSURLRequest requestWithURL:url] protocols:nil];
}

-(void)encode:(uint8_t *)message length:(int)length {
    NSData *msg = [self createFrame:message payloadLength:length opCode:CCWebSocketOpCodeText];
    [self.delegate codec:self write:(uint8_t *)msg.bytes length:(int)msg.length];
}

-(NSString *)SHA1_BASE64:(const char *)bytes length:(NSInteger)length{
    uint8_t digest[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1(bytes, (CC_LONG)length, digest);
    NSData * result = [NSData dataWithBytes:digest length:CC_SHA1_DIGEST_LENGTH];
    NSString *s = [result base64EncodedStringWithOptions:0];
    return s;
}

-(NSData *)createFrame:(uint8_t *)message payloadLength:(NSInteger)payloadLength opCode:(UInt8)opCode{
    NSMutableData *frame = [[NSMutableData alloc]initWithLength:payloadLength + DMSRFrameHeaderOverhead];
 
    uint8_t *frame_buffer = (uint8_t *)[frame mutableBytes];
    frame_buffer[0] = DMFinMask | opCode;
    
    // set the mask and header
    frame_buffer[1] |= DMMaskMask;
    
    size_t frame_buffer_size = 2;
    const uint8_t *unmasked_payload = message;
    
    if (payloadLength < 126) {
        frame_buffer[1] |= payloadLength;
    } else if (payloadLength <= UINT16_MAX) {
        frame_buffer[1] |= 126;
#if TARGET_OS_OSX
        *((uint16_t *)(frame_buffer + frame_buffer_size)) = EndianU16_BtoN((uint16_t)payloadLength);
#else
        *((uint16_t *)(frame_buffer + frame_buffer_size)) = htons((uint16_t)payloadLength);
#endif
        frame_buffer_size += sizeof(uint16_t);
    } else {
        frame_buffer[1] |= 127;
#if TARGET_OS_OSX
        *((uint64_t *)(frame_buffer + frame_buffer_size)) = EndianU64_BtoN((uint64_t)payloadLength);
#else
        *((uint64_t *)(frame_buffer + frame_buffer_size)) = htonll((uint64_t)payloadLength);
#endif
        frame_buffer_size += sizeof(uint64_t);
    }
 
    uint8_t *mask_key = frame_buffer + frame_buffer_size;
    int rc = SecRandomCopyBytes(kSecRandomDefault, sizeof(uint32_t), (uint8_t *)mask_key);
    if (rc) NSLog(@"SecRandomCopyBytes Error: %d", rc);
    frame_buffer_size += sizeof(uint32_t);
    
//    Method1
    memcpy(frame_buffer + frame_buffer_size, unmasked_payload, payloadLength);
    SRMaskBytesSIMD(frame_buffer + frame_buffer_size, payloadLength, mask_key);
    frame_buffer_size += payloadLength;
    
// Method2
//    for (size_t i = 0; i < payloadLength; i++) {
//        frame_buffer[frame_buffer_size] = unmasked_payload[i] ^ mask_key[i % sizeof(uint32_t)];
//        frame_buffer_size += 1;
//    }
    assert(frame_buffer_size <= [frame length]);
    frame.length = frame_buffer_size;
    return frame;
}

-(void)decode:(uint8_t *)message length:(int)length {
    [_balance appendBytes:message length:length];
    // TODO: unused for now; implementing it would reduce memory usage
    int toffset = 0;
    while (true) {
        BOOL again = [self decode:&toffset];
        if (!again) {
            break;
        }
    }
}

-(BOOL)decode:(int *)toffset {
    switch (_status) {
        case CCCodecStatusConnecting: {
            NSString *header = [[NSString alloc]initWithData:_balance encoding:NSUTF8StringEncoding];
            BOOL isComplete = [header containsString:@"\r\n\r\n"];
            if (!isComplete) {
                return NO;
            }
            NSArray <NSString *>*headers = [header componentsSeparatedByString:@"\r\n"];
            NSString *topLine = headers.firstObject;
            NSArray *topLines = [topLine componentsSeparatedByString:@" "];
            NSInteger code = 0;
            if (topLines.count >= 3) {
                code = [topLines[1] integerValue];
            }
            if (code == DMHttpSwitchProtocolCode) {
                // The protocol has changed
                NSMutableDictionary *info = [NSMutableDictionary new];
                for (NSInteger i=1; i<headers.count; i++) {
                    NSString *item = headers[i];
                    NSArray <NSString *>*items = [item componentsSeparatedByString:@":"];
                    if (items.count >= 2) {
                        NSString *key = [items[0] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
                        NSString *value = [items[1] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
                        info[key] = value;
                    }
                }
                NSString *footprint = info[@"Sec-WebSocket-Accept"];
                NSString * password = [_securityKey stringByAppendingString:IMWebSocketAppendToSecKeyString];
                password = [self SHA1_BASE64:password.UTF8String length:password.length];
                
                if ([password isEqualToString:footprint]) {
                    _status = CCCodecStatusConnected;
                    [self.delegate codec:self statusDidChanged:CCCodecStatusConnected error:nil];
                }
            }
            else {
                _status = CCCodecStatusDisconnected;
                NSError *error = [NSError errorWithDomain:@"Invalid response code" code:code userInfo:nil];
                [self.delegate codec:self statusDidChanged:CCCodecStatusDisconnected error:error];
            }
            _balance = [NSMutableData new];
            
        }
            break;
            
        case CCCodecStatusConnected: {
            NSInteger bytesAvailable = (int)_balance.length - (*toffset);
            if (bytesAvailable < 2) {
                return NO;
            }
            uint8_t *message = ((uint8_t *)_balance.bytes) + *toffset;
            uint8_t fin = (DMFinMask & message[0]);
            uint8_t receivedOpcode = (DMOpCodeMask & message[0]);
            uint8_t isMasked = (DMMaskMask & message[1]);
            uint8_t payloadLen = (DMPayloadLenMask & message[1]);
            if (isMasked) {
                NSError *error = [NSError errorWithDomain:@"" code:CCCloseCodeProtocolError userInfo:@{@"desc":@"Client must receive unmasked data"}];
                _status = CCCodecStatusDisconnected;
                [self.delegate codec:self statusDidChanged:CCCodecStatusDisconnected error:error];
                return NO;
            }
            
            if (message[0] & DMRSVMask) {
                NSError *error = [NSError errorWithDomain:@"DMWebSocketParserDomain" code:CCCloseCodeProtocolError userInfo:@{@"desc":@"Server used RSV bits"}];
                _status = CCCodecStatusDisconnected;
                [self.delegate codec:self statusDidChanged:CCCodecStatusDisconnected error:error];
                return NO;
            }
            
            // skip past the control opcodes of the frame
            int offset = DMFrameHeaderLength;
            
            BOOL isControlFrame = (receivedOpcode == CCWebSocketOpCodeClose || receivedOpcode == CCWebSocketOpCodePing);
            
            if (!isControlFrame && (receivedOpcode != CCWebSocketOpCodeBinary && receivedOpcode != CCWebSocketOpCodeContinueFrame &&
                                    receivedOpcode != CCWebSocketOpCodeText && receivedOpcode != CCWebSocketOpCodePong && receivedOpcode != CCWebSocketOpCodeClose)) {
                NSError *error = [[NSError alloc]initWithDomain:@"DMWebSocketParserDomain" code:CCCloseCodeProtocolError userInfo:@{@"desc":[NSString stringWithFormat:@"unknown opcode: %@", @(receivedOpcode)]}];
                _status = CCCodecStatusDisconnected;
                [self.delegate codec:self statusDidChanged:CCCodecStatusDisconnected error:error];
                return NO;
            }
            
            if (isControlFrame && fin == 0) {
                NSError *error = [[NSError alloc]initWithDomain:@"DMWebSocketParserDomain" code:CCCloseCodeProtocolError userInfo:@{@"desc":@"control frames can't be fragmented"}];
                _status = CCCodecStatusDisconnected;
                [self.delegate codec:self statusDidChanged:CCCodecStatusDisconnected error:error];
                return NO;
            }
            
            if (isControlFrame && payloadLen > 125) {
                NSError *error = [[NSError alloc]initWithDomain:@"DMWebSocketParserDomain" code:CCCloseCodeProtocolError userInfo:@{@"desc":@"control frame using extend payload"}];
                _status = CCCodecStatusDisconnected;
                [self.delegate codec:self statusDidChanged:CCCodecStatusDisconnected error:error];
                return NO;
            }
            
            NSInteger closeCode = CCCloseCodeNormal;
            if (receivedOpcode == CCWebSocketOpCodeClose) {
                if (payloadLen == 1) {
                    closeCode = CCCloseCodeProtocolError;
                }
                else if (payloadLen > 1){
                    uint16_t closeCode = 0;
                    memcpy(&closeCode, message + offset, 2);
                    closeCode = ntohs(closeCode);
                }
                NSError *error = [[NSError alloc]initWithDomain:@"DMWebSocketParserDomain" code:closeCode userInfo:@{@"desc":@"Connection closed by server"}];
                _status = CCCodecStatusDisconnected;
                [self.delegate codec:self statusDidChanged:CCCodecStatusDisconnected error:error];
                return NO;
            }
            uint64_t dataLength = payloadLen;
            if (dataLength == 126) {
                uint16_t smallLen = 0;
                memcpy(&smallLen, message + offset, 2);
                dataLength = ntohs(smallLen);
                offset += 2;
            }
            else if (dataLength == 127) {
                memcpy(&dataLength, message + offset, 8);
                dataLength = ntohll(dataLength);
                offset += 8;
            }
            
            if (bytesAvailable - offset < dataLength) {
                // Not enough data, bail out
                return NO;
            }
            uint8_t *msg = message;
            msg += offset;
            if (receivedOpcode == CCWebSocketOpCodePing) {
                NSData *pong = [self createFrame:msg payloadLength:dataLength opCode:CCWebSocketOpCodePong];
                [self.delegate codec:self write:(uint8_t *)pong.bytes length:(int)pong.length];
            }
            else {
                [self.delegate codec:self read:msg length:(int)dataLength];
            }
            NSInteger balance = bytesAvailable - offset - dataLength;
            if (balance > 0) {
                _balance = [NSMutableData dataWithBytes:msg + dataLength length:balance];
            }
            else {
                _balance = [NSMutableData new];
            }
            return balance > 0;
        }
            break;
            
        default:
            break;
    }
    return NO;
}

-(void)open {
    _status = CCCodecStatusConnecting;
    NSURL *url = _request.URL;
    CFHTTPMessageRef request = CFHTTPMessageCreateRequest(NULL, CFSTR("GET"), (__bridge CFURLRef)url, kCFHTTPVersion1_1);
    CFHTTPMessageSetHeaderFieldValue(request, CFSTR("Host"), (__bridge CFStringRef)(url.host));
    CFHTTPMessageSetHeaderFieldValue(request, CFSTR("Upgrade"), CFSTR("websocket"));
    CFHTTPMessageSetHeaderFieldValue(request, CFSTR("Connection"), CFSTR("Upgrade"));
    CFHTTPMessageSetHeaderFieldValue(request, CFSTR("Sec-WebSocket-Key"), (__bridge CFStringRef)_securityKey);
    CFHTTPMessageSetHeaderFieldValue(request, CFSTR("Sec-WebSocket-Version"), (__bridge CFStringRef)@"13");
    CFHTTPMessageSetHeaderFieldValue(request, CFSTR("Origin"), (__bridge CFStringRef)url.origin);
    if (_protocols) {
        CFHTTPMessageSetHeaderFieldValue(request, CFSTR("Sec-WebSocket-Protocol"), (__bridge CFStringRef)[_protocols componentsJoinedByString:@", "]);
    }
//    CFHTTPMessageSetHeaderFieldValue(request,CFSTR("Sec-WebSocket-Extensions"),CFSTR("permessage-deflate; client_max_window_bits; server_max_window_bits=15"));
    [self.allHTTPHeaderFields enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL *stop) {
        CFHTTPMessageSetHeaderFieldValue(request, (__bridge CFStringRef)key, (__bridge CFStringRef)obj);
    }];
    NSData *message = CFBridgingRelease(CFHTTPMessageCopySerializedMessage(request));
    CFRelease(request);
    [self.delegate codec:self write:(uint8_t *)message.bytes length:(int)message.length];
}

-(void)close {
    _status = CCCodecStatusDisconnected;
}

@end
