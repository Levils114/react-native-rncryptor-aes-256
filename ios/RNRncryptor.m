#import "RNRncryptor.h"

@implementation RNRncryptor

RCT_EXPORT_MODULE()

RCT_EXPORT_METHOD(encrypt:(NSString *)text 
                  password:(NSString *)password
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
{
    NSData *data = [text dataUsingEncoding:NSUTF8StringEncoding];
    NSError *error;
    NSData *encryptedData = [RNEncryptor encryptData:data
                                        withSettings:kRNCryptorAES256Settings
                                            password:password
                                               error:&error];
    NSString *string = [encryptedData base64EncodedStringWithOptions:0];
    
    if(error){
        reject(@"Error", @"Decrypt failed", error);
    } else {
        resolve(string);
    }
}

RCT_EXPORT_METHOD(decrypt:(NSString *)base64 
                  password:(NSString *)password
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
{
    NSData *data = [[NSData alloc] initWithBase64EncodedString:base64 options:0];
    NSError *error;
    NSData *decryptedData = [RNDecryptor decryptData:data
                                        withPassword:password
                                               error:&error];

    NSString *string = [decryptedData base64EncodedStringWithOptions:(0)];
    
    if(error){
        reject(@"Error", @"Decrypt failed", error);
    } else {
        resolve(string);
    }
}

RCT_EXPORT_METHOD(decryptStream:(NSString *)password 
                  cryptedPath:(NSString *)cryptedPath
                  destPath:(NSString *)destPath
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
{
    // Make sure that this number is larger than the header + 1 block.
    // 33+16 bytes = 49 bytes. So it shouldn't be a problem.
    dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);

    int blockSize = 32 * 1024;

    NSInputStream *cryptedStream = [NSInputStream inputStreamWithFileAtPath:cryptedPath];
    __block NSOutputStream *decryptedStream = [NSOutputStream outputStreamToFileAtPath:destPath append:NO];
    __block NSError *decryptionError = nil;

    [cryptedStream open];
    [decryptedStream open];

    RNDecryptor *decryptor = [[RNDecryptor alloc] initWithPassword:password handler:^(RNCryptor *cryptor, NSData *data) {
        @autoreleasepool {
            [decryptedStream write:data.bytes maxLength:data.length];
            dispatch_semaphore_signal(semaphore);

            data = nil;
            if (cryptor.isFinished) {
                [decryptedStream close];
                decryptionError = cryptor.error;
                
                if(decryptionError){
                    reject(@"Error", @"Decrypt failed", decryptionError);
                } else{
                    resolve(@"finish");
                }
                // call my delegate that I'm finished with decrypting
            }
        }
    }];

    while (cryptedStream.hasBytesAvailable) {
        @autoreleasepool {
            uint8_t buf[blockSize];
            NSUInteger bytesRead = [cryptedStream read:buf maxLength:blockSize];
            if (bytesRead > 0) {
                NSData *data = [NSData dataWithBytes:buf length:bytesRead];

                [decryptor addData:data];

                dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);
            }
        }
    }

    [cryptedStream close];
    [decryptor finish];
}
@end
  
