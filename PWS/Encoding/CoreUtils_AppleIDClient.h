#ifndef CoreUtils_AppleIDClient_h
#define CoreUtils_AppleIDClient_h
#import <Foundation/Foundation.h>

OSStatus SecKeyRawSign_macOS(SecKeyRef key, SecPadding padding, const uint8_t *dataToSign, size_t dataToSignLen, uint8_t *sig, size_t *sigLen);
OSStatus SecKeyRawVerify_macOS(SecKeyRef key, SecPadding padding, const uint8_t *signedData, size_t signedDataLen, const uint8_t *sig, size_t sigLen);

CFTypeRef SecPolicyCreateAppleIDValidationRecordSigningPolicy();

// From https://opensource.apple.com/source/Security/Security-55471/sec/Security/SecCMS.c
OSStatus SecCMSVerifyCopyDataAndAttributes(CFDataRef message, CFDataRef detached_contents,
CFTypeRef policy, SecTrustRef *trustref, CFDataRef *attached_contents, CFDictionaryRef *signed_attributes);

@interface CUAppleIDClient : NSObject { }

@property(copy, nonatomic) NSString *mySecretKeyType;
@property(copy, nonatomic) NSData *mySecretKeyData;
@property(copy, nonatomic) NSData *myCertificateData;
@property(copy, nonatomic) NSData *peerValidationData;
@property(copy, nonatomic) NSData *peerCertificateData;
@property(copy, nonatomic) NSArray *peerAppleIDs;
@property(copy, nonatomic) NSString *peerAppleID;
@property(retain, nonatomic) CUAppleIDClient *myInfoClient;
@property(copy, nonatomic) NSString *myAppleID;
@property(readonly, nonatomic) int securityLevel;

- (struct __SecCertificate* _Nullable)_getPeerCertificateAndReturnError:(NSError* _Nullable)error;
- (struct __SecIdentity* _Nullable)_getPeerPublicKeyAndReturnError:(NSError* _Nullable)error;

- (struct __SecIdentity* _Nullable)_getMySecretKeyAndReturnError:(NSError* _Nullable)error;

- (struct __SecIdentity* _Nullable)_getMyIdentityAndReturnError:(NSError* _Nullable)error;
- (struct __SecCertificate* _Nullable)_getMyCertificateAndReturnError:(NSError* _Nullable)error;

- (NSData* _Nullable)copyMyValidationDataAndReturnError:(NSError* _Nullable)error;
- (NSData* _Nullable)copyMyAppleIDAndReturnError:(NSError* _Nullable)error;
- (NSData* _Nullable)copyMyCertificateDataAndReturnError:(NSError* _Nullable)error;

- (BOOL)verifyBytes:(const void * _Nonnull)arg1 verifyLength:(unsigned long long)arg2 signatureBytes:(const void * _Nonnull)arg3 signatureLength:(unsigned long long)arg4 error:(NSError* _Nullable)error;
- (BOOL)verifyData:(NSData* _Nonnull)arg1 signature:(NSData* _Nonnull)arg2 error:(NSError* _Nullable)error;

- (BOOL)_validatePeerHashes:(id _Nonnull)arg1;
- (BOOL)validatePeerWithFlags:(unsigned int)arg1 error:(NSError* _Nullable)error;

- (NSData * _Nullable)signBytes:(const void * _Nonnull)arg1 length:(unsigned long long)arg2 error:(NSError* _Nullable)error;
- (NSData * _Nullable)signData:(NSData* _Nonnull)arg1 error:(NSError* _Nullable)error;

@end

#endif /* CoreUtils_AppleIDClient_h */
