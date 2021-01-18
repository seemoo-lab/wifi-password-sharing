#ifndef CoreUtils_Opack_h
#define CoreUtils_Opack_h
#import <Foundation/Foundation.h>

/**
 Decode Apple's binary format OPACK using CoreUtils`OPACKDecodeData.

 @param data OPACK encoded NSData
 @param flags flags should be 8
 @param error error pointer
 @return NSDictionary with decoded data
 */
NSDictionary* _Nullable OPACKDecodeData (NSData * _Nonnull data, int flags, NSError * _Nullable * _Nullable error);

/**
 This function call CoreUtils`OPACKEncoderCreateDataMutable. This function will encode a dictionary in Apple's OPACK format and create NSMutable Data from it

 @param dictionary dictionary to encode
 @param flags Should be 0
 @param error Error Pointer
 @return mutable Data in OPACK format
 */
NSMutableData * _Nullable OPACKEncoderCreateDataMutable (NSDictionary *  _Nonnull dictionary, int flags, NSError * _Nullable * _Nullable error);

#endif /* CoreUtils_Opack_h */
