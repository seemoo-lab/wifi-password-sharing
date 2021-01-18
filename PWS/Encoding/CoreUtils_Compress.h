#ifndef CoreUtils_Compress_h
#define CoreUtils_Compress_h
#import <Foundation/Foundation.h>

NSData* _Nullable NSDataDecompress(NSData * _Nonnull data, int i, NSError * _Nullable * _Nullable error);

NSData* _Nullable NSDataCompress(NSData * _Nonnull data, int i, NSError * _Nullable * _Nullable error);

#endif /* CoreUtils_Compress_h */
