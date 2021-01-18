//
//  main.swift
//  bleScan
//
//  Created by Jannik Lorenz on 21.11.19.
//  Copyright © 2019 Jannik Lorenz. All rights reserved.
//

import Foundation
import CoreBluetooth
import CryptoKit
import Security

struct PWS {
    enum Flags {
        case noPSK
        case noSSID
        case noPhoneHash
        case noMailHash
        case noSSIDCheck
        case ignoreInvalidPeerValidation
    }
}

// Normal PWS Flags
var flags: [PWS.Flags] = [.noPhoneHash, .noMailHash]

// Crash Settings.app
// var flags: [PWS.Flags] = [.noPhoneHash, .noMailHash, .noSSID, .noSSIDCheck]

let shareInfo = PWSGivingHandler.ShareInfo(
        ssid: "lambda",
        psk: "2jt99mgwvnJRJqvfkHEc6JAhAJRzv6" // unifi
//    psk: "JACEdxDnG4FP6GtigGvrFEAWqGDcXVUrgxzHTveFBpjWpcnJfFsfBybeAwfgMBZ" // zyxel
)

/////////
//
//
//
// let hkdfSpec = KeyGeneration.HKDFInfo(info: "Pair-Verify-ECDH-Info", salt: "Pair-Verify-ECDH-Salt", keyLength: KeyGeneration.Constants.curveKeyLength)
//
//
//
//
//
// func enc(data: Data, publicKey: Data) -> (ciphertext: Data, publicKey: Data) {
//    let sessionKeys = try! KeyGeneration.generateCurve25519RandomKeypair(usingHKDF: hkdfSpec)
//    let sharedSecret = try! KeyGeneration.curve25519(secretKey: sessionKeys.secretKey, base: publicKey)
//
//    //2. Generate the decryptionKey
//    let encryptionKey = KeyGeneration.cryptoHKDF(input: sharedSecret, outLength: KeyGeneration.Constants.curveKeyLength, salt: "Pair-Verify-Encrypt-Salt", info: "Pair-Verify-Encrypt-Info")
//
//    //3. Decrypt the data
//    let nonce = "PV-Msg02".data(using: .ascii)!
//
//    let encryptedResult = try! Crypto.chachaPoly1305Encrypt64x64(key: encryptionKey, nonce: nonce, aad: nil, message: data)
//    var encryptedData = encryptedResult.encrypted
//    encryptedData.append(encryptedResult.authTag)
//    return (encryptedData, sessionKeys.publicKey)
// }
//
//
//
// func dec(encyptedData: Data, decryptionKey: Data) -> Data {
////    let sharedSecret = try! KeyGeneration.curve25519(secretKey: sessionKeys.secretKey, base: peerPublicKey)
//
//    //2. Generate the decryptionKey
////    let decryptionKey = KeyGeneration.cryptoHKDF(input: sharedSecret, outLength: KeyGeneration.Constants.curveKeyLength, salt: "Pair-Verify-Encrypt-Salt", info: "Pair-Verify-Encrypt-Info")
//
//    //3. Decrypt the data
//    let nonce = "PV-Msg02".data(using: .ascii)!
//
//    let x = try! Crypto.chachaPoly1305Decrypt64x64(key: decryptionKey, nonce: nonce, aad: nil, encrypted: encyptedData)
//    return x
// }
//
//
////let sharedSecret1 = try! KeyGeneration.curve25519(secretKey: sessionKeys1.secretKey, base: sessionKeys2.publicKey)
////let sharedSecret2 = try! KeyGeneration.curve25519(secretKey: sessionKeys2.secretKey, base: sessionKeys1.publicKey)
////print("sharedSecret1: \(sharedSecret1.hexadecimal)")
////print("sharedSecret2: \(sharedSecret2.hexadecimal)")
////print("sharedSecret equals: \(sharedSecret1 == sharedSecret2)")
//
////let key = KeyGeneration.cryptoHKDF(input: sharedSecret1, outLength: KeyGeneration.Constants.curveKeyLength, salt: "Pair-Verify-Encrypt-Salt", info: "Pair-Verify-Encrypt-Info")
////print("key: \(key.hexadecimal)")
//
// let sessionKeys = try! KeyGeneration.generateCurve25519RandomKeypair(usingHKDF: hkdfSpec)
//
//
// let data = "HALLO WELT".data(using: .ascii)!
// let eD = enc(data: data, publicKey: sessionKeys.publicKey)
// print("Ciphertext: \(eD.ciphertext.hexadecimal)")
//
// let sharedSecret = try! KeyGeneration.curve25519(secretKey: sessionKeys.secretKey, base: eD.publicKey)
// let key = KeyGeneration.cryptoHKDF(input: sharedSecret, outLength: KeyGeneration.Constants.curveKeyLength, salt: "Pair-Verify-Encrypt-Salt", info: "Pair-Verify-Encrypt-Info")
//
// let dD = dec(encyptedData: eD.ciphertext, decryptionKey: key)
// print("Text: \(dD.hexadecimal) \(String(data: dD, encoding: .ascii))")
//
//
//
//
////////

//// Init AppleID Client and set certificate data and vaidaton data
// let myClient = CUAppleIDClient()
////myClient.myAppleID = "janniklorenz@me.com"
////let signature = myClient.signData(Data(), error: nil) as Data
//
//
// let mySecKey = myClient._getMySecretKeyAndReturnError(nil) as! SecKey
// print(mySecKey)
//
//
// let data = "Hallo Welt____________Hallo Welt________________________________".data(using: .ascii)!.bytes
//
// let blockSize = SecKeyGetBlockSize(mySecKey)
// var sig = Array<UInt8>(repeating: 0x00, count: 256)
// var sig_len = sig.count
//
// SecKeyRawSign(mySecKey, SecPadding(rawValue: 1), data, data.count, &sig, &sig_len)
//
// print(sig)

// SecTransformRef signingTransform = SecSignTransformCreate(privateKeyRef, error);
// if (signingTransform == NULL)
//    return NULL;
//
// Boolean success = SecTransformSetAttribute(signingTransform,
//                                           kSecTransformInputAttributeName,
//                                           plaintext,
//                                           error);
// if (!success) {
//    CFRelease(signingTransform);
//    return NULL;
// }
//
// CFDataRef signature = SecTransformExecute(signingTransform, error);
// CFRetain(signature);
// CFRelease(signingTransform);
// return signature;

let mode = ProcessInfo.processInfo.environment["MODE"]
switch mode {
case "Searching":
    print("Starting PWS Searching Device")
    _ = PWSSearchingHandler()

case "Giving":
    print("Starting PWS Giving Device")
    _ = PWSAdvertisementScanner(shareInfo: shareInfo)
default:
    print("Unknown Mode")
}

RunLoop.main.run()
