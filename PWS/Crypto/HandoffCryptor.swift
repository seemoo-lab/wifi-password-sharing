//
//  HandoffCryptor.swift
//  Handoff-Swift
//
//  Created by Alexander Heinrich on 26.06.19.
//  Copyright © 2019 Alexander Heinrich. All rights reserved.
//

import Foundation

struct HandoffCryptor {
    let encryptionKey: Data
    let decryptionKey: Data

    var decryptNonce: UInt64
    var encryptNonce: UInt64

    init(withSharedSecret secret: Data, andMode mode: HandoffMode) {
        let keys = HandoffCryptor.generateKeys(forSharedSecret: secret, andMode: mode)

        encryptionKey = keys.encKey
        decryptionKey = keys.decKey

        decryptNonce = 0
        encryptNonce = 0
    }

    /// Encrypt a message using the ChaCha20 Poly1305 AEAD encryption.
    ///
    /// - Parameters:
    ///   - data: plaintext message
    ///   - aad: Additional authentication data that may be included in the Poly1305 Authentication
    /// - Returns: A tuple with encrypted data and an authentication tag. This is used to validate the authenticity of the encrypted data
    /// - Throws: An error if the encryption fails
    mutating func encrypt(data: Data, aad: Data?) throws -> Crypto.ChachaOut {
        var nonceData = encryptNonce.data // Data(bytes: &encryptNonce, count: MemoryLayout.size(ofValue: encryptNonce))
        if nonceData.count < 12 {
            let count = 12 - nonceData.count
            nonceData.append(Data(repeating: 0x00, count: count))
        }

        let encrypted = try Crypto.chacha20poly1305Encrypt(key: encryptionKey, nonce: nonceData, aad: aad, message: data)

        log("Nonce \(encryptNonce)")
        log("Nonce Data \(nonceData.hexadecimal)")

        // After every encryption the nonce needs to update by 1. Because ChaCha20Poly1305 may never use the same nonce + key combination twice
        encryptNonce += 1

        return encrypted
    }

    /// Decrypt a message using the ChaCha20 Poly1305 AEAD decryption
    ///
    /// - Parameters:
    ///   - data: encrypted message
    ///   - aad: Additional authentication data that may be included in the Poly1305 Authentication
    /// - Returns: plaintext Data
    /// - Throws: An Error if the decryption fails.
    mutating func decrypt(data: Data, aad: Data) throws -> Data {
        var nonceData = Data(bytes: &decryptNonce, count: MemoryLayout.size(ofValue: decryptNonce))
        if nonceData.count < 12 {
            let count  = 12 - nonceData.count
            nonceData.append(Data(repeating: 0x00, count: count))
        }

        let decrypted = try Crypto.chacha20poly1305Decrypt(key: decryptionKey, nonce: nonceData, aad: aad, encrypted: data)

        // After every decryption the nonce needs to update by 1. Because ChaCha20Poly1305 may never use the same nonce + key combination twice
        decryptNonce += 1

        return decrypted
    }

    /// Decrypt a Continuity packet that has been received
    ///
    /// - Parameter continuityPacket: A continuity packet
    /// - Returns: Plaintext data
    /// - Throws: An error if the decryption fails
    mutating func decrypt(continuityPacket packet: ContinuityPacket) throws -> Data {
        let aad = packet.header.data

        let encrypted = packet.body

        let decrypted = try decrypt(data: encrypted, aad: aad)

        return decrypted
    }

}

// MARK: - Static methods
extension HandoffCryptor {
    /// Generate the encryption and decryption keys from the shared secret
    ///
    /// - Parameters:
    ///   - secret: a shared secret that has been negotiated in PairingSession
    ///   - mode: Handoff Mode
    /// - Returns: a tuple with an encryption and a decryption key
    private static func generateKeys(forSharedSecret secret: Data, andMode mode: HandoffMode) -> (encKey: Data, decKey: Data) {
        let keyServerEncryptionMain = KeyGeneration.cryptoHKDF(input: secret, outLength: KeyGeneration.Constants.curveKeyLength, salt: "", info: "ServerEncrypt-main")

        let keyClientEncryptionMain = KeyGeneration.cryptoHKDF(input: secret, outLength: KeyGeneration.Constants.curveKeyLength, salt: "", info: "ClientEncrypt-main")

        switch mode {
        case .client:
            return (encKey: keyClientEncryptionMain, decKey: keyServerEncryptionMain)
        case .server:
            return (encKey: keyServerEncryptionMain, decKey: keyClientEncryptionMain)
        }
    }
}
