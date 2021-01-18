import Foundation

struct Crypto {
    typealias ChachaOut = (encrypted: Data, authTag: Data)

    private static let useCoreUtilsChaCha = true

    static func chacha20poly1305Decrypt(key: Data, nonce: Data, aad: Data?, encrypted: Data) throws -> Data {

        var keyData = Array(key)
        var nonceData = Array(nonce)

        let msgLength = encrypted.count-16
        let encryptedData = Array(encrypted)
        var msgData = Array(encryptedData[0..<msgLength])
        var authTag = Array(encryptedData[msgLength...])
        assert(authTag.count == 16)

        var output = [UInt8](repeating: 0x00, count: msgLength)

        let success = { () -> Int32 in
            var info = ccchacha20poly1305_info_default

            if let aad = aad {
                var aadData = Array(aad)
                return ccchacha20poly1305_decrypt_oneshot(&info, &keyData, &nonceData, aadData.count, &aadData, msgData.count, &msgData, &output, &authTag)
            }
            return ccchacha20poly1305_decrypt_oneshot(&info, &keyData, &nonceData, 0, nil, msgData.count, &msgData, &output, &authTag)
        }()

        guard success == 0 else {throw CryptoError.decryptionFailed(msg: "chacha returned no success")}

        return Data(output)
    }

    static func chacha20poly1305Encrypt(key: Data, nonce: Data, aad: Data?, message: Data) throws -> ChachaOut {

        var keyData = Array(key)
        var nonceData = Array(nonce)
        var messageData = Array(message)

        let msgLength = messageData.count
        var output = [UInt8](repeating: 0x00, count: msgLength)
        var authTag = [UInt8](repeating: 0x00, count: 0x10)

        let success = { () -> Int32 in
            var info = ccchacha20poly1305_info_default

            if let aad = aad {
                var aadData = Array(aad)
                return ccchacha20poly1305_encrypt_oneshot(&info, &keyData, &nonceData, aadData.count, &aadData, messageData.count, &messageData, &output, &authTag)
            }
            return ccchacha20poly1305_encrypt_oneshot(&info, &keyData, &nonceData, 0, nil, messageData.count, &messageData, &output, &authTag)
        }()

        guard success == 0 else {throw CryptoError.decryptionFailed(msg: "chacha returned no success")}

        return (encrypted: Data(output), authTag: Data(authTag))
    }

    static func chachaPoly1305Encrypt64x64(key: Data, nonce: Data, aad: Data?, message: Data) throws -> (encrypted: Data, authTag: Data) {

        var keyData = Array(key)
        var nonceData = Array(nonce)
        var messageData = Array(message)

        let msgLength = messageData.count
        var output = [UInt8](repeating: 0x00, count: msgLength)
        var authTag = [UInt8](repeating: 0x00, count: 0x10)

        if nonceData.count == 8 {
            if let aad = aad {
                var aadData = Array(aad)
                chacha20_poly1305_encrypt_all_64x64(&keyData, &nonceData, &aadData, aadData.count, &messageData, messageData.count, &output, &authTag)

            } else {
                chacha20_poly1305_encrypt_all_64x64(&keyData, &nonceData, nil, 0, &messageData, messageData.count, &output, &authTag)
            }

            return (encrypted: Data(output), authTag: Data(authTag))
        }

        throw CryptoError.invalidNonce(msg: "Noce is not 8 byte")

    }

    static func chachaPoly1305Decrypt64x64(key: Data, nonce: Data, aad: Data?, encrypted: Data) throws -> Data {

        var keyData = Array(key)
        var nonceData = Array(nonce)

        let msgLength = encrypted.count-16
        let encryptedData = Array(encrypted)
        var msgData = Array(encryptedData[0..<msgLength])
        var authTag = Array(encryptedData[msgLength...])
        assert(authTag.count == 16)

        var output = [UInt8](repeating: 0x00, count: msgLength)

        if nonceData.count == 8 {

            if let aad = aad {
                var aadData = Array(aad)
                chacha20_poly1305_decrypt_all_64x64(&keyData, &nonceData, &aadData, aadData.count, &msgData, msgLength, &output, &authTag)
            } else {
                chacha20_poly1305_decrypt_all_64x64(&keyData, &nonceData, nil, 0, &msgData, msgLength, &output, &authTag)
            }

            guard output != [UInt8](repeating: 0x00, count: msgLength) else {throw CryptoError.decryptionFailed(msg: "Did not decrypt")}

            return Data(output)
        }

        throw CryptoError.invalidNonce(msg: "Nonce is not 8 byte")
    }

    static func chachaPoly1305Encrypt96x32(key: Data, nonce: Data, aad: Data?, message: Data) throws -> (encrypted: Data, authTag: Data) {

        var keyData = Array(key)
        var nonceData = Array(nonce)
        var messageData = Array(message)

        let msgLength = messageData.count
        var output = [UInt8](repeating: 0x00, count: msgLength)
        var authTag = [UInt8](repeating: 0x00, count: 0x10)

        if nonceData.count == 12 {
            if let aad = aad {
                var aadData = Array(aad)
                chacha20_poly1305_encrypt_all_96x32(&keyData, &nonceData, &aadData, aadData.count, &messageData, messageData.count, &output, &authTag)

            } else {
                chacha20_poly1305_encrypt_all_96x32(&keyData, &nonceData, nil, 0, &messageData, messageData.count, &output, &authTag)
            }

            return (encrypted: Data(output), authTag: Data(authTag))
        }

        throw CryptoError.invalidNonce(msg: "Noce is not 12 byte")
    }

    static func chachaPoly1305Decrypt96x32(key: Data, nonce: Data, aad: Data?, encrypted: Data) throws -> Data {

        var keyData = Array(key)
        var nonceData = Array(nonce)

        let msgLength = encrypted.count-16
        let encryptedData = Array(encrypted)
        var msgData = Array(encryptedData[0..<msgLength])
        var authTag = Array(encryptedData[msgLength...])
        assert(authTag.count == 16)

        var output = [UInt8](repeating: 0x00, count: msgLength)

        if nonceData.count == 12 {

            if let aad = aad {
                var aadData = Array(aad)
                chacha20_poly1305_decrypt_all_96x32(&keyData, &nonceData, &aadData, aadData.count, &msgData, msgLength, &output, &authTag)
            } else {
                chacha20_poly1305_decrypt_all_96x32(&keyData, &nonceData, nil, 0, &msgData, msgLength, &output, &authTag)
            }

            guard output != [UInt8](repeating: 0x00, count: msgLength) else {throw CryptoError.decryptionFailed(msg: "Did not decrypt")}

            return Data(output)
        }

        throw CryptoError.invalidNonce(msg: "Nonce is not 8 byte")
    }

}

extension Crypto {
    enum CryptoError: Error {
        case decryptionFailed(msg: String?)
        case invalidNonce(msg: String?)
    }
}
