import Foundation
import CommonCrypto

struct KeyGeneration {

    static func randomBytes(forSize size: Int) throws -> Data {
        var byteArray = [UInt8](repeating: 0x00, count: size)
        guard CCRandomGenerateBytes(&byteArray, size) == kCCSuccess else {
            throw KeyGenError.randomBytesFailed
        }

        return Data(byteArray)
    }

    /// Perform Curve25519 Diffie-Hellman.
    ///
    /// - Parameters:
    ///   - secretKey: Input secret key. (32 bytes)
    ///   - base: Input basepoint (32 bytes) (for computing a shared secret) or nil (for computing a public key).
    /// - Returns: Output shared secret or public key.
    static func curve25519(secretKey: Data, base: Data?=nil) throws -> Data {
        guard secretKey.count == Constants.curveKeyLength, (base == nil || base!.count == Constants.curveKeyLength)
            else { throw KeyGenError.incorrectKeyLength }

        var outArray = [UInt8](repeating: 0x00, count: Constants.curveKeyLength)

        var secretKeyArray = Array(secretKey)

        if let base = base {
            var baseArray = Array(base)
            cccurve25519(&outArray, &secretKeyArray, &baseArray)
        } else {
            cccurve25519(&outArray, &secretKeyArray, nil)
        }

        return Data(outArray)
    }

    /// Use Apple's CoreUtils CryptoHKDF to create a hash based key derivation from given input. This will trim the key to a given size
    ///
    /// - Parameters:
    ///   - input: The input from which a key should be derived
    ///   - outLength: The length the output key should have
    ///   - salt: Possible salt
    ///   - info: Possible info string
    /// - Returns: Data with a derived key
    static func cryptoHKDF(input: Data, outLength: Int, salt: String, info: String) -> Data {
        var inputArray = Array(input)

        var infoIn = Array(info.data(using: .ascii)!)
        var saltIn = Array(salt.data(using: .ascii)!)

        var outArray = [UInt8](repeating: 0x00, count: outLength)

        // Call CryptoHKDF in Core Utils as there is no CoreCrypto / CommonCrypto Equivalent
        CryptoHKDF(kCryptoHashDescriptor_SHA512, &inputArray, inputArray.count, &saltIn, saltIn.count, &infoIn, infoIn.count, outLength, &outArray)

        return Data(outArray)
    }

    /// Generate random using Apple's curve 25519 implementatopn and an optional HKDF on  top
    ///
    /// - Parameter usingHKDF: Can be used to modify the randomly generate bytes more to get a higher entropy. Optional
    /// - Returns: A Curve 25519 keypair
    /// - Throws: Key generation may fail which can throw an error
    static func generateCurve25519RandomKeypair(usingHKDF: HKDFInfo?=nil) throws -> CurveKeyPair {
        // 1. Generate random bytes
        let randomBytes = try self.randomBytes(forSize: Constants.curveKeyLength)

        var secretKey: Data = randomBytes
        if let hkdf  = usingHKDF {
            // 2. Use HKDF on random bytes
            secretKey =  self.cryptoHKDF(input: randomBytes, outLength: Constants.curveKeyLength, salt: hkdf.salt, info: hkdf.info)
        }

        // 3. Use curve25519 to generate public key
        let publicKey = try curve25519(secretKey: secretKey)

        return CurveKeyPair(sKey: secretKey, pKey: publicKey)
    }

    /// Generate a new ed25519 signing key pair
    static func generateEd25519SigningKeys() -> SigningKeys {
        var edSecretKey = [UInt8](repeating: 0x00, count: Int(crypto_sign_ed25519_SECRETKEYBYTES))
        var edPublicKey = [UInt8](repeating: 0x00, count: Int(crypto_sign_ed25519_PUBLICKEYBYTES))

        crypto_sign_ed25519_keypair(&edPublicKey, &edSecretKey)

        return SigningKeys(edSecretKey: Data(edSecretKey), edPublicKey: Data(edPublicKey))
    }

    struct HKDFInfo {
        let info: String
        let salt: String
        let keyLength: Int
    }

    struct Constants {
        static let curveKeyLength = 32
        static let sha512HashLen = 32

    }

    enum KeyGenError: Error {
        case randomBytesFailed
        case incorrectKeyLength
    }
}
