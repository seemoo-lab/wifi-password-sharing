import Foundation

/// Struct that contains signing keys
struct SigningKeys {

    /// An elliptic curve signing secret key
    var edSecretKey: Data
    /// An elliptic curve signing public key
    var edPublicKey: Data

    /// This struct contains static keys that can be used on Linux or macOS when no access to the keychain is permitted
    struct Static {
        static let secretKeyHex = "<6b82ec2e 59e7c436 aed0a48c 77c2604c cb043e7b 1deaaa95 347aef93 93308a9d>"
        static let publicKeyHex = "<4a22a999 7d007206 5e38258b 8d3bc524 add6fc0e 1382fe09 7a70528c 4ecc2436>"

        static var secretKeyData: Data {
            return secretKeyHex.hexadecimal!
        }

        static var publicKeyData: Data {
            return publicKeyHex.hexadecimal!
        }

        static var keys: SigningKeys {
            return SigningKeys(edSecretKey: secretKeyData, edPublicKey: publicKeyData)
        }

        static var catalinaKeys: SigningKeys {
            let secretKey = "<f7f6eeec be933d33 6757bdcb edfab49f b2a46a71 df543fd2 9dae6101 9a71a98a>"
            let publicKey = "<e5798aa4 109e1f5a 50b6fdc2 b7012f66 422a2602 8a9fb5be f48d1f62 573b66cf>"

            return SigningKeys(edSecretKey: secretKey.hexadecimal!, edPublicKey: publicKey.hexadecimal!)
        }

        /// Those keys are listed in the access group com.apple.rapport
        static var eveKeys: SigningKeys {
            let secretKey = "<14b6aa69 d11377f2 ae4f46cd 6766e2df 8c8103ec 85a364aa 16648493 4887332d 70d468b2 0dde0ccc 16aac5e7 435c76d7 23c8a18c cb6f25a1 4ad36a5a 185116ee>"
            let publicKey = "<70d468b2 0dde0ccc 16aac5e7 435c76d7 23c8a18c cb6f25a1 4ad36a5a 185116ee>"

            return SigningKeys(edSecretKey: secretKey.hexadecimal!, edPublicKey: publicKey.hexadecimal!)
        }

        /// Those keys are **not** listed in the access group com.apple.rapport
        static var evesBrotherKeys: SigningKeys {
            let secretKey = "<4f7e33dd c1318b65 91ee555f 306fab27 fcf7cfb2 b3609b5d 89d8a571 867a2a7f 1e26e891 a7c6a49b 898d6af0 3f7cb5f2 5dc08d15 eeb94516 85154852 e2c031dc>"
            let publicKey = "<1e26e891 a7c6a49b 898d6af0 3f7cb5f2 5dc08d15 eeb94516 85154852 e2c031dc>"

            return SigningKeys(edSecretKey: secretKey.hexadecimal!, edPublicKey: publicKey.hexadecimal!)
        }
    }
}
