import Foundation

struct PairingConfig {
    var signingKeys: SigningKeys
    var pairingIdentity: String

    struct Static {

        /// Copied from a macOS Catalina Beta instance
        static var `default`: PairingConfig {
            let signingKeys = SigningKeys.Static.catalinaKeys
            let pairingID = "68800C7B-BBD4-47CF-BBFD-10C59232002D"

            return PairingConfig(signingKeys: signingKeys, pairingIdentity: pairingID)
        }

        /// Alternative Pairing Config copied from my main macOS instance (Mojave)
        static var alternative: PairingConfig {
            let signingKeys = SigningKeys.Static.keys
            let pairingID = "61B210FC-D79C-401B-98C6-AE7EFE889730"

            return PairingConfig(signingKeys: signingKeys, pairingIdentity: pairingID)
        }

        static var eve: PairingConfig {
            let signingKeys = SigningKeys.Static.eveKeys
            let pairingId = "43B40D1F-60F2-45E3-838A-209204F865AC"

            return PairingConfig(signingKeys: signingKeys, pairingIdentity: pairingId)
        }

        /// Those keys are not listed in an Apple security access group (com.apple.rapport)
        static var evesBrother: PairingConfig {
            let signingKeys = SigningKeys.Static.evesBrotherKeys
            let pairingId = "43B40D1F-60F2-45E3-838A-209204F865AC"

            return PairingConfig(signingKeys: signingKeys, pairingIdentity: pairingId)
        }
    }
}
