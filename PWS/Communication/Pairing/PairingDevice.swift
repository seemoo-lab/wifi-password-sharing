import Foundation

#if os(macOS)
import Security
#endif

/// This class is responsible for using 
class PairingDevice {
    static let current = PairingDevice()

    var config: PairingConfig
    var signingKeys: SigningKeys {
        return config.signingKeys
    }

    init() {
        // Load the signing keys to verify the identity

        // Use some present signing Keys for testing
        self.config = PairingConfig.Static.default

        #if os(macOS)
//        self.loadSigningKeysFromKeychain()
        #else // Linux or other
        // Load the keys from file
        keys = SigningKeys.Static.keys
        #endif
    }
}
