import Foundation
import CoreBluetooth
import CryptoKit
import Security

// MARK: - WDNeadbyHandler

class WDNeadbyHandler {
    var peripheral: CBPeripheral
    var characteristic: CBCharacteristic

    init(peripheral: CBPeripheral, characteristic: CBCharacteristic) throws {
        self.peripheral = peripheral
        self.characteristic = characteristic
    }

    // Was not nessesary
    var chuncks: [[UInt8]]?
    func send(_ frame: WDNearbyFrame) {
        chuncks = frame.data.chunked(into: 99)
        sendNextChunck()
    }

    func didWriteValue() {
        sendNextChunck()
    }

    func sendNextChunck() {
        if let chunk = chuncks?.first {
            peripheral.writeValue(chunk.data, for: characteristic, type: CBCharacteristicWriteType.withResponse)
            chuncks?.remove(at: 0)
        }
    }
}

// MARK: - PWSGivingHandler

class PWSGrantorHandler: WDNeadbyHandler {

    struct ShareInfo {
        var ssid: String
        var psk: String
        var mailHash: String?
        var phoneHash: String?

        var ssidHash: [UInt8] {
            guard let shareInfoSSIDData = ssid.data(using: .utf8) else {
                return []
            }
            return Array(Data(SHA256.hash(data: shareInfoSSIDData)).bytes[0...2])
        }

        func checkAdvertisement(_ appleAdvertisement: AppleBLEAdvertisement, flags: [PWS.Flags]) -> PWSAdvertisement? {
            if let nearbyActionFrame = appleAdvertisement.continuityMessages[.NearbyActionFrame] as? NearbyActionFrame {
                if let pwsAdvertisement = nearbyActionFrame.parameter as? PWSAdvertisement {
                    if pwsAdvertisement.ssidHash == self.ssidHash || flags.contains(.noSSIDCheck) {
                        return pwsAdvertisement
                    }
                }
            }
            return nil
        }
    }
    var shareInfo: ShareInfo

    var sessionKeys: CurveKeyPair
    var sharedSecret: Data?
    var peerPairingIdentity: PairingIdentity?

    var peerPublicKey: Data?

    init(peripheral: CBPeripheral, characteristic: CBCharacteristic, shareInfo: ShareInfo) throws {
        // Generate session keys with fixed salt
        let hkdfSpec = KeyGeneration.HKDFInfo(info: "Pair-Verify-ECDH-Info", salt: "Pair-Verify-ECDH-Salt", keyLength: KeyGeneration.Constants.curveKeyLength)
        self.sessionKeys = try KeyGeneration.generateCurve25519RandomKeypair(usingHKDF: hkdfSpec)

        self.shareInfo = shareInfo

        try super.init(peripheral: peripheral, characteristic: characteristic)
        setNotify {
            do {
                try self.sendPWS1()
            } catch let error {
                print("Error: \(error)")
            }
        }
    }

    private func setNotify(callback: @escaping () -> Void) {
        peripheral.setNotifyValue(true, for: characteristic)

        // We have to wait for about 200 milliseconds until we can send pws1 after subsribing, otherwise we get
        // a CBATTErrorDomain Code=6 "The request is not supported"
        let deadlineTime = DispatchTime.now() + .milliseconds(2000)
        DispatchQueue.main.asyncAfter(deadline: deadlineTime, execute: callback)
    }

    // MARK: - Received Frame Handling

    // Called when a new frame has been fully received
    func receivedFrame(_ frame: WDNearbyFrame) {
        do {
            let sessionFrame = try SFSessionFrame(data: frame.body)
            switch (sessionFrame.frameType, sessionFrame.serviceType) {
            case (.pws2, .passwordSharing):             try receivedPWS2(sessionFrame.body)
            case (.pairVerifyM234, .passwordSharing):   try receivedM2_4(sessionFrame.body)
            case (.pwsPayload, .passwordSharing):       try receivedPWS4(sessionFrame.body)
            default:                                    throw PWSError.unknownFrameTypeServiceType(sessionFrame.frameType, sessionFrame.serviceType)
            }
        } catch let error {
            print("Error: \(error)")
        }
    }

    // MARK: - PWS 1 & 2

    private func sendPWS1() throws {
        print("Send PWS1")

        // Not checked at all, empty dict works
        let pws1Dict: [String: Any] = [
            "sid": NSNumber(value: UInt32(1576046130)),
            "shv": "1476.17"
        ]
        let opackData = try OPACKCoding.encode(fromDictionary: pws1Dict)
        let frame = SFPasswordSharingSessionFrame(frameType: .pws1, body: opackData.bytes)
        self.send(frame.nearbyFrame)
    }

    private func receivedPWS2(_ payload: [UInt8]) throws {
        let pws2Dict = try OPACKCoding.decode(fromData: payload.data)
        print("Received PWS2: \(pws2Dict)")

        try sendM1()
    }

    // MARK: - Pair Verify

    private func sendM1() throws {
        print("Send M1")

        let pubKeyData = sessionKeys.publicKey

        // Construct a tlv with our public key and the pair verify state (0x01)
        var tlv = TLV8Box()
        tlv.addValue(withType: PairingTLV.publicKey, andLength: UInt8(crypto_box_PUBLICKEYBYTES), andValue: pubKeyData)
        tlv.addInt(withType: PairingTLV.state, andValue: 0x01)
        let tlvBytes = try tlv.serialize()

        // Construct a dictionary with 2 key value pairs, pf are pair verify flags
        let m1Dict: [String: Any] = [
            "pf": NSNumber(value: UInt32(1052676)),
            "pd": tlvBytes
        ]

        // Encode dictionary with opack
        let opackData = try OPACKCoding.encode(fromDictionary: m1Dict)

        // Construct session frame and send
        let frame = SFPasswordSharingSessionFrame(frameType: .pairVerifyRequestM1, body: opackData.bytes)
        self.send(frame.nearbyFrame)
    }

    // M2 and M4 messages use the same session frameType, so we use the state value to identify if its an M2 or M4 message
    private func receivedM2_4(_ payload: [UInt8]) throws {
        let m2_4Dict = try OPACKCoding.decode(fromData: payload.data)
        guard let tlv8BoxData = m2_4Dict["pd"] as? Data else {
            throw PVError.missingPD
        }

        // Get state from pd tlv box
        let tlv8Box = try TLV8Box.deserialize(fromData: tlv8BoxData)
        guard let state = tlv8Box.getValue(forType: PairingTLV.state)?.bytes[0] else {
            throw PVError.missingState
        }

        // call based on the received state to receivedM2 or receivedM4
        switch state {
        case 2:     try receivedM2(tlv8Box)
        case 4:     try receivedM4(tlv8Box)
        default:    throw PVError.unknownStateValue(state)
        }
    }

    func receivedM2(_ box: TLV8Box) throws {
        print("Received M2")

        // If publicKey and encyptedData is included we are in M2 (TODO keep state of it local after sending M3)
        if let peerPublicKey = box.getValue(forType: UInt8(0x03)), let encyptedData = box.getValue(forType: UInt8(0x05)) {
            self.peerPublicKey = peerPublicKey

            // -----------

            // 1. Generate the shared Secret
            let sharedSecret = try KeyGeneration.curve25519(secretKey: self.sessionKeys.secretKey, base: peerPublicKey)
            self.sharedSecret = sharedSecret

            // 2. Generate the decryptionKey
            let decryptionKey = KeyGeneration.cryptoHKDF(input: sharedSecret, outLength: KeyGeneration.Constants.curveKeyLength, salt: "Pair-Verify-Encrypt-Salt", info: "Pair-Verify-Encrypt-Info")

            // 3. Decrypt the data
            let encrypted = encyptedData
            let nonce = "PV-Msg02".data(using: .ascii)!

            let decrypted = try Crypto.chachaPoly1305Decrypt64x64(key: decryptionKey, nonce: nonce, aad: nil, encrypted: encrypted)

            // 4. Verify decrypted Data
            // Should be a TLV
            let tlv = try TLV8Box.deserialize(fromData: decrypted)

            // Unpack TLV8 Box into signature, appleIDCert and validationData
            guard let signature = tlv.getValue(forType: UInt8(10)) else {
                throw PVM2Error.noSignature
            }
            guard let appleIDCertificateCompressed = tlv.getValue(forType: UInt8(9)) else {
                throw PVM2Error.noPeerAppleIDCertificate
            }
            guard let validationDataCompressed = tlv.getValue(forType: UInt8(20)) else {
                throw PVM2Error.noPeerValidatonData
            }

            // Init AppleID Client and set certificate data and vaidaton data
            let peerClient = CUAppleIDClient()
            peerClient.peerCertificateData = try Compress.decompress(data: appleIDCertificateCompressed)
            peerClient.peerValidationData = try Compress.decompress(data: validationDataCompressed)

            // Construct message data from peer (searching device) public key + own (giving device) public key
            var messageData = peerPublicKey // peer key
            messageData.append(sessionKeys.publicKey)

            // Verify peer
            let verifyed = Signing.verifyAppleIDCertificateSignature(appleIDCertificate: peerClient.peerCertificateData, signedData: messageData, signature: signature)

            // Or use the CUAppleIDClient method
            // let verifyed = peerClient.verifyData(messageData, signature: signature, error: nil)
            print("Verify Peer Signature: \(verifyed)")
            if flags.contains(.ignoreInvalidPeerValidation) {
                throw PVM2Error.invalidPeerValidation
            }

            // Parse Validation data and print plist
            let signingPolicy = SecPolicyCreateAppleIDValidationRecordSigningPolicy()?.takeRetainedValue()
            var trustref_unmanaged: Unmanaged<SecTrust>?
            var attached_contents_unmanaged: Unmanaged<CFData>?

            let status = SecCMSVerifyCopyDataAndAttributes(peerClient.peerValidationData as CFData, nil, signingPolicy, &trustref_unmanaged, &attached_contents_unmanaged, nil)
            print(status)

            let trustref = trustref_unmanaged?.takeRetainedValue()
            let attached_contents = attached_contents_unmanaged?.takeRetainedValue() as Data?
            print("\(String(describing: trustref))")

            var propertyListFormat =  PropertyListSerialization.PropertyListFormat.xml
            let attached_contents_plist = try? PropertyListSerialization.propertyList(from: attached_contents!, options: .mutableContainersAndLeaves, format: &propertyListFormat)
            print("\(String(describing: attached_contents_plist))")

            guard let validationPlist = attached_contents_plist as? NSDictionary else {
                throw PVM2Error.invalidValidationData
            }
            guard let encDsID = validationPlist["encDsID"] as? String else {
                throw PVM2Error.invalidValidationData
            }

            // Check Certificate Name suffix with validation record dsID
            let cert = SecCertificateCreateWithData(nil, peerClient.peerCertificateData as CFData)
            print(cert)

            var commonName: CFString?
            SecCertificateCopyCommonName(cert!, &commonName)

            if !String(commonName!).hasSuffix(encDsID) {
                throw PVM2Error.appleIDCertificateNotMatchingValidationData
            }

            try sendM3()
        } else {
            print("ERROR M2 publicKey or encyptedData not set")
        }
    }

    func sendM3() throws {
        print("Send M3")

        guard let sharedSecret = self.sharedSecret else {
            throw PWSError.noSharedSecret
        }

        // Generate encrytion key
        let encryptionKey = KeyGeneration.cryptoHKDF(input: sharedSecret, outLength: KeyGeneration.Constants.curveKeyLength, salt: "Pair-Verify-Encrypt-Salt", info: "Pair-Verify-Encrypt-Info")

        // Call encrypt with empty payload and just use the authTag from it
        let nonce = "PV-Msg03".data(using: .ascii)!
        let emptyData = Data()
        let result = try Crypto.chachaPoly1305Encrypt64x64(key: encryptionKey, nonce: nonce, aad: nil, message: emptyData)
        let encryptedData = result.authTag

        // Construct tlv packet with encrypted data (auth tag) and pair verify state (0x03)
        var answerTLV = TLV8Box()
        answerTLV.addValue(withType: PairingTLV.encryptedData, andLength: UInt8(encryptedData.count), andValue: encryptedData)
        answerTLV.addInt(withType: PairingTLV.state, andValue: 0x03)
        let answerTLVBytes = try answerTLV.serialize()

        // Construct dictionary with a single key value combination ("pd": tlv data)
        let m3Dict: [String: Any] = ["pd": answerTLVBytes]

        // Encode dictionary with opack
        let opackData = try OPACKCoding.encode(fromDictionary: m3Dict)

        // Construct session frame and send
        let frame = SFPasswordSharingSessionFrame(frameType: .pairVerifyM234, body: opackData.bytes)
        self.send(frame.nearbyFrame)
    }

    func receivedM4(_ box: TLV8Box) throws {
        print("Received M4: \(box)")
        try sendPWS3()
    }

    // MARK: - PWS 3 & 4

    func sendPWS3() throws {
        print("sendPWS3")

        guard let sharedSecret = self.sharedSecret else {
            throw PWSError.noSharedSecret
        }

        var pws3Dict: [String: Any] = [
            // "dn": "Rihanna", // Not needed
            // "gr": NSNumber(1), // Not needed
            "op": NSNumber(5) // Parsed as ranged int64 0-0xff, OP Code - has to be 5 to call _handleReceivedPassword in SFPasswordSharingService (checked in [SFPasswordSharingService _receivedObject:flags:])
        ]

        if !flags.contains(.noMailHash) {
            pws3Dict["eh"] = shareInfo.mailHash
        }

        if !flags.contains(.noPhoneHash) {
            pws3Dict["ph"] = shareInfo.mailHash
        }

        if !flags.contains(.noSSID) {
            pws3Dict["nw"] = shareInfo.ssid
        }

        if !flags.contains(.noPSK) {
            pws3Dict["psk"] = shareInfo.psk
        }

        let opackData = try OPACKCoding.encode(fromDictionary: pws3Dict)

        // Init encrytion key
        let encryptionKey = KeyGeneration.cryptoHKDF(input: sharedSecret, outLength: KeyGeneration.Constants.curveKeyLength, salt: "WriteKeySalt", info: "WriteKeyInfo")

        // Write nonce starts with 0 and is increase by 1 after a package has been send, pws only sends one package
        let nonce = "00000000 00000000 00000000".hexadecimal!

        // aad 2 bytes long, first the frame type (0x06) followed then the service type (PWS 0x07)
        let aad = "0607".hexadecimal!
        let result = try Crypto.chachaPoly1305Encrypt96x32(key: encryptionKey, nonce: nonce, aad: aad, message: opackData)

        // Append the 16 byte of the auth tag at the end of the ciphertext
        var encryptedData = result.encrypted
        encryptedData.append(result.authTag)

        // Construct session frame and send
        let frame = SFPasswordSharingSessionFrame(frameType: .pwsPayload, body: encryptedData.bytes)
        self.send(frame.nearbyFrame)
    }

    private func receivedPWS4(_ payload: [UInt8]) throws {
        print("Received PWS4: \(payload.data.hexadecimal)")

        guard let sharedSecret = self.sharedSecret else {
            throw PWSError.noSharedSecret
        }

        // Init decryption key
        let decryptionKey = KeyGeneration.cryptoHKDF(input: sharedSecret, outLength: KeyGeneration.Constants.curveKeyLength, salt: "ReadKeySalt", info: "ReadKeyInfo")

        // Read nonce starts with 0 and is increase by 1 after a package has been received, pws only received one package
        let nonce = "00000000 00000000 00000000".hexadecimal!

        // aad 2 bytes long, first the frame type (0x06) followed then the service type (PWS 0x07)
        let aad = "0607".hexadecimal!
        let clear = try Crypto.chachaPoly1305Decrypt96x32(key: decryptionKey, nonce: nonce, aad: aad, encrypted: payload.data)

        // Decode the cleartext as an opack dict
        let dict = try OPACKCoding.decode(fromData: clear)

        // This dict should include 2 ints, op and re
        guard let op = dict["op"] as? Int else {
            throw PWS4Error.no_op
        }
        guard let re = dict["re"] as? Int else {
            throw PWS4Error.no_re
        }

        // These 2 ints should 5 and 1, otherwise the sharings was not successfull
        if op == 5 && re == 1 {
            print("PWS DONE")
        } else {
            throw PWS4Error.wrongValue
        }
    }
}

enum PVError: Error {
    case unknownStateValue(UInt8)
    case missingState, wrongState
    case missingPD
    case missingPublicKey
    case missingPeerPublicKey
}

enum PVM2Error: Error {
    case noSignature
    case noPeerAppleIDCertificate
    case noPeerValidatonData
    case appleIDCertificateNotMatchingValidationData
    case invalidPeerValidation
    case couldNotGenerateSignature
    case invalidValidationData
    case invalidAppleIDCertificate
}

enum PWS4Error: Error {
    case no_op
    case no_re
    case wrongValue
}

enum PWSError: Error {
    case unknownFrameTypeServiceType(SFSessionFrameType, SFSessionServiceType)
    case keyGenerationFailed
    case noConnection
    case noPairingDataFound
    case parsingFailed
    case keyExchangeFailed
    case signingFailed
    case peerVerificationFailed
    case noPeerPublicKeyAvailable
    case noSharedSecret
    case peerFailed
    case noEncrytedDataFound
}

enum PairingTLV: TLVType {

    case state
    case publicKey
    case appFlags
    case appleIDCertificateData
    case signature
    case encryptedData
    case identityId

    var uInt8: UInt8 {
        switch self {
        case .publicKey:
            return 0x03
        case .state:
            return 0x06
        case .appFlags:
            return 0x19
        case .appleIDCertificateData:
            return 9
        case .signature:
            return 10
        case .encryptedData:
            return 5
        case .identityId:
            return 1
        }
    }
}
