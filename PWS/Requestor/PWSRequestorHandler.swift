import Foundation

class PWSRequestorHandler: TCPGATTBridgeDelegate {

    struct ShareInfo {
        let appleID: String
        let gattBridgeIPAddress: String
        let gattBridgePort: Int
    }

    private var bridge: TCPGATTBridge

    var sessionKeys: CurveKeyPair
    var sharedSecret: Data?
    var peerPairingIdentity: PairingIdentity?

    var peerPublicKey: Data?

    var shareInfo: ShareInfo?

    init(shareInfo: ShareInfo) {
        let hkdfSpec = KeyGeneration.HKDFInfo(info: "Pair-Verify-ECDH-Info", salt: "Pair-Verify-ECDH-Salt", keyLength: KeyGeneration.Constants.curveKeyLength)
        self.sessionKeys = try! KeyGeneration.generateCurve25519RandomKeypair(usingHKDF: hkdfSpec)
        self.shareInfo = shareInfo
        bridge = TCPGATTBridge(ipAddress: shareInfo.gattBridgeIPAddress, port: shareInfo.gattBridgePort)
        bridge.delegate = self
        bridge.connect()
    }

    func onReceivedData(data: [UInt8]) {
        do {
            let frame = try WDNearbyFrame(data: data)
            let sessionFrame = try SFSessionFrame(data: frame.body)

            switch (sessionFrame.frameType, sessionFrame.serviceType) {
            case (.pws1, .passwordSharing):                     try receivedPWS1(sessionFrame.body)
            case (.pairVerifyRequestM1, .passwordSharing):      try receivedM1(sessionFrame.body)
            case (.pairVerifyM234, .passwordSharing):           try receivedM3(sessionFrame.body)
            case (.pwsPayload, .passwordSharing):               try receivedPWS3(sessionFrame.body)
            default:                                            throw PWSError.unknownFrameTypeServiceType(sessionFrame.frameType, sessionFrame.serviceType)
            }
        } catch let error {
            print("Error: \(error)")
        }
    }

    func receivedPWS1(_ payload: [UInt8]) throws {
        print("receivedPWS1")
        let opackData = try OPACKCoding.decode(fromData: payload.data)
        print(opackData)

        try sendPWS2()
    }

    func sendPWS2() throws {
        print("sendPWS2")
        let dict: [String: Any] = [
            "shv": "1476.17" // Not looked at on the giving devcie, works if dict is empty
        ]
        let opackData = try OPACKCoding.encode(fromDictionary: dict)
        let frame = SFPasswordSharingSessionFrame(frameType: .pws2, body: opackData.bytes).nearbyFrame
        bridge.write(frame: frame)
    }

    func receivedM1(_ payload: [UInt8]) throws {
        print("receivedM1")
        let opackData = try OPACKCoding.decode(fromData: payload.data)
        print(opackData)

        guard let tlv8BoxData = opackData["pd"] as? Data else {
            throw PVError.missingPD
        }
        let tlv8Box = try TLV8Box.deserialize(fromData: tlv8BoxData)
        guard let state = tlv8Box.getValue(forType: PairingTLV.state)?.bytes[0] else {
            throw PVError.missingState
        }
        guard state == 0x1 else {
            throw PVError.wrongState
        }

        guard let publicKey = tlv8Box.getValue(forType: PairingTLV.publicKey) else {
            throw PVError.missingPublicKey
        }

        self.peerPublicKey = publicKey

        try sendM2()
    }

    func sendM2() throws {
        print("sendM2")

        guard let peerPublicKey = self.peerPublicKey else {
            throw PVError.missingPeerPublicKey
        }

        // Construct message data from peer (searching device) public key + own (giving device) public key
        var messageData = sessionKeys.publicKey
        messageData.append(peerPublicKey)

        // Init AppleID Client and set certificate data and vaidaton data
        let myClient = CUAppleIDClient()
        myClient.myAppleID = self.shareInfo?.appleID

        // Call CUAppleIDMethod
        guard let signature = myClient.sign(messageData, error: nil) else {
            throw PVM2Error.couldNotGenerateSignature
        }

        var encrytedTLV = TLV8Box()
        encrytedTLV.addBigValue(withType: UInt8(10), andValue: signature)

        guard let validationData = myClient.copyMyValidationDataAndReturnError(nil) else {
            throw PVM2Error.invalidValidationData
        }
        encrytedTLV.addBigValue(withType: UInt8(20), andValue: try! Compress.compress(data: validationData))

        guard let appleIDCertificate = myClient.copyMyCertificateDataAndReturnError(nil) else {
            throw PVM2Error.invalidAppleIDCertificate
        }
        encrytedTLV.addBigValue(withType: UInt8(9), andValue: try! Compress.compress(data: appleIDCertificate))

        // 1. Generate the shared Secret
        let sharedSecret = try KeyGeneration.curve25519(secretKey: self.sessionKeys.secretKey, base: peerPublicKey)
        self.sharedSecret = sharedSecret

        // 2. Generate the decryptionKey
        let encryptionKey = KeyGeneration.cryptoHKDF(input: sharedSecret, outLength: KeyGeneration.Constants.curveKeyLength, salt: "Pair-Verify-Encrypt-Salt", info: "Pair-Verify-Encrypt-Info")

        // 3. Decrypt the data
        let nonce = "PV-Msg02".data(using: .ascii)!

        let m = try! encrytedTLV.serialize()
        let encryptedResult = try Crypto.chachaPoly1305Encrypt64x64(key: encryptionKey, nonce: nonce, aad: nil, message: m)
        var encryptedData = encryptedResult.encrypted
        encryptedData.append(encryptedResult.authTag)

        // Construct a tlv with our public key and the pair verify state (0x01)
        var tlv = TLV8Box()
        tlv.addValue(withType: PairingTLV.publicKey, andLength: UInt8(crypto_box_PUBLICKEYBYTES), andValue: self.sessionKeys.publicKey)
        tlv.addBigValue(withType: PairingTLV.encryptedData, andValue: encryptedData)
        tlv.addInt(withType: PairingTLV.state, andValue: 0x02)
        // TODO add missing keys
        let tlvBytes = try tlv.serialize()

        // Construct a dictionary with 2 key value pairs, pf are pair verify flags
        let m2Dict: [String: Any] = [
            "pd": tlvBytes
        ]

        // Encode dictionary with opack
        let opackData = try OPACKCoding.encode(fromDictionary: m2Dict)

        // Construct session frame and send
        let frame = SFPasswordSharingSessionFrame(frameType: .pairVerifyM234, body: opackData.bytes).nearbyFrame
        bridge.write(frame: frame)
    }

    func receivedM3(_ payload: [UInt8]) throws {
        print("receivedM3")
        let opackData = try OPACKCoding.decode(fromData: payload.data)
        print(opackData)

        guard let pdData = opackData["pd"] as? Data else {
            throw PWSError.noPairingDataFound
        }

        guard let sharedSecret = self.sharedSecret else {
            throw PWSError.noSharedSecret
        }

        let tlv = try TLV8Box.deserialize(fromData: pdData)
        print(tlv)

        guard let encryptedData = tlv.getValue(forType: PairingTLV.encryptedData) else {
            throw PWSError.noEncrytedDataFound
        }

        try sendM4()
    }

    func sendM4() throws {
        print("sendM4")

        // Construct a tlv with the pair verify state (0x04)
        var tlv = TLV8Box()
        tlv.addInt(withType: PairingTLV.state, andValue: 0x04)
        // TODO add missing keys
        let tlvBytes = try tlv.serialize()

        // Construct a dictionary with 1 key value pair
        let dict: [String: Any] = [
            "pd": tlvBytes
        ]

        // Encode dictionary with opack
        let opackData = try OPACKCoding.encode(fromDictionary: dict)

        // Construct session frame and send
        let frame = SFPasswordSharingSessionFrame(frameType: .pairVerifyM234, body: opackData.bytes).nearbyFrame
        bridge.write(frame: frame)
    }

    func receivedPWS3(_ payload: [UInt8]) throws {
        print("receivedPWS3 \(payload.data.hexadecimal)")

        guard let sharedSecret = self.sharedSecret else {
            throw PWSError.noSharedSecret
        }

        // Init encrytion key
        let encryptionKey = KeyGeneration.cryptoHKDF(input: sharedSecret, outLength: KeyGeneration.Constants.curveKeyLength, salt: "WriteKeySalt", info: "WriteKeyInfo")

        // Write nonce starts with 0 and is increase by 1 after a package has been send, pws only sends one package
        let nonce = "00000000 00000000 00000000".hexadecimal!

        // aad 2 bytes long, first the frame type (0x06) followed then the service type (PWS 0x07)
        let aad = "0607".hexadecimal!
        let result = try Crypto.chachaPoly1305Decrypt96x32(key: encryptionKey, nonce: nonce, aad: aad, encrypted: payload.data)

        let opackDict = try OPACKCoding.decode(fromData: result)
        print(opackDict)

        try sendPWS4()
    }

    func sendPWS4() throws {
        print("sendPWS4")

        guard let sharedSecret = self.sharedSecret else {
            throw PWSError.noSharedSecret
        }

        let pws4Dict: [String: Any] = [
            "re": NSNumber(1),
            "op": NSNumber(5) // Parsed as ranged int64 0-0xff, OP Code - has to be 5 to call _handleReceivedPassword in SFPasswordSharingService (checked in [SFPasswordSharingService _receivedObject:flags:])
        ]

        let opackData = try OPACKCoding.encode(fromDictionary: pws4Dict)

        // Init encrytion key
        let encryptionKey = KeyGeneration.cryptoHKDF(input: sharedSecret, outLength: KeyGeneration.Constants.curveKeyLength, salt: "ReadKeySalt", info: "ReadKeyInfo")

        // Write nonce starts with 0 and is increase by 1 after a package has been send, pws only sends one package
        let nonce = "00000000 00000000 00000000".hexadecimal!

        // aad 2 bytes long, first the frame type (0x06) followed then the service type (PWS 0x07)
        let aad = "0607".hexadecimal!
        let result = try Crypto.chachaPoly1305Encrypt96x32(key: encryptionKey, nonce: nonce, aad: aad, message: opackData)

        // Append the 16 byte of the auth tag at the end of the ciphertext
        var encryptedData = result.encrypted
        encryptedData.append(result.authTag)

        // Construct session frame and send
        let frame = SFPasswordSharingSessionFrame(frameType: .pwsPayload, body: encryptedData.bytes).nearbyFrame
        bridge.write(frame: frame)

    }

}
