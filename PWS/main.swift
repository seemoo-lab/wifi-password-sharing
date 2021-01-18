import Foundation
import CoreBluetooth
import CryptoKit
import Security

import ArgumentParser

struct PWS {
    enum Flags {
        // Do not include psk key in PWS3 package
        case noPSK

        // Do not include ssid (nw) key in PWS3 package
        case noSSID

        // Do not include phone hash (ph) key in PWS3 package
        case noPhoneHash

        // Do not include mail hash (eh) key in PWS3 package
        case noMailHash

        // Do not check ssid in pws advertisement bevor connecting to it
        // Note: will still include the specified ssid in the SharingInfo, which will lead to a not successfull pws if not matching
        case noSSIDCheck

        // continue if the peer validation fails in PWS2
        case ignoreInvalidPeerValidation
    }
}

var flags: [PWS.Flags] = []

#if MODE_REQUESTOR
struct Requestor: ParsableCommand {
    @Argument(help: "Apple ID of local account.")
    var appleID: String

    @Argument(help: "Address or hostname of GATT server.")
    var gattServerAddress: String

    @Argument(help: "Port of GATT server.")
    var gattPort: Int = 8080

    mutating func run() throws {
        let shareInfoRequestor = PWSRequestorHandler.ShareInfo(
            appleID: self.appleID,
            gattBridgeIPAddress: self.gattServerAddress,
            gattBridgePort: self.gattPort
        )
        print("Starting PWS Requestor")
        _ = PWSRequestorHandler(shareInfo: shareInfoRequestor)
    }
}
Requestor.main()
#else
struct Grantor: ParsableCommand {
    @Argument(help: "SSID to share.")
    var ssid: String

    @Argument(help: "PSK to share.")
    var psk: String

    mutating func run() throws {
        let shareInfoGrantor = PWSGrantorHandler.ShareInfo(
            ssid: self.ssid,
            psk: self.psk
        )
        flags = [.noPhoneHash, .noMailHash]
        print("Starting PWS Grantor")
        _ = PWSAdvertisementScanner(shareInfo: shareInfoGrantor)
    }
}
Grantor.main()
#endif
RunLoop.main.run()
