import Foundation
import CoreBluetooth

let PWSServiceUUID = CBUUID(string: "9FA480E0-4967-4542-9390-D343DC5D04AE")
let PWSCharacteristicUUID = CBUUID(string: "AF0BADB1-5B99-43CD-917A-A77BC549E3CC")

extension Data {
    var sha512: Data {
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA512_DIGEST_LENGTH))
        self.withUnsafeBytes {
            _ = CC_SHA512($0.baseAddress, CC_LONG(self.count), &hash)
        }
        return hash.data
    }
}
