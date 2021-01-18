import Foundation

enum PWSAdvertisementError: Error {
    case AdvertisementDataToShort
}

// Basic Advertisement Payload
//
// 0 - 1      | 2 - n
// Company ID | TLV8 for each continuity message
struct AppleBLEAdvertisement {
    var continuityMessages: [ContinuityMessageType: ContinuityMessage]

    init?(data: [UInt8]) throws {
        if data.count < 3 {
            throw PWSAdvertisementError.AdvertisementDataToShort
        }

        // Check raw adv data for apple company id, if no matching return with no pws adv
        let companyID = data[0...1]
        guard companyID == [0x4c, 0x00] else {
            return nil
        }

        // Loop over all continuity messages in this advertisement
        let tlvData = Array(data[2...]).data
        let continuityMessageBoxes = try TLV8Box.deserialize(fromData: tlvData)
        self.continuityMessages = [:]
        for type in continuityMessageBoxes.getTypes() {
            let message = continuityMessageBoxes.getValue(forType: type)!.bytes
            switch type {
            case ContinuityMessageType.NearbyActionFrame.rawValue:
                if let actionFrame = try? NearbyActionFrame(data: message) {
                    self.continuityMessages[.NearbyActionFrame] = actionFrame
                }

            // Possible other continuity messages
            default:
                continue
            }
        }
    }
}

protocol ContinuityMessage {}
enum ContinuityMessageType: UInt8 {
    case NearbyActionFrame = 15
}

struct NearbyActionFrame: ContinuityMessage {
    var flags: UInt8
    var actionType: UInt8
    var authTag: [UInt8]
    var parameterData: [UInt8]
    var parameter: NearbyActionData?

    init(data: [UInt8]) throws {
        if data.count < 6 {
            throw PWSAdvertisementError.AdvertisementDataToShort
        }

        flags = data[0]
        actionType = data[1] // 0x08 for pws, see 2020 paper or [SFPasswordSharingService _runServiceStar]
        authTag = Array(data[2...4])
        parameterData = Array(data[5...])

        switch actionType {
        case 8:
            parameter = try PWSAdvertisement(data: parameterData)
        default:
            parameter = nil
        }
    }
}

protocol NearbyActionData {}

struct PWSAdvertisement: NearbyActionData {
    var mailHash: [UInt8]
    var phoneHash: [UInt8]
    var appleidHash: [UInt8]
    var ssidHash: [UInt8]

    init(data: [UInt8]) throws {
        if data.count < 12 {
            throw PWSAdvertisementError.AdvertisementDataToShort
        }

        mailHash = Array(data[0...2])
        phoneHash = Array(data[3...5])
        appleidHash = Array(data[6...8])
        ssidHash = Array(data[9...11])
    }
}
