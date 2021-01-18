import Foundation

enum SFSessionFrameType: UInt8 {
    case pws1 = 0x17
    case pws2 = 0x18
    case pwsPayload = 0x06
    case pairVerifyRequestM1 = 0x12
    case pairVerifyM234 = 0x13
    case heartbeat = 0x1e
    case pairVerifyHeartbeatA = 0x15
    case pairVerifyHeartbeatB = 0x16

}

enum SFSessionServiceType: UInt8 {
    case passwordSharing = 0x07
}

enum SFSessionError: Error {
    case invalidFrameType
    case invalidServiceType
}

class SFSessionFrame {
    var frameType: SFSessionFrameType
    var serviceType: SFSessionServiceType
    var body: [UInt8]

    var data: [UInt8] {
        var data = [UInt8]()
        data.append(self.frameType.rawValue)
        data.append(self.serviceType.rawValue)
        data += body
        return data
    }

    var nearbyFrame: WDNearbyFrame {
        return WDNearbyFrame(body: data)
    }

    init(frameType: SFSessionFrameType, serviceType: SFSessionServiceType, body: [UInt8]) {
        self.frameType = frameType
        self.serviceType = serviceType
        self.body = body
    }

    init(data: [UInt8]) throws {
        guard let frameType = SFSessionFrameType(rawValue: data[0]) else {
            throw SFSessionError.invalidFrameType
        }
        guard let serviceType = SFSessionServiceType(rawValue: data[1]) else {
            throw SFSessionError.invalidServiceType
        }
        self.frameType = frameType
        self.serviceType = serviceType
        self.body = Array(data[2..<data.count])
    }
}

class SFPasswordSharingSessionFrame: SFSessionFrame {
    init(frameType: SFSessionFrameType, body: [UInt8]) {
        super.init(frameType: frameType, serviceType: .passwordSharing, body: body)
    }
}
