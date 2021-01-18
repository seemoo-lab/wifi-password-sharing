import Foundation

// Lowest Frame used in password sharing
// Frame Structure: 2 bytes of payload length followed by the raw payload data.
class WDNearbyFrame {

    // The expected length of the full WPNearby frame. This length is given in
    // the first 2 bytes of a new frame.
    private var expectedPayloadLength: UInt16

    // WPNearby payload
    var body: [UInt8]

    // Indicatior if this frame has been received completly
    var isComplete: Bool {
        return body.count >= expectedPayloadLength
    }

    // Assembles the full WDNearbyFrame with the length in the first 2 bytes, used while sending
    var data: [UInt8] {
        var data = withUnsafeBytes(of: expectedPayloadLength.littleEndian) { Array($0) }
        data += body
        return data
    }

    // Init new frame with received data
    // The first 2 bytes of this first package is the expected payload size
    init(data: [UInt8]) throws {
        if data.count <= 2 {
            throw WDNearbyFrameError.notEnoughtData
        }
        expectedPayloadLength = UInt16(data[0...1].reversed())
        body = Array(data[2..<data.count])
    }

    // Init with payload, used to send this frame
    init(body: [UInt8]) {
        self.body = body
        self.expectedPayloadLength = UInt16(body.count)
    }

    // Append received data to the payload
    func appendData(data: [UInt8]) {
        body += data
    }
}

enum WDNearbyFrameError: Error {
    case notEnoughtData
}
