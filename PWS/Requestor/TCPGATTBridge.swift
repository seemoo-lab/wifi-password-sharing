import Foundation

protocol TCPGATTBridgeDelegate: class {
    func onReceivedData(data: [UInt8])
}

class TCPGATTBridge {
    let addr: String
    let port: Int

    var inputStream: InputStream!
    var outputStream: OutputStream!

    let queue: DispatchQueue

    let running = true

    var delegate: TCPGATTBridgeDelegate?

    init(ipAddress: String, port: Int) {
        self.addr = ipAddress
        self.port = port
        queue = DispatchQueue(label: "socket")
    }

    func connect() {
        var inp: InputStream?
        var out: OutputStream?
        Stream.getStreamsToHost(withName: addr, port: port, inputStream: &inp, outputStream: &out)
        inputStream = inp
        outputStream = out

        inputStream.open()
        outputStream.open()

        queue.async {
            self.readLoop()
        }
    }

    func readLoop() {
        while running {
            guard let data = readStream(stream: inputStream) else {
                break
            }
            DispatchQueue.main.async {
                self.delegate?.onReceivedData(data: data)
            }
        }
        connect()
    }

    func readStream(stream: InputStream) -> [UInt8]? {
        let bufferSize = 256
        var inputBuffer = [UInt8](repeating: 0x00, count: bufferSize)
        stream.read(&inputBuffer, maxLength: bufferSize)

        let dataLen = inputBuffer[0]
        if dataLen == 0 {
            return nil
        }

        let payload = inputBuffer[1...Int(dataLen)]
        return Array(payload)
    }

    var chuncks: [[UInt8]]?
    func write(frame: WDNearbyFrame) {
        print(frame.data.data.hexadecimal)
        chuncks = frame.data.chunked(into: 101)
        sendNextChunck()
    }

    func sendNextChunck() {
        if let chunk = chuncks?.first {
            outputStream.write(chunk, maxLength: chunk.count)
            chuncks?.remove(at: 0)
        }

        DispatchQueue.main.asyncAfter(deadline: .now() + 0.10) {
            self.sendNextChunck()
        }
    }
}
