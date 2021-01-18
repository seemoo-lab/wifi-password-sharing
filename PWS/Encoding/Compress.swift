import Foundation

/// This is a wrapper around Apple's NSDataCompress/ Decompress  functions
struct Compress {

    static func compress(data: Data) throws -> Data {
        var errorPointer: NSError?
        let out: Data? =  NSDataCompress(data, 0, &errorPointer) as Data?

        // Check if error not nil. Throw error if an error occurred
        guard let data = out, errorPointer == nil else {
            throw CompressError.compressFailed(errorPointer!)
        }

        return data
    }

    static func decompress(data: Data) throws -> Data {
        var errorPointer: NSError?
        let out = NSDataDecompress(data, 0, &errorPointer)

        // Check if error not nil. Throw error if an error occurred
        guard let decodedDict = out, errorPointer == nil else {
                throw CompressError.decompressFailed(errorPointer!)
        }

        return decodedDict
    }

}

enum CompressError: Error {
    case compressFailed(NSError)
    case decompressFailed(NSError)
}
