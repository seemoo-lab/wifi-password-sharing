/// A struct that handles all the keys that are generated and used througout a pairing session
struct CurveKeyPair {
    var secretKey: Data
    var publicKey: Data

    var sharedSecret: Data?

    init(sKey: Data, pKey: Data ) {
        secretKey = sKey
        publicKey = pKey
    }
}
