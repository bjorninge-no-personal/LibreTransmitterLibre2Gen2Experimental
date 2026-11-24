//
//  Libre2Gen2.swift
//  LibreTransmitter
//
//  Cryptography of the Libre 2 "generation 2" BLE stream.
//
//  This is the Swift counterpart of the `libre2blecrypto` Python reference.
//  Scope is cryptography only: no transport, no BLE, no decoding of readings.
//  The transport/session wiring lives in the Bluetooth layer; parsing of the
//  decrypted 44-byte payload reuses the existing Libre 2 pipeline.
//
//  A Libre 2 is "generation 2" when patchInfo[2] gives product type 3 and
//  security version >= 9 (see `securityGeneration`). Generation 1 sensors use
//  none of this; they are handled by `enum Libre2` in PreLibre2.swift.
//
//  NOTE ON KEYS: this is now the REAL Gen2 scheme, ported from Juggluco's
//  `protocol.c` (the authoritative open-source reference). The key material is
//  NOT account-tied: two compiled-in root tables (a "sensor" root and a
//  "session" root) are selected by a root slot (1 or 2). The actual per-sensor
//  keys are DERIVED from those roots. The root tables live in
//  `Libre2Gen2Credentials.swift`; this file contains only the algorithms and
//  the derivation.
//
//  NOTE ON THE KDF: `Libre2Gen2.derive(...)` is NIST SP 800-108 counter mode
//  with the PRF = CMAC over Speck64/128 (an 8-byte block cipher), exactly as
//  Juggluco implements it — NOT CMAC-AES-128. The earlier AES-CMAC port was a
//  placeholder and produced wrong keys. The 16-byte derived key is
//  CMAC(counter=1) || CMAC(counter=2), each 8 bytes. See `speckCMAC`/`derive`.
//

import Foundation
import Security

enum Libre2Gen2 {

    // Lengths, mirroring the reference constants.
    static let uidLength = 8            // ISO 15693 UID, least significant first
    static let contextLength = 6        // UID[0..<6]: the serial, without 07 and E0
    static let streamingAuthLength = 10 // streamingAuthData, produced by NFC 0x1e
    static let challengeLength = 14      // the challenge notification
    static let sessionInfoLength = 25    // the sensor's reply: 7 bytes then 18
    static let commandLength = 19        // what we send: 0x1f then 18 ciphertext bytes
    static let randomLength = 7          // the echo proving the sensor holds kAuth
    static let keyLength = 16
    static let ivLength = 8
    static let packetLength = 46         // 20 + 18 + 8, reassembled by the app
    static let payloadLength = 44        // what is left once the 2-byte counter is removed
    static let crcLength = 2

    static let cmdSessionInfo: UInt8 = 0x1F

    /// "Read security challenge" opcode. Per DiaBLE's Abbott gen2 BLE path, the
    /// handshake is kicked off by writing this; the sensor then sends its
    /// challenge notification.
    static let cmdReadChallenge: UInt8 = 0x20

    // Product/security classification, from patchInfo[2].
    static let productType = 3
    static let securityVersionMin = 9

    // The two KDF labels differ only by the case of one letter, and BOTH carry a
    // trailing NUL, so each is 17 bytes (Juggluco protocol.c: the labels are the
    // 16 visible characters plus the C-string terminator, fed into the KDF).
    //   sensor  = "ADC_*SpeckPatch#\0"  (lower-case k)
    //   session = "ADC_*SpecKpatch#\0"  (CAPITAL K)
    static let sensorLabel = Array("ADC_*SpeckPatch#".utf8) + [0x00]
    static let sessionLabel = Array("ADC_*SpecKpatch#".utf8) + [0x00]

    struct Libre2Gen2Error: Error, LocalizedError {
        let errorDescription: String?
        init(_ message: String) { self.errorDescription = message }
    }
}

// MARK: - Speck64/128 in counter mode

extension Libre2Gen2 {
    private static let speckRounds = 27

    private static func ror(_ x: UInt32, _ r: UInt32) -> UInt32 {
        (x >> r) | (x << (32 - r))
    }

    private static func rol(_ x: UInt32, _ r: UInt32) -> UInt32 {
        (x << r) | (x >> (32 - r))
    }

    /// Key words are little-endian, k[0] first in the buffer.
    private static func speckSchedule(_ key: [UInt8]) -> [UInt32] {
        let m = (0..<4).map { u32le(key, $0 * 4) }
        var k: [UInt32] = [m[0]]
        var l: [UInt32] = [m[1], m[2], m[3]]
        for i in 0..<(speckRounds - 1) {
            l.append((k[i] &+ ror(l[i], 8)) ^ UInt32(i))
            k.append(rol(k[i], 3) ^ l[i + 3])
        }
        return k
    }

    private static func speckBlock(_ x0: UInt32, _ y0: UInt32, _ sk: [UInt32]) -> (UInt32, UInt32) {
        var x = x0, y = y0
        for k in sk {
            x = (ror(x, 8) &+ y) ^ k
            y = rol(y, 3) ^ x
        }
        return (x, y)
    }

    /// One raw Speck64/128 block encryption (`Speck_K(block)` in Juggluco's
    /// protocol.c). Little-endian block I/O: the low word is `right = load32(in+0)`
    /// and the high word is `left = load32(in+4)`; the 8-byte output is written
    /// back in the same order. This is the cipher primitive underneath both the
    /// CTR keystream and the Speck-CMAC PRF.
    ///
    /// Verified against the canonical Speck64/128 test vector (see
    /// `Libre2Gen2Tests.testSpeckKnownAnswer`).
    static func speckEncryptBlock(key: [UInt8], block: [UInt8]) -> [UInt8] {
        let sk = speckSchedule(key)
        let y0 = u32le(block, 0)   // right / low word
        let x0 = u32le(block, 4)   // left / high word
        let (x, y) = speckBlock(x0, y0, sk)
        return le(y) + le(x)
    }

    /// Speck64/128 in counter mode, as the engine configures it.
    ///
    /// The IV block IS the initial counter block, and only its first byte
    /// increments, modulo 256: a counter width of 1. Encrypting and decrypting
    /// are the same operation.
    static func speckCTR(key: [UInt8], iv: [UInt8], data: [UInt8]) throws -> [UInt8] {
        guard key.count == keyLength else {
            throw Libre2Gen2Error("key of \(key.count) bytes, expected \(keyLength)")
        }
        guard iv.count == ivLength else {
            throw Libre2Gen2Error("iv of \(iv.count) bytes, expected \(ivLength)")
        }
        let sk = speckSchedule(key)
        var stream = [UInt8]()
        stream.reserveCapacity(((data.count + 7) / 8) * 8)
        for i in 0..<((data.count + 7) / 8) {
            var block = iv
            block[0] = block[0] &+ UInt8(i & 0xFF)
            let y0 = u32le(block, 0)
            let x0 = u32le(block, 4)
            let (x, y) = speckBlock(x0, y0, sk)
            stream.append(contentsOf: le(y))
            stream.append(contentsOf: le(x))
        }
        return zip(data, stream).map { $0 ^ $1 }
    }
}

// MARK: - CRC16 (Abbott), matching the reference exactly

extension Libre2Gen2 {
    private static let crcTable: [UInt16] = {
        var table = [UInt16]()
        table.reserveCapacity(256)
        for i in 0..<256 {
            var c = UInt16(i)
            for _ in 0..<8 {
                c = (c & 1) != 0 ? (c >> 1) ^ 0x8408 : c >> 1
            }
            table.append(c)
        }
        return table
    }()

    /// Abbott's CRC16: reflected table 0x8408, init 0xffff, and the sixteen
    /// bits of the result READ BACKWARDS. No final xor, and (unlike
    /// `Crc.crc16`) no byte swap. An odd-length input is padded with one zero
    /// byte (Juggluco's l2g2_crc16). That matters for the 23-byte NFC
    /// challenge and replies; the 42-byte BLE payload is even and unaffected.
    static func crc16(_ data: ArraySlice<UInt8>) -> UInt16 {
        var crc: UInt16 = 0xFFFF
        for b in data {
            crc = crcTable[Int((crc ^ UInt16(b)) & 0xFF)] ^ (crc >> 8)
        }
        if data.count % 2 == 1 {
            crc = crcTable[Int(crc & 0xFF)] ^ (crc >> 8)
        }
        var reversed: UInt16 = 0
        var tmp = crc
        for _ in 0..<16 {
            reversed = (reversed << 1) | (tmp & 1)
            tmp >>= 1
        }
        return reversed
    }

    static func crc16(_ data: [UInt8]) -> UInt16 { crc16(data[...]) }

    /// The first 42 bytes carry the CRC, stored little-endian behind them.
    static func checkCRC(_ payload: [UInt8]) -> Bool {
        guard payload.count >= payloadLength else { return false }
        let computed = crc16(payload[0..<(payloadLength - crcLength)])
        let stored = UInt16(payload[payloadLength - crcLength])
            | (UInt16(payload[payloadLength - crcLength + 1]) << 8)
        return computed == stored
    }

    /// Append the CRC to 42 bytes of payload, returning the 44.
    static func sealCRC(_ payload: [UInt8]) throws -> [UInt8] {
        guard payload.count == payloadLength - crcLength else {
            throw Libre2Gen2Error("expected \(payloadLength - crcLength) bytes")
        }
        let crc = crc16(payload)
        return payload + [UInt8(crc & 0xFF), UInt8(crc >> 8)]
    }
}

// MARK: - CMAC over Speck64/128, and SP 800-108 derivation

extension Libre2Gen2 {
    static let speckBlockLength = 8     // Speck64/128 block size
    private static let cmacRb: UInt8 = 0x1b   // Juggluco uses 0x1b (not the GF(2^64) 0x1b/… AES 0x87)

    /// CMAC subkey doubling over a 64-bit block (Juggluco `double`): left-shift
    /// the whole block by one bit, and if the top bit was set, XOR the reduction
    /// constant 0x1b into the last byte.
    static func cmacDouble(_ input: [UInt8]) -> [UInt8] {
        var output = [UInt8](repeating: 0, count: input.count)
        var carry: UInt8 = 0
        for i in stride(from: input.count - 1, through: 0, by: -1) {
            output[i] = (input[i] << 1) | carry
            carry = (input[i] & 0x80) != 0 ? 1 : 0
        }
        if (input[0] & 0x80) != 0 { output[input.count - 1] ^= cmacRb }
        return output
    }

    /// CMAC with the Speck64/128 block cipher as the PRF (Juggluco protocol.c).
    /// Same construction as RFC 4493 CMAC-AES, but with an 8-byte block and the
    /// 0x1b reduction constant: subkey L = Speck_K(0^8), K1 = double(L),
    /// K2 = double(K1); the final block is XORed with K1 when it is full and K2
    /// when it was padded with 0x80.
    static func speckCMAC(key: [UInt8], message: [UInt8]) -> [UInt8] {
        let bs = speckBlockLength
        let zero = [UInt8](repeating: 0, count: bs)

        let l = speckEncryptBlock(key: key, block: zero)
        let k1 = cmacDouble(l)
        let k2 = cmacDouble(k1)

        let complete = message.count > 0 && message.count % bs == 0
        let blocks = max((message.count + bs - 1) / bs, 1)

        var lastBlock: [UInt8]
        if complete {
            lastBlock = zip(Array(message[(blocks - 1) * bs ..< blocks * bs]), k1).map { $0 ^ $1 }
        } else {
            var padded = Array(message[((blocks - 1) * bs)...])
            padded.append(0x80)
            while padded.count < bs { padded.append(0x00) }
            lastBlock = zip(padded, k2).map { $0 ^ $1 }
        }

        // CBC-MAC with a zero IV.
        var x = zero
        for i in 0..<(blocks - 1) {
            let block = Array(message[i * bs ..< (i + 1) * bs])
            x = speckEncryptBlock(key: key, block: zip(x, block).map { $0 ^ $1 })
        }
        return speckEncryptBlock(key: key, block: zip(x, lastBlock).map { $0 ^ $1 })
    }

    /// NIST SP 800-108 key derivation in counter mode, PRF = Speck-CMAC, exactly
    /// as Juggluco's `derive_key` builds it. Each PRF message is
    ///
    ///     counter(1 byte) || label || context || outputBits{0x80, 0x00}
    ///
    /// and the output is the 8-byte CMAC blocks concatenated: for a 16-byte key,
    /// CMAC(counter=1) || CMAC(counter=2). The label already includes its
    /// trailing NUL (see `sensorLabel`/`sessionLabel`), and `context` is the
    /// UID-minus-last-2 (sensor key) or the 16-byte session context.
    static func derive(key: [UInt8], label: [UInt8], context: [UInt8],
                       length: Int = keyLength) throws -> [UInt8] {
        guard key.count == keyLength else {
            throw Libre2Gen2Error("derive key of \(key.count) bytes, expected \(keyLength)")
        }
        var out = [UInt8]()
        var counter: UInt8 = 1
        while out.count < length {
            var message = [counter]
            message += label
            message += context
            message += [0x80, 0x00]        // output length field, verbatim from Juggluco
            out += speckCMAC(key: key, message: message)
            counter &+= 1
        }
        return Array(out[0..<length])
    }
}

// MARK: - Nonces and IV

extension Libre2Gen2 {
    /// Opening-exchange nonce: 00 || seed(3) || counter(4, little-endian).
    /// Bit 7 of the fourth byte marks the direction; BLE always sets it.
    static func authNonce(seed: [UInt8], counter: UInt32) throws -> [UInt8] {
        guard seed.count == 3 else {
            throw Libre2Gen2Error("seed of \(seed.count) bytes, expected 3")
        }
        return [0, seed[0], seed[1], seed[2] | 0x80] + le(counter)
    }

    /// Reading IV: 00 00 || stream(4) || packet counter(2). Bit 7 of the
    /// stream's last byte is set, as in the nonces.
    static func dataIV(streamID: [UInt8], packetCounter: [UInt8]) throws -> [UInt8] {
        guard streamID.count == 4 else {
            throw Libre2Gen2Error("stream of \(streamID.count) bytes, expected 4")
        }
        guard packetCounter.count == 2 else {
            throw Libre2Gen2Error("packet counter must be 2 bytes")
        }
        return [0, 0, streamID[0], streamID[1], streamID[2], streamID[3] | 0x80]
            + packetCounter
    }
}

// MARK: - Credentials

/// One selected root slot (Juggluco: a `root_slot`, 1 or 2). It carries the two
/// 16-byte compiled-in roots for that slot and derives the per-sensor keys from
/// them. `index` is the selecting slot and enters no context, no nonce and no
/// transmitted byte.
///
/// NAMING: `authKey` is the slot's SENSOR root (`sensor_roots[slot-1]`) and
/// `sessionGeneratorKey` is the slot's SESSION root (`session_roots[slot-1]`).
/// The names are kept for source compatibility with the BLE handler/keystore.
struct Libre2Gen2Credential {
    let index: Int
    let authKey: [UInt8]                // sensor_roots[slot-1]
    let sessionGeneratorKey: [UInt8]    // session_roots[slot-1]

    /// kAuth, the sensor key = derive_key(sensor_root, sensorLabel, UID without
    /// its last 2 bytes). For an 8-byte ISO 15693 UID that is UID[0..<6] — the
    /// serial without the manufacturer code and ISO prefix (Juggluco uses
    /// `uidSize - 2`).
    func kauth(uid: [UInt8]) throws -> [UInt8] {
        guard uid.count == Libre2Gen2.uidLength else {
            throw Libre2Gen2.Libre2Gen2Error("uid of \(uid.count) bytes, expected \(Libre2Gen2.uidLength)")
        }
        return try Libre2Gen2.derive(key: authKey,
                                     label: Libre2Gen2.sensorLabel,
                                     context: Array(uid[0..<(uid.count - 2)]))
    }

    /// The reading key = derive_key(session_root, sessionLabel, sessionContext16).
    /// The 16-byte context comes out of the sensor's decrypted auth reply
    /// (plaintext bytes [7..23)).
    func sessionKey(context: [UInt8]) throws -> [UInt8] {
        guard context.count == Libre2Gen2.keyLength else {
            throw Libre2Gen2.Libre2Gen2Error("context of \(context.count) bytes, expected \(Libre2Gen2.keyLength)")
        }
        return try Libre2Gen2.derive(key: sessionGeneratorKey,
                                     label: Libre2Gen2.sessionLabel,
                                     context: context)
    }
}

/// Supplies the root-slot credential at runtime. The real root tables are in
/// `Libre2Gen2Credentials.swift`; `index` is the root slot (1 or 2).
protocol Libre2Gen2KeyStore {
    func credential(forIndex index: Int) -> Libre2Gen2Credential?
}

// MARK: - Session

/// The cryptographic half of a BLE connection. No transport.
///
/// Needs three NFC-derived values (app DB fields `sensorUID`,
/// `securityVersion`, `streamingAuthData`):
///
///     uid                   8 bytes, the sensor's ISO 15693 UID
///     keyIndex              the row index (NFC 02 A1 07 22)
///     streamingAuthData     10 bytes (NFC 0x1e)
final class Libre2Gen2Session {
    let uid: [UInt8]
    let credential: Libre2Gen2Credential
    let blob: [UInt8]           // streamingAuthData
    let kauth: [UInt8]

    private(set) var sessionKey: [UInt8]?
    private var random: [UInt8]?
    private var counter: UInt32?

    init(uid: [UInt8], credential: Libre2Gen2Credential, streamingAuthData: [UInt8]) throws {
        guard uid.count == Libre2Gen2.uidLength else {
            throw Libre2Gen2.Libre2Gen2Error("uid of \(uid.count) bytes, expected \(Libre2Gen2.uidLength)")
        }
        guard streamingAuthData.count == Libre2Gen2.streamingAuthLength else {
            throw Libre2Gen2.Libre2Gen2Error("streamingAuthData of \(streamingAuthData.count) bytes, expected \(Libre2Gen2.streamingAuthLength)")
        }
        self.uid = uid
        self.credential = credential
        self.blob = streamingAuthData
        self.kauth = try credential.kauth(uid: uid)
    }

    convenience init(uid: [UInt8], keyIndex: Int, streamingAuthData: [UInt8],
                     keyStore: Libre2Gen2KeyStore) throws {
        guard let credential = keyStore.credential(forIndex: keyIndex) else {
            throw Libre2Gen2.Libre2Gen2Error("key index \(keyIndex) not present")
        }
        try self.init(uid: uid, credential: credential, streamingAuthData: streamingAuthData)
    }

    var streamID: [UInt8] { Array(blob[0..<4]) }

    /// Answer the 14-byte challenge with the 19-byte command to send. The
    /// plaintext is `random(7) || ~0x1f || blob[7..<10] || challenge[0..<7]`,
    /// encrypted under kAuth. The leading random bytes, echoed back by the
    /// sensor, are what prove it holds the same kAuth.
    func sessionInfoCommand(challenge: [UInt8], random overrideRandom: [UInt8]? = nil) throws -> [UInt8] {
        guard challenge.count == Libre2Gen2.challengeLength else {
            throw Libre2Gen2.Libre2Gen2Error("challenge of \(challenge.count) bytes, expected \(Libre2Gen2.challengeLength)")
        }
        let random = overrideRandom ?? Libre2Gen2.randomBytes(Libre2Gen2.randomLength)
        guard random.count == Libre2Gen2.randomLength else {
            throw Libre2Gen2.Libre2Gen2Error("random must be \(Libre2Gen2.randomLength) bytes")
        }
        self.random = random
        let counter = u32le(challenge, 7)
        self.counter = counter

        var plaintext = random
        plaintext.append(~Libre2Gen2.cmdSessionInfo)
        plaintext += Array(blob[7..<10])
        plaintext += Array(challenge[0..<7])

        let nonce = try Libre2Gen2.authNonce(seed: Array(blob[4..<7]), counter: counter)
        return [Libre2Gen2.cmdSessionInfo] + (try Libre2Gen2.speckCTR(key: kauth, iv: nonce, data: plaintext))
    }

    /// Open the session on the 25-byte reply and return the key. The sensor
    /// answers under the same nonce with the counter raised by one. The only
    /// check is the echo of our random bytes.
    @discardableResult
    func open(sessionInfo: [UInt8]) throws -> [UInt8] {
        guard let random = random, let counter = counter else {
            throw Libre2Gen2.Libre2Gen2Error("call sessionInfoCommand() first")
        }
        guard sessionInfo.count == Libre2Gen2.sessionInfoLength else {
            throw Libre2Gen2.Libre2Gen2Error("reply of \(sessionInfo.count) bytes, expected \(Libre2Gen2.sessionInfoLength)")
        }
        let nonce = try Libre2Gen2.authNonce(seed: Array(blob[4..<7]), counter: counter &+ 1)
        let plaintext = try Libre2Gen2.speckCTR(key: kauth, iv: nonce, data: Array(sessionInfo[0..<23]))
        guard Array(plaintext[0..<Libre2Gen2.randomLength]) == random else {
            throw Libre2Gen2.Libre2Gen2Error("the sensor did not echo our random bytes: kAuth differs, so the key index is wrong")
        }
        let key = try credential.sessionKey(context: Array(plaintext[7..<23]))
        self.sessionKey = key
        return key
    }

    /// Resume a session already opened, without redoing the exchange.
    func resume(sessionKey: [UInt8]) throws {
        guard sessionKey.count == Libre2Gen2.keyLength else {
            throw Libre2Gen2.Libre2Gen2Error("key of \(sessionKey.count) bytes, expected \(Libre2Gen2.keyLength)")
        }
        self.sessionKey = sessionKey
    }

    /// Decrypt a 46-byte packet and return the 44 bytes of payload. The first
    /// two bytes are a clear counter, which feeds the IV; here they stay in
    /// `packet`. The CRC settles whether the key is right.
    func decrypt(packet: [UInt8], verify: Bool = true) throws -> [UInt8] {
        guard let sessionKey = sessionKey else {
            throw Libre2Gen2.Libre2Gen2Error("session not open")
        }
        guard packet.count >= Libre2Gen2.packetLength else {
            throw Libre2Gen2.Libre2Gen2Error("packet of \(packet.count) bytes, expected at least \(Libre2Gen2.packetLength)")
        }
        let iv = try Libre2Gen2.dataIV(streamID: streamID, packetCounter: Array(packet[0..<2]))
        let payload = try Libre2Gen2.speckCTR(key: sessionKey, iv: iv, data: Array(packet[2...]))
        if verify && !Libre2Gen2.checkCRC(payload) {
            throw Libre2Gen2.Libre2Gen2Error("CRC failure: wrong key, or damaged packet")
        }
        return payload
    }

    /// The other direction, to exercise the chain against a fake sensor.
    func encrypt(packetCounter: [UInt8], payload: [UInt8]) throws -> [UInt8] {
        guard let sessionKey = sessionKey else {
            throw Libre2Gen2.Libre2Gen2Error("session not open")
        }
        let iv = try Libre2Gen2.dataIV(streamID: streamID, packetCounter: packetCounter)
        return packetCounter + (try Libre2Gen2.speckCTR(key: sessionKey, iv: iv, data: payload))
    }
}

// MARK: - NFC inputs

extension Libre2Gen2 {
    /// The generation, read from patchInfo[2]: 2 for product type 3 with
    /// security version >= 9. A generation 1 sensor uses none of these keys.
    ///
    /// The reference reads patchInfo[3] because it indexes the raw NFC frame,
    /// whose byte 0 is the ISO 15693 response-flags byte. CoreNFC strips that
    /// byte, so here it is patchInfo[2] (patchInfo[3] is the region). DiaBLE
    /// reads the same byte, e.g. US Libre 2+ `2C 0A 3A 02` is gen2.
    static func securityGeneration(patchInfo: [UInt8]) throws -> Int {
        guard patchInfo.count >= 3 else {
            throw Libre2Gen2Error("patchInfo too short")
        }
        let productTypeValue = Int(patchInfo[2] >> 4)
        let securityVersion = Int(patchInfo[2] & 0x0F)
        if productTypeValue == productType && securityVersion >= securityVersionMin {
            return 2
        }
        if (productTypeValue == productType || productTypeValue == 7) && securityVersion < securityVersionMin {
            return 1
        }
        return 0
    }

    /// The NFC command asking for the key index: 02 A1 <UID[6]> 22. UID[6] is
    /// the manufacturer code, 07 at Abbott.
    static func keyIndexCommand(uid: [UInt8]) throws -> [UInt8] {
        guard uid.count == uidLength else {
            throw Libre2Gen2Error("uid of \(uid.count) bytes, expected \(uidLength)")
        }
        return [0x02, 0xA1, uid[6], 0x22]
    }

    /// The index is the little-endian u16 at bytes 2 and 3 of the raw response
    /// frame. Pass a smaller `offset` when the transport has already stripped
    /// leading bytes (CoreNFC drops the response-flags byte).
    static func parseKeyIndex(response: [UInt8], offset: Int = 2) throws -> Int {
        guard offset >= 0, response.count >= offset + 2 else {
            throw Libre2Gen2Error("response too short")
        }
        return Int(UInt16(response[offset]) | (UInt16(response[offset + 1]) << 8))
    }
}

// MARK: - Byte helpers

extension Libre2Gen2 {
    static func randomBytes(_ count: Int) -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: count)
        _ = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        return bytes
    }
}

/// Little-endian u32 read from a byte buffer at `offset`.
private func u32le(_ buffer: [UInt8], _ offset: Int) -> UInt32 {
    UInt32(buffer[offset])
        | (UInt32(buffer[offset + 1]) << 8)
        | (UInt32(buffer[offset + 2]) << 16)
        | (UInt32(buffer[offset + 3]) << 24)
}

/// 4 little-endian bytes of a u32.
private func le(_ value: UInt32) -> [UInt8] {
    [UInt8(value & 0xFF),
     UInt8((value >> 8) & 0xFF),
     UInt8((value >> 16) & 0xFF),
     UInt8((value >> 24) & 0xFF)]
}

// MARK: - NFC exchange
//
// The authenticated NFC side, as Juggluco runs it (Gen2.java over protocol.c:
// prepareNfcCommand, readAuthenticatedFram, enableStreaming). Every command is
// ISO 15693 custom command 0xA1; the layouts are as CoreNFC returns them,
// without the response-flags byte Juggluco's raw frames start with:
//
//   A1 22          root slot: x x slot(LE2)                      (Juggluco raw[3..4])
//   A1 20          challenge(25): sensorRandom(7) counter(LE4) 3 salt(3) streamPrefix(4) epoch(2) CRC(2)
//   A1 cmd ‖ 15    authenticated command: Speck-CTR(kAuth, nonce step 0,
//                  hostRandom(7) ‖ ~cmd ‖ sensorRandom(7))
//     1F           FRAM read auth -> header(8) ‖ CTR(step 1, hostRandom ‖ context16) ‖ CRC
//     1E           enable streaming -> header(8) ‖ CTR(step 1, sensorRandom ‖ payload9 ‖ hostRandom) ‖ CRC
//                  payload9 = BLE address(6) ‖ the last 3 bytes of streamingAuthData
//   A1 21 b n-1    n blocks from b: header(8) ‖ n × 8, each XORed with
//                  Speck(dataKey, 00 b streamPrefix(top bit of byte 5 clear) epoch)
//
// streamingAuthData (the BLE provisioning) = streamPrefix ‖ salt ‖ payload9[6..<9].

extension Libre2Gen2 {
    static let cmdEnableStreaming: UInt8 = 0x1E
    static let cmdAuthenticateFRAMRead: UInt8 = 0x1F
    static let cmdReadBlocks: UInt8 = 0x21
    static let cmdReadRootSlot: UInt8 = 0x22
    static let nfcChallengeLength = 25
    static let nfcReplyHeaderLength = 8
    static let nfcAuthReplyLength = 8 + 23 + 2

    /// The CRC of data[0..<count], stored little-endian behind it.
    static func hasCRC(_ data: [UInt8], payloadCount count: Int) -> Bool {
        guard data.count >= count + 2 else { return false }
        return crc16(data[0..<count]) == (UInt16(data[count]) | (UInt16(data[count + 1]) << 8))
    }

    /// The NFC auth nonce: as `authNonce`, but with the transport bit clear.
    static func nfcAuthNonce(salt: [UInt8], counter: UInt32) -> [UInt8] {
        [0, salt[0], salt[1], salt[2] & 0x7F] + le(counter)
    }
}

/// One authenticated NFC exchange: a challenge and the command that answers it.
final class Libre2Gen2NFCExchange {
    let credential: Libre2Gen2Credential
    let kauth: [UInt8]

    private(set) var sensorRandom: [UInt8] = []
    private(set) var counter: UInt32 = 0
    private(set) var salt: [UInt8] = []
    private(set) var streamPrefix: [UInt8] = []
    private(set) var epoch: [UInt8] = []
    private var hostRandom: [UInt8] = []

    init(uid: [UInt8], credential: Libre2Gen2Credential) throws {
        self.credential = credential
        self.kauth = try credential.kauth(uid: uid)
    }

    /// The A1 parameters (command ‖ 15 bytes) answering a 25-byte challenge.
    func request(challenge: [UInt8], command: UInt8, random overrideRandom: [UInt8]? = nil) throws -> [UInt8] {
        guard challenge.count == Libre2Gen2.nfcChallengeLength,
              Libre2Gen2.hasCRC(challenge, payloadCount: 23) else {
            throw Libre2Gen2.Libre2Gen2Error("NFC challenge of \(challenge.count) bytes, or its CRC, is wrong")
        }
        sensorRandom = Array(challenge[0..<7])
        counter = u32le(challenge, 7)
        salt = Array(challenge[14..<17])
        streamPrefix = Array(challenge[17..<21])
        epoch = Array(challenge[21..<23])
        hostRandom = overrideRandom ?? Libre2Gen2.randomBytes(Libre2Gen2.randomLength)
        let plaintext = hostRandom + [~command] + sensorRandom
        let nonce = Libre2Gen2.nfcAuthNonce(salt: salt, counter: counter)
        return [command] + (try Libre2Gen2.speckCTR(key: kauth, iv: nonce, data: plaintext))
    }

    private func openReply(_ reply: [UInt8], encryptedCount: Int) throws -> [UInt8] {
        let h = Libre2Gen2.nfcReplyHeaderLength
        guard reply.count == h + encryptedCount + 2,
              Libre2Gen2.hasCRC(Array(reply[h...]), payloadCount: encryptedCount) else {
            throw Libre2Gen2.Libre2Gen2Error("NFC reply of \(reply.count) bytes, or its CRC, is wrong")
        }
        let nonce = Libre2Gen2.nfcAuthNonce(salt: salt, counter: counter &+ 1)
        return try Libre2Gen2.speckCTR(key: kauth, iv: nonce, data: Array(reply[h..<(h + encryptedCount)]))
    }

    /// The data key from the reply to an authenticated FRAM read (0x1F).
    func dataKey(reply: [UInt8]) throws -> [UInt8] {
        let plaintext = try openReply(reply, encryptedCount: 23)
        guard Array(plaintext[0..<7]) == hostRandom else {
            throw Libre2Gen2.Libre2Gen2Error("the sensor did not echo our random bytes: kAuth differs, so the root slot is wrong")
        }
        return try credential.sessionKey(context: Array(plaintext[7..<23]))
    }

    /// The payload of an authenticated command's reply, both randoms checked.
    func commandReply(_ reply: [UInt8], payloadCount: Int) throws -> [UInt8] {
        let r = Libre2Gen2.randomLength
        let plaintext = try openReply(reply, encryptedCount: payloadCount + 2 * r)
        guard Array(plaintext[0..<r]) == sensorRandom,
              Array(plaintext[(r + payloadCount)...]) == hostRandom else {
            throw Libre2Gen2.Libre2Gen2Error("the command reply's random echoes do not match")
        }
        return Array(plaintext[r..<(r + payloadCount)])
    }

    /// Decrypt FRAM blocks read with A1 21 under the data key.
    func decryptBlocks(dataKey: [UInt8], firstBlock: Int, encrypted: [UInt8]) throws -> [UInt8] {
        var out = [UInt8]()
        for i in 0..<(encrypted.count / 8) {
            var nonce = [UInt8](repeating: 0, count: 8)
            nonce[1] = UInt8((firstBlock + i) & 0xFF)
            nonce[2..<6] = streamPrefix[0..<4]
            nonce[5] &= 0x7F
            nonce[6..<8] = epoch[0..<2]
            // one block per nonce: the counter byte is the block number's own
            out += try Libre2Gen2.speckCTR(key: dataKey, iv: nonce, data: Array(encrypted[(i * 8)..<(i * 8 + 8)]))
        }
        return out
    }

    /// streamingAuthData: streamPrefix ‖ salt ‖ the reply's last 3 bytes.
    func streamingAuthData(enableStreamingPayload payload: [UInt8]) -> [UInt8] {
        streamPrefix + salt + Array(payload[6..<9])
    }
}
