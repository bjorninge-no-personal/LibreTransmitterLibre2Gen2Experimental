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
//  NOTE ON KEYS: the three credential rows (two AES-128 keys each) are NOT
//  embedded here. They belong to the publisher and must be supplied at runtime
//  through a `Libre2Gen2KeyStore`. This file contains only the algorithms.
//
//  NOTE ON THE KDF: `Libre2Gen2.derive(...)` implements NIST SP 800-108
//  counter-mode framing with CMAC-AES-128. Per the reference, this one link is
//  NOT confirmed against a real sensor. If it is wrong, every derived key is
//  wrong, and the round-trip self-test cannot tell (it only checks that both
//  sides agree with themselves). Settling it needs a real Gen2 sensor.
//

import Foundation
import CommonCrypto

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

    // The two KDF labels differ only by the case of one letter.
    static let authLabel = Array("ADC_*SpeckPatch#".utf8)
    static let sessionLabel = Array("ADC_*SpecKpatch#".utf8)

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
    /// `Crc.crc16`) no byte swap.
    static func crc16(_ data: ArraySlice<UInt8>) -> UInt16 {
        var crc: UInt16 = 0xFFFF
        for b in data {
            crc = crcTable[Int((crc ^ UInt16(b)) & 0xFF)] ^ (crc >> 8)
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

// MARK: - CMAC-AES-128 and SP 800-108 derivation

extension Libre2Gen2 {
    /// A single AES-128 ECB block (no padding), used only to build CMAC.
    private static func aesEncryptBlock(key: [UInt8], block: [UInt8]) throws -> [UInt8] {
        precondition(key.count == 16 && block.count == 16)
        var out = [UInt8](repeating: 0, count: 16)
        var moved = 0
        let status = key.withUnsafeBytes { keyPtr in
            block.withUnsafeBytes { dataPtr in
                out.withUnsafeMutableBytes { outPtr in
                    CCCrypt(
                        CCOperation(kCCEncrypt),
                        CCAlgorithm(kCCAlgorithmAES),
                        CCOptions(kCCOptionECBMode),
                        keyPtr.baseAddress, key.count,
                        nil,
                        dataPtr.baseAddress, block.count,
                        outPtr.baseAddress, outPtr.count,
                        &moved)
                }
            }
        }
        guard status == kCCSuccess, moved == 16 else {
            throw Libre2Gen2Error("AES block failed (status \(status))")
        }
        return out
    }

    private static func leftShiftOne(_ input: [UInt8]) -> [UInt8] {
        var output = [UInt8](repeating: 0, count: input.count)
        var overflow: UInt8 = 0
        for i in stride(from: input.count - 1, through: 0, by: -1) {
            output[i] = (input[i] << 1) | overflow
            overflow = (input[i] & 0x80) != 0 ? 1 : 0
        }
        return output
    }

    /// CMAC-AES-128 (RFC 4493) over an arbitrary-length message.
    static func cmac(key: [UInt8], message: [UInt8]) throws -> [UInt8] {
        guard key.count == 16 else {
            throw Libre2Gen2Error("cmac key of \(key.count) bytes, expected 16")
        }
        let rb: UInt8 = 0x87
        let zero = [UInt8](repeating: 0, count: 16)

        // Subkey generation.
        let l = try aesEncryptBlock(key: key, block: zero)
        var k1 = leftShiftOne(l)
        if (l[0] & 0x80) != 0 { k1[15] ^= rb }
        var k2 = leftShiftOne(k1)
        if (k1[0] & 0x80) != 0 { k2[15] ^= rb }

        // Last block.
        let n = (message.count + 15) / 16
        let complete = message.count > 0 && message.count % 16 == 0
        let blocks = max(n, 1)

        var lastBlock: [UInt8]
        if complete {
            lastBlock = Array(message[(blocks - 1) * 16 ..< blocks * 16])
            lastBlock = zip(lastBlock, k1).map { $0 ^ $1 }
        } else {
            let start = (blocks - 1) * 16
            var padded = Array(message[start...])
            padded.append(0x80)
            while padded.count < 16 { padded.append(0x00) }
            lastBlock = zip(padded, k2).map { $0 ^ $1 }
        }

        // CBC-MAC with a zero IV.
        var x = zero
        for i in 0..<(blocks - 1) {
            let block = Array(message[i * 16 ..< (i + 1) * 16])
            x = try aesEncryptBlock(key: key, block: zip(x, block).map { $0 ^ $1 })
        }
        return try aesEncryptBlock(key: key, block: zip(x, lastBlock).map { $0 ^ $1 })
    }

    /// NIST SP 800-108 key derivation, counter mode — NOT MEASURED. See the
    /// file header. Framing:
    ///
    ///     K(i) = CMAC(key, i(4, big-endian) || label || 0x00
    ///                     || context || L(4, big-endian))
    static func derive(key: [UInt8], label: [UInt8], context: [UInt8],
                       length: Int = keyLength) throws -> [UInt8] {
        var out = [UInt8]()
        var counter: UInt32 = 1
        let lBits = UInt32(length * 8)
        while out.count < length {
            var input = be(counter)
            input += label
            input.append(0x00)
            input += context
            input += be(lBits)
            out += try cmac(key: key, message: input)
            counter += 1
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

/// One row of the credential table, picked by its index. The same index serves
/// both derivations: `authKey` yields kAuth (opening exchange), and
/// `sessionGeneratorKey` yields the reading key. The index enters no context,
/// no nonce and no transmitted byte; it only selects the row.
struct Libre2Gen2Credential {
    let index: Int
    let authKey: [UInt8]
    let sessionGeneratorKey: [UInt8]

    /// kAuth, derived from the sensor UID and nothing else. The context is
    /// UID[0..<6], the serial without the manufacturer code and ISO prefix.
    func kauth(uid: [UInt8]) throws -> [UInt8] {
        guard uid.count == Libre2Gen2.uidLength else {
            throw Libre2Gen2.Libre2Gen2Error("uid of \(uid.count) bytes, expected \(Libre2Gen2.uidLength)")
        }
        return try Libre2Gen2.derive(key: authKey,
                                     label: Libre2Gen2.authLabel,
                                     context: Array(uid[0..<Libre2Gen2.contextLength]))
    }

    /// The reading key. The context comes out of the sensor's reply.
    func sessionKey(context: [UInt8]) throws -> [UInt8] {
        guard context.count == Libre2Gen2.keyLength else {
            throw Libre2Gen2.Libre2Gen2Error("context of \(context.count) bytes, expected \(Libre2Gen2.keyLength)")
        }
        return try Libre2Gen2.derive(key: sessionGeneratorKey,
                                     label: Libre2Gen2.sessionLabel,
                                     context: context)
    }
}

/// Supplies the publisher's credential rows at runtime. Implementations keep
/// the key material out of version control.
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

/// 4 big-endian bytes of a u32.
private func be(_ value: UInt32) -> [UInt8] {
    [UInt8((value >> 24) & 0xFF),
     UInt8((value >> 16) & 0xFF),
     UInt8((value >> 8) & 0xFF),
     UInt8(value & 0xFF)]
}
