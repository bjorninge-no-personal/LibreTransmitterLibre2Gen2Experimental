//
//  Libre2Gen2Tests.swift
//  LibreTransmitterTests
//
//  A full Gen2 session against a simulated sensor, mirroring example.py.
//
//  The sensor is not reproduced: only the three things it sends are -- the
//  challenge, the opening reply, the packets -- computed with the same keys.
//  That exercises the whole chain and checks that both sides land on the same
//  session key. No real key material is used: the credential rows below are
//  arbitrary and exist only to make both halves agree with themselves.
//
//  This CANNOT validate `derive(...)` against a real sensor; it only proves the
//  Swift port is internally consistent (see the note in Libre2Gen2.swift).
//

import XCTest
@testable import LibreTransmitter

/// A keystore of arbitrary, non-secret rows for the self-test.
private struct DummyKeyStore: Libre2Gen2KeyStore {
    static let rows: [Int: (auth: [UInt8], session: [UInt8])] = [
        0: (auth: Array(repeating: 0xA0, count: 16), session: Array(repeating: 0xA0, count: 16)),
        1: (auth: Array(repeating: 0x11, count: 16), session: Array(repeating: 0x22, count: 16)),
        2: (auth: Array(repeating: 0x33, count: 16), session: Array(repeating: 0x44, count: 16)),
    ]

    func credential(forIndex index: Int) -> Libre2Gen2Credential? {
        guard let row = Self.rows[index] else { return nil }
        return Libre2Gen2Credential(index: index, authKey: row.auth, sessionGeneratorKey: row.session)
    }
}

/// The bare minimum: a UID, a stream blob, and the replies.
private final class FakeGen2Sensor {
    let uid: [UInt8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x07, 0xE0]
    let blob = Libre2Gen2.randomBytes(Libre2Gen2.streamingAuthLength)
    let credential: Libre2Gen2Credential
    let kauth: [UInt8]
    let context = Libre2Gen2.randomBytes(16)

    private var counter: UInt32 = 0
    private var head: [UInt8] = []

    init(index: Int, keyStore: Libre2Gen2KeyStore) throws {
        self.credential = keyStore.credential(forIndex: index)!
        self.kauth = try credential.kauth(uid: uid)
    }

    /// 14 bytes. The four from offset 7 carry the counter.
    func challenge() -> [UInt8] {
        counter = Libre2Gen2.randomBytes(4).withUnsafeBytes { $0.load(as: UInt32.self) }
        head = Libre2Gen2.randomBytes(7)
        let c = withUnsafeBytes(of: counter.littleEndian) { Array($0) }
        return head + c + Libre2Gen2.randomBytes(3)
    }

    /// Check the command, then return the 25 opening bytes.
    func reply(command: [UInt8]) throws -> [UInt8] {
        guard command[0] == Libre2Gen2.cmdSessionInfo else {
            throw Libre2Gen2.Libre2Gen2Error("unexpected opcode")
        }
        let nonce = try Libre2Gen2.authNonce(seed: Array(blob[4..<7]), counter: counter)
        let plain = try Libre2Gen2.speckCTR(key: kauth, iv: nonce, data: Array(command[1...]))
        guard Array(plain[8..<11]) == Array(blob[7..<10]), Array(plain[11..<18]) == head else {
            throw Libre2Gen2.Libre2Gen2Error("the app does not hold our kAuth")
        }
        let nonce2 = try Libre2Gen2.authNonce(seed: Array(blob[4..<7]), counter: counter &+ 1)
        let out = try Libre2Gen2.speckCTR(key: kauth, iv: nonce2, data: Array(plain[0..<7]) + context)
        return out + [0x00, 0x00]
    }

    /// A 46-byte packet, CRC applied as the sensor would.
    func reading(number: UInt16) throws -> [UInt8] {
        let key = try credential.sessionKey(context: context)
        let counterBytes = withUnsafeBytes(of: number.littleEndian) { Array($0) }
        var plain = Array("realtime glucose".utf8)
        while plain.count < Libre2Gen2.payloadLength - Libre2Gen2.crcLength { plain.append(0x00) }
        let payload = try Libre2Gen2.sealCRC(plain)
        let iv = try Libre2Gen2.dataIV(streamID: Array(blob[0..<4]), packetCounter: counterBytes)
        return counterBytes + (try Libre2Gen2.speckCTR(key: key, iv: iv, data: payload))
    }
}

final class Libre2Gen2Tests: XCTestCase {

    private let keyStore = DummyKeyStore()

    func testCRCRoundTrips() throws {
        let body = Array("some 42-byte payload goes right here!!".utf8)
            + [UInt8](repeating: 0, count: 42 - "some 42-byte payload goes right here!!".count)
        let sealed = try Libre2Gen2.sealCRC(body)
        XCTAssertEqual(sealed.count, Libre2Gen2.payloadLength)
        XCTAssertTrue(Libre2Gen2.checkCRC(sealed))
        var corrupted = sealed
        corrupted[0] ^= 0xFF
        XCTAssertFalse(Libre2Gen2.checkCRC(corrupted))
    }

    /// Canonical Speck64/128 known-answer test (the vector published with the
    /// cipher and used by Juggluco protocol.c). This pins the round function,
    /// key schedule and little-endian block I/O so the derived keys match a real
    /// sensor, which no round-trip self-test could catch.
    func testSpeckKnownAnswer() {
        let key: [UInt8] = [0, 1, 2, 3, 8, 9, 10, 11, 16, 17, 18, 19, 24, 25, 26, 27]
        let plaintext: [UInt8] = [0x2d, 0x43, 0x75, 0x74, 0x74, 0x65, 0x72, 0x3b]
        let expected: [UInt8] = [0x8b, 0x02, 0x4e, 0x45, 0x48, 0xa5, 0x6f, 0x8c]
        XCTAssertEqual(Libre2Gen2.speckEncryptBlock(key: key, block: plaintext), expected)
    }

    /// The root tables must be transcribed exactly, or every derived key is wrong.
    func testRootTablesPresent() {
        XCTAssertEqual(Libre2Gen2.sensorRoots.count, 2)
        XCTAssertEqual(Libre2Gen2.sessionRoots.count, 2)
        XCTAssertEqual(Libre2Gen2.sensorRoots[0].first, 0xa1)
        XCTAssertEqual(Libre2Gen2.sessionRoots[1].first, 0x4e)
        XCTAssertEqual(Libre2Gen2.credential(rootSlot: 1)?.authKey, Libre2Gen2.sensorRoots[0])
        XCTAssertNil(Libre2Gen2.credential(rootSlot: 3))
    }

    func testSpeckIsItsOwnInverse() throws {
        let key = Array(repeating: UInt8(0x5A), count: 16)
        let iv = Array(repeating: UInt8(0x01), count: 8)
        let data = Array("the quick brown fox jumps over".utf8)
        let ct = try Libre2Gen2.speckCTR(key: key, iv: iv, data: data)
        let pt = try Libre2Gen2.speckCTR(key: key, iv: iv, data: ct)
        XCTAssertEqual(pt, data)
        XCTAssertNotEqual(ct, data)
    }

    func testFullSession() throws {
        let sensor = try FakeGen2Sensor(index: 1, keyStore: keyStore)
        let session = try Libre2Gen2Session(uid: sensor.uid, keyIndex: 1,
                                            streamingAuthData: sensor.blob, keyStore: keyStore)

        // Both sides must derive the same kAuth.
        XCTAssertEqual(session.kauth, sensor.kauth)

        let challenge = sensor.challenge()
        let command = try session.sessionInfoCommand(challenge: challenge)
        XCTAssertEqual(command.count, Libre2Gen2.commandLength)

        let reply = try sensor.reply(command: command)
        let appKey = try session.open(sessionInfo: reply)
        let sensorKey = try sensor.credential.sessionKey(context: sensor.context)
        XCTAssertEqual(appKey, sensorKey)

        let packet = try sensor.reading(number: 1)
        let payload = try session.decrypt(packet: packet)
        XCTAssertEqual(payload.count, Libre2Gen2.payloadLength)
        XCTAssertEqual(Array(payload[0..<"realtime glucose".count]), Array("realtime glucose".utf8))
    }

    func testWrongIndexIsCaught() throws {
        let sensor = try FakeGen2Sensor(index: 1, keyStore: keyStore)
        // A wrong index means a different kAuth, so the echoed random bytes
        // do not match. That is the only test a client has.
        let wrong = try Libre2Gen2Session(uid: sensor.uid, keyIndex: 2,
                                          streamingAuthData: sensor.blob, keyStore: keyStore)
        let challenge = sensor.challenge()
        _ = try wrong.sessionInfoCommand(challenge: challenge)
        let reply = try sensor.reply(command: try {
            // Produce a valid command/reply pair from the *correct* session so
            // the sensor answers at all; the wrong session must then reject it.
            let right = try Libre2Gen2Session(uid: sensor.uid, keyIndex: 1,
                                             streamingAuthData: sensor.blob, keyStore: keyStore)
            return try right.sessionInfoCommand(challenge: challenge)
        }())
        XCTAssertThrowsError(try wrong.open(sessionInfo: reply))
    }

    func testSecurityGeneration() throws {
        // Real patchInfo prefixes, as recorded in DiaBLE's Libre.swift. The
        // generation is in byte 2; byte 3 is the region and must not matter.
        let gen2: [[UInt8]] = [
            [0x2C, 0x0A, 0x3A, 0x02],   // Libre 2+ US
            [0x2B, 0x0A, 0x3A, 0x08],   // Libre 2+ LA
            [0x2B, 0x0A, 0x39, 0x08],   // Libre 2 RU (Gen2)
        ]
        let gen1: [[UInt8]] = [
            [0xC6, 0x09, 0x31, 0x01],   // Libre 2+ EU
            [0x7F, 0x0E, 0x31, 0x01],   // Libre 2+ EU, mid 2025
            [0x7F, 0x0E, 0x30, 0x01],   // Libre 2 EU
            [0x9D, 0x08, 0x30, 0x01, 0x73, 0x17],   // Libre2.Example.sensorInfo, gen1 EU
        ]
        for info in gen2 {
            XCTAssertEqual(try Libre2Gen2.securityGeneration(patchInfo: info), 2, "\(info)")
        }
        for info in gen1 {
            XCTAssertEqual(try Libre2Gen2.securityGeneration(patchInfo: info), 1, "\(info)")
        }
        XCTAssertThrowsError(try Libre2Gen2.securityGeneration(patchInfo: [0x2C, 0x0A]))

        // LibreLink's rule: product type 3 is gen2 from security version 9,
        // product type 7 from security version 4; any other type is neither.
        XCTAssertEqual(try Libre2Gen2.securityGeneration(patchInfo: [0x00, 0x00, 0x74, 0x02]), 2)
        XCTAssertEqual(try Libre2Gen2.securityGeneration(patchInfo: [0x00, 0x00, 0x7F, 0x02]), 2)
        XCTAssertEqual(try Libre2Gen2.securityGeneration(patchInfo: [0x00, 0x00, 0x73, 0x02]), 1)
        XCTAssertEqual(try Libre2Gen2.securityGeneration(patchInfo: [0x00, 0x00, 0x39, 0x02]), 2)
        XCTAssertEqual(try Libre2Gen2.securityGeneration(patchInfo: [0x00, 0x00, 0x38, 0x02]), 1)
        XCTAssertEqual(try Libre2Gen2.securityGeneration(patchInfo: [0x00, 0x00, 0x5A, 0x02]), 0)
    }

    func testSessionResetForgetsTheKey() throws {
        let sensor = try FakeGen2Sensor(index: 1, keyStore: keyStore)
        let session = try Libre2Gen2Session(uid: sensor.uid, keyIndex: 1,
                                            streamingAuthData: sensor.blob, keyStore: keyStore)
        let command = try session.sessionInfoCommand(challenge: sensor.challenge())
        try session.open(sessionInfo: try sensor.reply(command: command))
        XCTAssertNotNil(session.sessionKey)

        // A new connection must not decrypt with the previous connection's key,
        // nor open a session from its exchange
        session.reset()
        XCTAssertNil(session.sessionKey)
        XCTAssertThrowsError(try session.decrypt(packet: try sensor.reading(number: 1)))
        XCTAssertThrowsError(try session.open(sessionInfo: try sensor.reply(command: command)))
    }

    func testPairingRetriesEachCommandAsLibreLink() async throws {
        let uid = Self.bytes("1122334455a407e0")
        struct Dropped: Error {}

        // A command that keeps failing is tried attemptsPerCommand times, then fails the pairing
        var calls = 0
        do {
            _ = try await Libre2Gen2Pairing.pair(uid: uid) { _ in
                calls += 1
                throw Dropped()
            }
            XCTFail("pairing should fail")
        } catch is Dropped {
        }
        XCTAssertEqual(calls, Libre2Gen2Pairing.attemptsPerCommand)

        // One dropped exchange is retried: the second answer is used
        var sent = [Data]()
        do {
            _ = try await Libre2Gen2Pairing.pair(uid: uid) { parameters in
                sent.append(parameters)
                if sent.count == 1 { throw Dropped() }
                return Data([0x00, 0x00, 0x09, 0x00])   // root slot 9, which is not present
            }
            XCTFail("pairing should fail on the unknown root slot")
        } catch is Dropped {
            XCTFail("the dropped exchange should have been retried")
        } catch {
        }
        XCTAssertEqual(sent, [Data([Libre2Gen2.cmdReadRootSlot]), Data([Libre2Gen2.cmdReadRootSlot])])
    }

    func testParseKeyIndex() throws {
        XCTAssertEqual(try Libre2Gen2.parseKeyIndex(response: [0x00, 0x00, 0x02, 0x00]), 2)
        // The same answer with the response-flags byte already stripped.
        XCTAssertEqual(try Libre2Gen2.parseKeyIndex(response: [0x00, 0x02, 0x00], offset: 1), 2)
        XCTAssertThrowsError(try Libre2Gen2.parseKeyIndex(response: [0x00, 0x02], offset: 1))
        XCTAssertEqual(try Libre2Gen2.keyIndexCommand(uid: [0, 0, 0, 0, 0, 0, 0x07, 0xE0]),
                       [0x02, 0xA1, 0x07, 0x22])
    }

    // MARK: - Vectors from Juggluco's compiled protocol.c (independent oracle)
    //
    // Generated by building Juggluco's libre2_imp/gen2/protocol.c (primary) and
    // calling l2g2_crc16, l2g2_build_nfc_auth_request and l2g2_make_data_nonce
    // with the inputs below, real root tables. Not derived from this code.

    private static func bytes(_ hex: String) -> [UInt8] {
        var out = [UInt8](); var i = hex.startIndex
        while i < hex.endIndex {
            let j = hex.index(i, offsetBy: 2)
            out.append(UInt8(hex[i..<j], radix: 16)!); i = j
        }
        return out
    }

    /// l2g2_crc16 pads odd-length input with a zero byte; the NFC challenge and
    /// replies CRC 23 bytes, so an unpadded CRC rejects every real NFC reply.
    func testCRCMatchesJugglucoIncludingOddLengths() {
        XCTAssertEqual(Libre2Gen2.crc16([1, 2, 3]), 0x5201)
        XCTAssertEqual(Libre2Gen2.crc16((0..<23).map { UInt8(truncatingIfNeeded: $0 * 7 + 1) }), 0x1467)
        XCTAssertEqual(Libre2Gen2.crc16((0..<42).map { UInt8(truncatingIfNeeded: $0 * 3) }), 0x5AC5)
    }

    func testNFCAuthRequestMatchesJuggluco() throws {
        let uid = Self.bytes("1122334455a407e0")
        let challenge = Self.bytes("30353a3f44494e53585d62676c71767b80858a8f94999ed830")
        let hostRandom = Self.bytes("a0a1a2a3a4a5a6")
        let expected: [Int: [UInt8: String]] = [
            1: [0x1F: "1fa5f689e836f4cfed66d153d430d179", 0x1E: "1ea5f689e836f4cfec66d153d430d179"],
            2: [0x1F: "1f1ed1fb1f9ff6f7a9a9dd9de0cb0187", 0x1E: "1e1ed1fb1f9ff6f7a8a9dd9de0cb0187"],
        ]
        let store = Libre2Gen2RootKeyStore()
        for (slot, byCommand) in expected {
            let credential = try XCTUnwrap(store.credential(forIndex: slot))
            for (command, params) in byCommand {
                let exchange = try Libre2Gen2NFCExchange(uid: uid, credential: credential)
                let request = try exchange.request(challenge: challenge, command: command, random: hostRandom)
                XCTAssertEqual(request, Self.bytes(params), "slot \(slot) command \(command)")
            }
        }
        // A challenge whose CRC does not check is refused before anything is sent.
        var bad = challenge
        bad[0] ^= 1
        let exchange = try Libre2Gen2NFCExchange(uid: uid, credential: try XCTUnwrap(store.credential(forIndex: 1)))
        XCTAssertThrowsError(try exchange.request(challenge: bad, command: 0x1F, random: hostRandom))
        // The fields parsed from the challenge give Juggluco's NFC data nonce.
        _ = try exchange.request(challenge: challenge, command: 0x1F, random: hostRandom)
        var nonce = [UInt8](repeating: 0, count: 8)
        nonce[2..<6] = exchange.streamPrefix[0..<4]
        nonce[5] &= 0x7F
        nonce[6..<8] = exchange.epoch[0..<2]
        XCTAssertEqual(nonce, Self.bytes("0000858a8f14999e"))
    }
}
