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
    }

    func testParseKeyIndex() throws {
        XCTAssertEqual(try Libre2Gen2.parseKeyIndex(response: [0x00, 0x00, 0x02, 0x00]), 2)
        // The same answer with the response-flags byte already stripped.
        XCTAssertEqual(try Libre2Gen2.parseKeyIndex(response: [0x00, 0x02, 0x00], offset: 1), 2)
        XCTAssertThrowsError(try Libre2Gen2.parseKeyIndex(response: [0x00, 0x02], offset: 1))
        XCTAssertEqual(try Libre2Gen2.keyIndexCommand(uid: [0, 0, 0, 0, 0, 0, 0x07, 0xE0]),
                       [0x02, 0xA1, 0x07, 0x22])
    }
}
