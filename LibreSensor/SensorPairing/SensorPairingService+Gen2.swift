//
//  SensorPairingService+Gen2.swift
//  LibreTransmitter
//
//  NFC side of pairing a Libre 2 "generation 2" sensor. On top of the gen1
//  inputs, gen2 needs two credentials only NFC can provide: the root slot
//  (`keyIndex`) and streamingAuthData (the BLE provisioning).
//
//  The exchange follows Juggluco's Gen2.java (readAuthenticatedFram,
//  enableStreaming); the crypto is in Libre2Gen2.swift (Libre2Gen2NFCExchange).
//  It used to send gen1 commands (an unauthenticated A1 21 read and the gen1
//  0x1E), which a gen2 sensor that follows Juggluco's protocol refuses.
//
//  `Libre2Gen2Pairing.pair` is transport-agnostic: CoreNFC's customCommand here,
//  libre2sim's /nfc in SimulatedSensorPairingService, so the two cannot drift.
//
//  Order matters: everything read-only comes first, and enable-streaming (the
//  one command that changes sensor state, handing BLE to this app) is sent
//  last, only once FRAM and the root slot are known good. Every failure is
//  closed: nothing is handed to setup unless all of it succeeded.
//

import Foundation
import CoreNFC
import os.log

/// What a gen2 NFC pairing yields.
struct Libre2Gen2PairingResult {
    let fram: Data              // decrypted, 344 bytes, CRCs checked
    let rootSlot: Int           // stored as Sensor.keyIndex
    let streamingAuthData: Data // 10 bytes
    let bleAddress: Data        // as the sensor sends it (least significant byte first)
}

enum Libre2Gen2Pairing {
    static let framBlocks = 43
    static let blocksPerRequest = 3
    /// Attempts per command, as LibreLink (DefaultNfcRfModuleGen2.tranceiveWithRetries)
    static let attemptsPerCommand = 5

    /// Run the gen2 NFC exchange. `custom` sends ISO 15693 custom command 0xA1
    /// with the given parameters and returns the reply as CoreNFC does.
    static func pair(uid: [UInt8],
                     keyStore: Libre2Gen2KeyStore = Libre2Gen2RootKeyStore(),
                     custom: (Data) async throws -> Data) async throws -> Libre2Gen2PairingResult {
        // Each command is retried on its own, as LibreLink does, so one
        // dropped exchange in the 20 needed does not fail the pairing.
        func send(_ parameters: [UInt8]) async throws -> [UInt8] {
            var attempt = 1
            while true {
                do {
                    return [UInt8](try await custom(Data(parameters)))
                } catch {
                    guard attempt < attemptsPerCommand, !Task.isCancelled else { throw error }
                    attempt += 1
                }
            }
        }

        // Root slot: A1 22, the u16 at raw[3..4], CoreNFC [2..3].
        let slotReply = try await send([Libre2Gen2.cmdReadRootSlot])
        guard slotReply.count >= 4 else {
            throw Libre2Gen2.Libre2Gen2Error("root slot reply of \(slotReply.count) bytes")
        }
        let rootSlot = Int(slotReply[2]) | (Int(slotReply[3]) << 8)
        guard let credential = keyStore.credential(forIndex: rootSlot) else {
            throw PairingError.gen2CredentialsUnavailable
        }

        // FRAM: an authenticated 0x1F, then encrypted A1 21 reads.
        let framExchange = try Libre2Gen2NFCExchange(uid: uid, credential: credential)
        let framRequest = try framExchange.request(challenge: try await send([Libre2Gen2.cmdReadChallenge]),
                                                   command: Libre2Gen2.cmdAuthenticateFRAMRead)
        let dataKey = try framExchange.dataKey(reply: try await send(framRequest))
        var fram = [UInt8]()
        for first in stride(from: 0, to: framBlocks, by: blocksPerRequest) {
            let count = min(blocksPerRequest, framBlocks - first)
            let reply = try await send([Libre2Gen2.cmdReadBlocks, UInt8(first), UInt8(count - 1)])
            let h = Libre2Gen2.nfcReplyHeaderLength
            guard reply.count == h + count * 8 else {
                throw Libre2Gen2.Libre2Gen2Error("A1 21 block \(first): reply of \(reply.count) bytes")
            }
            fram += try framExchange.decryptBlocks(dataKey: dataKey, firstBlock: first, encrypted: Array(reply[h...]))
        }
        // Calibration comes from FRAM, and glucose is computed from it. Never
        // store calibration from bytes that are not self-consistent.
        guard let sensorData = SensorData(bytes: fram), sensorData.hasValidCRCs else {
            throw PairingError.decryptionError
        }

        // Enable streaming last: an authenticated 0x1E.
        let streamExchange = try Libre2Gen2NFCExchange(uid: uid, credential: credential)
        let streamRequest = try streamExchange.request(challenge: try await send([Libre2Gen2.cmdReadChallenge]),
                                                       command: Libre2Gen2.cmdEnableStreaming)
        let payload = try streamExchange.commandReply(try await send(streamRequest), payloadCount: 9)

        return Libre2Gen2PairingResult(fram: Data(fram), rootSlot: rootSlot,
                                       streamingAuthData: Data(streamExchange.streamingAuthData(enableStreamingPayload: payload)),
                                       bleAddress: Data(payload[0..<6]))
    }
}

extension Libre2Gen2PairingResult {
    /// The BLE name, as gen1 derives it from its enable-streaming reply.
    var macAddress: String { Data(bleAddress.reversed()).hexEncodedString().uppercased() }

    func pairingInfo(sensorUID: Data, patchInfo: Data) -> SensorPairingInfo {
        SensorPairingInfo(uuid: sensorUID, patchInfo: patchInfo, fram: fram, streamingEnabled: true,
                          macAddress: macAddress, keyIndex: rootSlot, streamingAuthData: streamingAuthData)
    }
}

extension SensorPairingService {

    func pairGen2(session: NFCTagReaderSession, tag: NFCISO15693Tag, sensorUID: Data, patchInfo: Data) {
        let logger = Logger(forType: Self.self)

        guard sensorUID.count == Libre2Gen2.uidLength, patchInfo.count == 6 || patchInfo.count == 8 else {
            session.invalidate(errorMessage: PairingError.noSensorData.localizedDescription)
            sendError(PairingError.noSensorData)
            return
        }

        Task {
            do {
                let result = try await Libre2Gen2Pairing.pair(uid: [UInt8](sensorUID)) { parameters in
                    try await withCheckedThrowingContinuation { continuation in
                        tag.customCommand(requestFlags: .highDataRate, customCommandCode: 0xA1,
                                          customRequestParameters: parameters) { response, error in
                            if let error {
                                continuation.resume(throwing: error)
                            } else {
                                continuation.resume(returning: response)
                            }
                        }
                    }
                }
                self.sendUpdate(result.pairingInfo(sensorUID: sensorUID, patchInfo: patchInfo))
                session.invalidate()
            } catch {
                logger.error("gen2: pairing failed: \(error.localizedDescription)")
                // Only an unknown root slot means the sensor can't be supported; anything
                // else (a dropped NFC exchange, an unexpected reply) is worth a new scan
                let pairingError = error as? PairingError ?? .readInterrupted
                session.invalidate(errorMessage: pairingError.localizedDescription)
                self.sendError(pairingError)
            }
        }
    }
}
