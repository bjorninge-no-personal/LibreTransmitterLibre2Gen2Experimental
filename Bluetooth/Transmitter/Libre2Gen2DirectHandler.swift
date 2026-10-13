//
//  Libre2Gen2DirectHandler.swift
//  LibreTransmitter
//
//  The BLE-side state machine for a Libre 2 "generation 2" sensor, driving the
//  pure crypto in Libre2Gen2.swift. Gen2 sensors advertise the same service
//  and characteristics as gen1 (FDE3 / F001 / F002) and the same peripheral
//  name, so they arrive through `Libre2DirectTransmitter`; that class branches
//  to this handler when the paired sensor is gen2.
//
//  WHAT IS KNOWN (read off the reference and verified in Libre2Gen2Tests):
//    - the crypto: challenge -> command -> session-info -> per-packet decrypt.
//    - message shapes: 14-byte challenge, 19-byte command out, 25-byte session
//      info, 46-byte readings, 44-byte decrypted payload.
//
//  WHAT IS NOT YET CONFIRMED (needs a real gen2 sensor or the binary's
//  transport layer — the Python reference has no transport):
//    - the exact BLE choreography: whether a kick-off write is needed, on which
//      characteristic the challenge arrives, and how multi-notification
//      messages are framed/reassembled. The reassembly below keys off message
//      length, which is a placeholder until the framing is observed on-device.
//  These sites are marked `GEN2-TRANSPORT-TODO`.
//

import Foundation
import os.log

/// The result of feeding one reassembled message to the handler.
enum Libre2Gen2Action {
    /// Write these bytes to the write characteristic (the session-info command).
    case write([UInt8])
    /// A reading was decrypted: 44-byte payload ready for `Libre2.parseBLEData`.
    case payload([UInt8])
    /// Nothing to do yet (e.g. session info consumed, key established).
    case none
    /// The exchange failed; caller should reset. Carries the reason.
    case failure(Error)
}

final class Libre2Gen2DirectHandler {
    private lazy var logger = Logger(forType: Self.self)

    private let session: Libre2Gen2Session

    init?(sensor: Sensor, keyStore: Libre2Gen2KeyStore) {
        guard sensor.isGen2Ready,
              let keyIndex = sensor.keyIndex,
              let blob = sensor.streamingAuthData else {
            return nil
        }
        do {
            self.session = try Libre2Gen2Session(
                uid: [UInt8](sensor.uuid),
                keyIndex: keyIndex,
                streamingAuthData: [UInt8](blob),
                keyStore: keyStore)
        } catch {
            return nil
        }
    }

    /// Classify a single reassembled message and advance the state machine.
    ///
    /// GEN2-TRANSPORT-TODO: dispatch is by length. Confirm against a real
    /// sensor that these lengths are unambiguous on the wire (they are distinct
    /// here: 14 / 25 / 46), and that readings cannot also be 25 bytes.
    func ingest(_ message: [UInt8]) -> Libre2Gen2Action {
        do {
            switch message.count {
            case Libre2Gen2.challengeLength:
                let command = try session.sessionInfoCommand(challenge: message)
                logger.debug("gen2: answering challenge with \(command.count)-byte command")
                return .write(command)

            case Libre2Gen2.sessionInfoLength:
                let key = try session.open(sessionInfo: message)
                logger.debug("gen2: session opened, key established (\(key.count) bytes)")
                return .none

            case let n where n >= Libre2Gen2.packetLength:
                guard session.sessionKey != nil else {
                    // A reading arrived before the handshake completed.
                    return .none
                }
                let payload = try session.decrypt(packet: message)
                return .payload(payload)

            default:
                logger.debug("gen2: ignoring \(message.count)-byte message")
                return .none
            }
        } catch {
            logger.error("gen2: \(error.localizedDescription)")
            return .failure(error)
        }
    }

    var isOpen: Bool { session.sessionKey != nil }
}

// MARK: - Key store

/// Runtime holder for the publisher's credential rows. The rows are NOT in
/// source control; they must be injected once at launch (e.g. decrypted from a
/// provisioning blob, or read from the Keychain) before a gen2 sensor streams.
/// Left empty, every gen2 session fails closed with "key index not present".
final class Libre2Gen2RuntimeKeyStore: Libre2Gen2KeyStore {
    static let shared = Libre2Gen2RuntimeKeyStore()

    private var rows: [Int: Libre2Gen2Credential] = [:]
    private let queue = DispatchQueue(label: "Libre2Gen2RuntimeKeyStore")

    private init() {}

    /// Inject one credential row. `authKey` and `sessionGeneratorKey` are the
    /// two unsealed AES-128 keys for that index.
    func install(index: Int, authKey: [UInt8], sessionGeneratorKey: [UInt8]) {
        queue.sync {
            rows[index] = Libre2Gen2Credential(index: index,
                                               authKey: authKey,
                                               sessionGeneratorKey: sessionGeneratorKey)
        }
    }

    var hasKeys: Bool { queue.sync { !rows.isEmpty } }

    func credential(forIndex index: Int) -> Libre2Gen2Credential? {
        queue.sync { rows[index] }
    }
}
