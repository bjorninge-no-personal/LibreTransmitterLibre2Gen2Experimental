//
//  Libre2Gen2DirectHandler.swift
//  LibreTransmitter
//
//  The message-level state machine for a Libre 2 "generation 2" sensor,
//  driving the pure crypto in Libre2Gen2.swift: it turns a whole challenge
//  into the session-info command, opens the session on session info, and
//  decrypts glucose records. The BLE transport around it (notifications,
//  kickoff, reassembly) is Libre2Gen2Connection.
//
//  WHAT IS KNOWN (read off the reference and verified in Libre2Gen2Tests):
//    - the crypto: challenge -> command -> session-info -> per-packet decrypt.
//    - message shapes: 14-byte challenge, 19-byte command out, 25-byte session
//      info, 46-byte readings, 44-byte decrypted payload.
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

    /// Classify a single *fully reassembled* message and advance the state
    /// machine. The caller (Libre2Gen2Connection) reassembles the raw
    /// notifications by exchange phase before calling this, so the message
    /// lengths dispatched on here are the whole-message totals and are
    /// unambiguous: 14 (challenge) / 25 (session info) / >= 46 (reading). The
    /// colliding raw-fragment lengths never reach this point.
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

    /// Called on each new connection, before the kickoff: the sensor opens a
    /// new session every time, so the previous one's key must not be used.
    func reset() {
        session.reset()
    }
}
