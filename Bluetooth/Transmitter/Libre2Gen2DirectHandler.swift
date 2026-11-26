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
//  BLE CHOREOGRAPHY (LibreLink's BLE callback class; applied in
//  Libre2DirectTransmitter, which owns the transport/reassembly):
//    - enable notifications on F001 only; once that completes, write {0x20}
//      ("read security challenge") on F001.
//    - F001 challenge: ONE 14-byte notification.
//    - F001 session info: TWO notifications, 7 bytes THEN 18 (total 25).
//    - only once the session is open, enable notifications on F002.
//    - F002 stream: each 46-byte record as THREE notifications of 20, 18 and
//      8 bytes, placed by length at 0, 20 and 38 as LibreLink does.
//  This handler only ever sees a fully reassembled message, so its length
//  dispatch below is unambiguous.
//
//  STILL NEEDS A REAL-SENSOR CAPTURE: the sequence and chunk lengths are
//  LibreLink's, but have not been seen on a real gen2 sensor here.
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
    /// machine. The caller (Libre2DirectTransmitter) reassembles the raw
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
