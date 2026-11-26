//
//  Libre2Gen2Connection.swift
//  LibreTransmitter
//
//  The BLE transport of a Libre 2 "generation 2" sensor: which notifications
//  to enable when, the kickoff, reassembly of notifications into messages, and
//  writing the session-info command. The crypto behind each message is in
//  Libre2Gen2DirectHandler / Libre2Gen2.swift.
//
//  Gen2 sensors advertise the same service and characteristics as gen1 and
//  arrive through Libre2DirectTransmitter, which hands everything to this
//  class when the paired sensor is gen2 and keeps the gen1 path to itself.
//
//  The sequence follows LibreLink's BLE callback class:
//    - enable notifications on F001 only; once that completes, write {0x20}
//      ("read security challenge") on F001.
//    - F001 challenge: ONE 14-byte notification, answered with the 19-byte
//      session-info command.
//    - F001 session info: a 7-byte and an 18-byte notification, at 0 and 7.
//    - only once the session is open, enable notifications on F002.
//    - F002 stream: each 46-byte record as a 20, an 18 and an 8-byte
//      notification, at 0, 20 and 38.
//
//  STILL NEEDS A REAL-SENSOR CAPTURE: this is LibreLink's sequence, not yet
//  seen on a real gen2 sensor here; the fragments are logged so a capture can
//  confirm it.
//

import CoreBluetooth
import Foundation
import os.log

final class Libre2Gen2Connection {
    private lazy var logger = Logger(forType: Self.self)

    weak var delegate: LibreTransmitterDelegate?

    // Nil when the sensor is gen2 but its NFC credentials or keys are missing:
    // such a sensor must never fall back to the gen1 unlock, it simply cannot stream.
    private let handler: Libre2Gen2DirectHandler?
    private let uuid: Data
    private let keyIndex: Int?
    private let streamingAuthData: Data?

    // Where we are in the exchange. Reassembly is keyed on this phase, because
    // notification lengths collide across phases: 18 bytes is both the second
    // part of session info and the middle of a record.
    private enum Phase {
        case awaitingNotify       // F001 notifications being enabled; kickoff not yet written
        case awaitingChallenge    // F001: a single 14-byte challenge notification
        case awaitingSessionInfo  // F001: a 7-byte and an 18-byte notification (total 25)
        case streaming            // F002: 20, 18 and 8-byte notifications per 46-byte record

        /// The notification lengths making up one message, in message order.
        var fragmentLengths: [Int] {
            switch self {
            case .awaitingNotify: return []
            case .awaitingChallenge: return [Libre2Gen2.challengeLength]
            case .awaitingSessionInfo: return [7, 18]
            case .streaming: return [20, 18, 8]
            }
        }
    }
    private var phase: Phase = .awaitingNotify

    // The fragments of the message being reassembled, keyed by length. Like
    // LibreLink, each fragment is placed by its length rather than by arrival
    // order, and a repeated length replaces the earlier fragment.
    private var fragments = [Int: Data]()

    // F002, saved at discovery; notifications on it are enabled only once the
    // session is open.
    private var notifyCharacteristic: CBCharacteristic?

    init(sensor: Sensor, delegate: LibreTransmitterDelegate?) {
        self.delegate = delegate
        self.uuid = sensor.uuid
        self.keyIndex = sensor.keyIndex
        self.streamingAuthData = sensor.streamingAuthData
        self.handler = Libre2Gen2DirectHandler(sensor: sensor, keyStore: Libre2Gen2RootKeyStore())
        if handler == nil {
            logger.debug("gen2 sensor paired but handler unavailable (missing NFC credentials or keys)")
        }
    }

    /// Whether this connection was built for this sensor and its current credentials.
    func isFor(_ sensor: Sensor) -> Bool {
        sensor.uuid == uuid && sensor.keyIndex == keyIndex && sensor.streamingAuthData == streamingAuthData
    }

    /// Drop a partial message. The phase is kept: a missed fragment mid-stream
    /// must not rewind the handshake.
    func reset() {
        fragments.removeAll()
    }

    func didDiscoverNotificationCharacteristic(_ characteristic: CBCharacteristic) {
        // Enabled once the session is open (receive), as LibreLink does
        logger.debug("gen2: saving notifyCharacteristic")
        notifyCharacteristic = characteristic
    }

    func didDiscoverWriteCharacteristic(_ peripheral: CBPeripheral, _ characteristic: CBCharacteristic) {
        // LibreLink counts a connection lost while waiting for session info
        // as an authentication failure, not a dropout: the sensor did not
        // accept our command, e.g. a wrong root slot or streamingAuthData
        if case .awaitingSessionInfo = phase {
            logger.error("gen2: authentication failed, the previous connection was lost while waiting for session info")
            delegate?.libreDeviceLogMessage(payload: "gen2 authentication failed: connection lost while waiting for session info (wrong root slot or streamingAuthData?)", type: .receive)
        }

        // A new connection always starts a new session: drop the previous
        // connection's partial message and session key. The handshake rides
        // on notifications from the write characteristic (F001); as LibreLink
        // does, enable those first and write the kickoff once that has
        // completed (didUpdateNotificationState).
        phase = .awaitingNotify
        reset()
        handler?.reset()
        logger.debug("gen2: enabling notify on write characteristic")
        peripheral.setNotifyValue(true, for: characteristic)
    }

    func didUpdateNotificationState(_ peripheral: CBPeripheral, characteristic: CBCharacteristic) {
        guard case .awaitingNotify = phase,
              characteristic.uuid == Libre2DirectTransmitter.writeCharacteristic?.value else {
            return
        }
        // Notifications on F001 are on: kick off the exchange by writing the
        // "read security challenge" opcode (0x20). The sensor answers with its
        // 14-byte challenge on F001.
        phase = .awaitingChallenge
        let kickoff = Data([Libre2Gen2.cmdReadChallenge])
        logger.debug("gen2: writing read-security-challenge kickoff: \(kickoff.hexEncodedString())")
        delegate?.libreDeviceLogMessage(payload: "gen2 kickoff (read security challenge): \(kickoff.hexEncodedString())", type: .send)
        peripheral.writeValue(kickoff, for: characteristic, type: .withResponse)
    }

    /// Takes one notification and returns a decrypted, CRC-checked 44-byte
    /// payload when it completes a glucose record.
    ///
    /// The source characteristic is not available here (the BLE router
    /// forwards only the value), so reassembly is keyed on the phase. Since
    /// F002 is only enabled once the handshake is done, the handshake never
    /// sees record fragments. A fragment of a length the phase does not expect
    /// is dropped. A missing fragment is covered by the shared inter-
    /// notification timeout in LibreTransmitterProxyManager, which calls
    /// reset() to drop the partial message without rewinding the phase.
    func receive(_ value: Data, peripheral: CBPeripheral, writeCharacteristic: CBCharacteristic?) -> Data? {
        delegate?.libreDeviceLogMessage(payload: "gen2 received value: \(value.toDebugString())", type: .receive)

        let lengths = phase.fragmentLengths
        guard lengths.contains(value.count) else {
            logger.debug("gen2: ignoring \(value.count)-byte notification in phase \(String(describing: self.phase))")
            return nil
        }
        fragments[value.count] = value

        guard lengths.allSatisfy({ fragments[$0] != nil }) else {
            // Still waiting for the remaining fragment(s) of this message.
            logger.debug("gen2: reassembling in phase \(String(describing: self.phase)): have \(self.fragments.keys.sorted()) of \(lengths)")
            return nil
        }

        let message = lengths.flatMap { [UInt8](fragments[$0]!) }
        fragments.removeAll()

        guard let handler else { return nil }
        switch handler.ingest(message) {
        case .write(let bytes):
            guard let writeCharacteristic else {
                logger.debug("gen2: no write characteristic to send command")
                return nil
            }
            // Challenge answered; the sensor now replies with session info on
            // F001 as a 7-byte then an 18-byte notification.
            phase = .awaitingSessionInfo
            delegate?.libreDeviceLogMessage(payload: "gen2 writing command: \(Data(bytes).hexEncodedString())", type: .send)
            peripheral.writeValue(Data(bytes), for: writeCharacteristic, type: .withResponse)

        case .payload(let payload):
            return Data(payload)

        case .none:
            // Session info has opened the session: now enable notifications on
            // F002, where the glucose records arrive. (`.none` is also the no-op
            // for a message that did not open it, which must leave the phase alone.)
            if case .awaitingSessionInfo = phase, handler.isOpen {
                phase = .streaming
                guard let notifyCharacteristic else {
                    logger.error("gen2: session open but no notify characteristic to enable")
                    return nil
                }
                logger.debug("gen2: session open, enabling notify on notify characteristic")
                peripheral.setNotifyValue(true, for: notifyCharacteristic)
            }

        case .failure:
            delegate?.libreSensorDidUpdate(with: .checksumValidationError)
            reset()
        }
        return nil
    }
}
