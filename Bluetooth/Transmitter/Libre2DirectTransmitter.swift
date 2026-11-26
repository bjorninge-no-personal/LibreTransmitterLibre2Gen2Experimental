//
//  Libre2DirectTransmitter.swift

import CoreBluetooth
import Foundation
import os.log
import UIKit

class Libre2DirectTransmitter: LibreTransmitterProxyProtocol {

    fileprivate lazy var logger = Logger(forType: Self.self)

    func reset() {
        rxBuffer.resetAllBytes()
        gen2Fragments.removeAll()
    }

    class var manufacturerer: String {
        "Abbott"
    }

    class var smallImage: UIImage? {
        UIImage(named: "libresensor", in: Bundle.current, compatibleWith: nil)
    }

    class var shortTransmitterName: String {
        "libre2"
    }

    class var requiresDelayedReconnect: Bool {
        false
    }

    private let expectedBufferSize = 46
    static var requiresSetup = true
    static var requiresPhoneNFC: Bool = true

    static var writeCharacteristic: UUIDContainer? = "F001"// 0000f001-0000-1000-8000-00805f9b34fb"
    static var notifyCharacteristic: UUIDContainer? = "F002"// "0000f002-0000-1000-8000-00805f9b34fb"
    // static var serviceUUID: [UUIDContainer] = ["0000fde3-0000-1000-8000-00805f9b34fb"]
    static var serviceUUID: [UUIDContainer] = ["FDE3"]

    weak var delegate: LibreTransmitterDelegate?

    private var rxBuffer = Data()
    private var lastValueReceived: Date?
    private var sensorData: SensorData?
    private var metadata: LibreTransmitterMetadata?

    // MARK: Gen2 routing
    //
    // Gen2 sensors share this class (same service/characteristics/name). When
    // the paired sensor is gen2-ready, messages are driven through a session
    // handler instead of the stateless gen1 unlock-then-decrypt path.
    //
    // Routing follows what the sensor is, not whether the handler could be
    // built: a gen2 sensor without credentials or keys must never fall back to
    // the gen1 unlock, it simply cannot stream.
    private lazy var isGen2: Bool = UserDefaults.standard.preSelectedSensor?.securityGeneration == 2

    private lazy var gen2Handler: Libre2Gen2DirectHandler? = {
        guard self.isGen2, let sensor = UserDefaults.standard.preSelectedSensor else {
            return nil
        }
        let handler = Libre2Gen2DirectHandler(sensor: sensor, keyStore: Libre2Gen2RootKeyStore())
        if handler == nil {
            self.logger.debug("gen2 sensor paired but handler unavailable (missing NFC credentials or keys)")
        }
        return handler
    }()

    // Where we are in the gen2 BLE exchange, following LibreLink's BLE callback
    // class: notifications are enabled on F001 only; once that completes, the
    // kickoff is written; the challenge and session info arrive on F001; only
    // once the session is open are notifications enabled on F002, which
    // carries the glucose records. Reassembly (updateValueForGen2) is keyed on
    // this phase, because notification lengths collide across phases: 18
    // bytes is both the second part of session info and the middle of a record.
    private enum Gen2Phase {
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
    private var gen2Phase: Gen2Phase = .awaitingNotify

    // The fragments of the message being reassembled, keyed by length. Like
    // LibreLink, each fragment is placed by its length rather than by arrival
    // order, and a repeated length replaces the earlier fragment.
    private var gen2Fragments = [Int: Data]()

    // F002, saved at discovery; notifications on it are enabled only once the
    // session is open.
    private var gen2NotifyCharacteristic: CBCharacteristic?

    class func canSupportPeripheral(_ peripheral: PeripheralProtocol) -> Bool {
        // name can be one of the following formats:
        // <description>: example
        //ABBOT<SerialNumber>: ABBOTT3MH015PCNC4
        // <MACADDRESS>: A4B7C9023F8D
        
        guard let name = peripheral.name else {
            return false
        }
        
        if name.lowercased().starts(with: "abbott") == true {
            print("Libre 2 detected using legacy name format as matcher")
            return true
        }
        
        print("Libre 2 detection using MAC address as matcher: \(String(describing: UserDefaults.standard.preSelectedSensor?.macAddress?.lowercased())) vs \(name.lowercased())")
        if let sensor = UserDefaults.standard.preSelectedSensor, let macAddress = sensor.macAddress {
            return name.lowercased().contains(macAddress.lowercased())
        }
        
        
        return false
    }

    class func getDeviceDetailsFromAdvertisement(advertisementData: [String: Any]?) -> String? {
        nil
    }

    required init(delegate: LibreTransmitterDelegate, advertisementData: [String: Any]?) {
        // advertisementData is unknown for the miaomiao
        self.delegate = delegate
    }

    func requestData(writeCharacteristics: CBCharacteristic, peripheral: CBPeripheral) {
        // because of timing issues, we cannot use this method on libre2 eu sensors
    }

    func updateValueForNotifyCharacteristics(_ value: Data, peripheral: CBPeripheral, writeCharacteristic: CBCharacteristic?) {
        if isGen2 {
            updateValueForGen2(value, peripheral: peripheral, writeCharacteristic: writeCharacteristic)
            return
        }

        // A packet arrives as 20 + 20 + 6 bytes within milliseconds, and packets come a
        // minute apart. Bytes still here from seconds ago are an incomplete packet: left
        // in the buffer, they would misalign every later packet.
        if !rxBuffer.isEmpty, let lastValueReceived, Date().timeIntervalSince(lastValueReceived) > 5 {
            logger.debug("libre2 direct dropping \(self.rxBuffer.count) bytes of an incomplete packet")
            reset()
        }
        lastValueReceived = Date()
        rxBuffer.append(value)

        logger.debug("libre2 direct Appended value with length  \(String(describing: value.count)), buffer length is: \(String(describing: self.rxBuffer.count))")

        delegate?.libreDeviceLogMessage(payload: "libre2direct received value: \(value.toDebugString())", type: .receive)

        if rxBuffer.count == expectedBufferSize {
            handleCompleteMessage()
        }

    }

    func didDiscoverWriteCharacteristics(_ peripheral: CBPeripheral, writeCharacteristics: CBCharacteristic) {

        if isGen2 {
            // Gen2 uses a challenge/response handshake, not the gen1 streaming
            // unlock, and it rides on notifications from the write
            // characteristic (F001). As LibreLink does, enable those first; the
            // kickoff is written once that has completed
            // (didUpdateNotificationState).
            //
            // A new connection always starts a new session: drop the previous
            // connection's partial message and session key.
            gen2Phase = .awaitingNotify
            reset()
            gen2Handler?.reset()
            logger.debug("gen2: enabling notify on write characteristic")
            peripheral.setNotifyValue(true, for: writeCharacteristics)
            return
        }

        guard let unlock = unlock() else {
            logger.debug("Cannot unlock sensor, aborting")
            return
        }

        logger.debug("Writing streaming unlock code to peripheral: \(unlock.hexEncodedString())")
        
        delegate?.libreDeviceLogMessage(payload: "Writing streaming unlock code to peripheral: \(unlock.hexEncodedString())", type: .send)
        peripheral.writeValue(unlock, for: writeCharacteristics, type: .withResponse)

    }

    func didDiscoverNotificationCharacteristic(_ peripheral: CBPeripheral, notifyCharacteristic: CBCharacteristic) {

        if isGen2 {
            // Enabled once the session is open (updateValueForGen2), as LibreLink does
            logger.debug("gen2: saving notifyCharacteristic")
            gen2NotifyCharacteristic = notifyCharacteristic
            return
        }

        logger.debug("libre2: saving notifyCharacteristic")
        // peripheral.setNotifyValue(true, for: notifyCharacteristic)
        logger.debug("libre2 setting notify while discovering : \(String(describing: notifyCharacteristic.debugDescription))")
        peripheral.setNotifyValue(true, for: notifyCharacteristic)
    }

    func didUpdateNotificationState(_ peripheral: CBPeripheral, characteristic: CBCharacteristic) {
        guard isGen2, case .awaitingNotify = gen2Phase,
              characteristic.uuid == Self.writeCharacteristic?.value else {
            return
        }
        // Notifications on F001 are on: kick off the exchange by writing the
        // "read security challenge" opcode (0x20). The sensor answers with its
        // 14-byte challenge on F001.
        gen2Phase = .awaitingChallenge
        let kickoff = Data([Libre2Gen2.cmdReadChallenge])
        logger.debug("gen2: writing read-security-challenge kickoff: \(kickoff.hexEncodedString())")
        delegate?.libreDeviceLogMessage(payload: "gen2 kickoff (read security challenge): \(kickoff.hexEncodedString())", type: .send)
        peripheral.writeValue(kickoff, for: characteristic, type: .withResponse)
    }

    private func unlock() -> Data? {

        guard var sensor = UserDefaults.standard.preSelectedSensor else {
            logger.debug("impossible to unlock sensor")
            return nil
        }

        sensor.unlockCount +=  1

        UserDefaults.standard.preSelectedSensor = sensor

        let unlockPayload = Libre2.streamingUnlockPayload(sensorUID: sensor.uuid, info: sensor.patchInfo, enableTime: 42, unlockCount: UInt16(sensor.unlockCount))
        return Data(unlockPayload)

    }

    // previously captured trend values, limit to the last 20-ish minutes
    // we have some leniency here by having up to 30 data elements
    private var bufferedTrends =  LimitedQueue<Measurement>(limit: 30)
    private var lastSensorUUID : [UInt8]?
    func handleCompleteMessage() {
        guard rxBuffer.count >= expectedBufferSize else {
            logger.debug("libre2 handle complete message with incorrect buffersize")
            reset()
            return
        }

        guard let sensor = UserDefaults.standard.preSelectedSensor else {
            logger.debug("libre2 handle complete message without sensorinfo present")
            reset()
            return
        }

        do {
            let decryptedBLE = Data(try Libre2.decryptBLE(id: [UInt8](sensor.uuid), data: [UInt8](rxBuffer)))
            emit(decryptedBLE: decryptedBLE, sensor: sensor)
        } catch {

        }

        reset()

    }

    /// Shared tail for both generations: parse a 44-byte decrypted BLE payload,
    /// verify its CRC, build metadata, merge buffered trends, and notify the
    /// delegate. Gen1 reaches here after `Libre2.decryptBLE`; gen2 after the
    /// session handler has already decrypted and CRC-checked the packet.
    private func emit(decryptedBLE: Data, sensor: Sensor) {
            var sensorUpdate = Libre2.parseBLEData(decryptedBLE)


            guard sensorUpdate.crcVerified else {
                delegate?.libreSensorDidUpdate(with: .checksumValidationError)
                return
            }


            metadata = LibreTransmitterMetadata(hardware: nil, firmware: nil, battery: 100,
                                                name: Self.shortTransmitterName,
                                                macAddress: sensor.macAddress,
                                                patchInfo: sensor.patchInfo,
                                                uid: [UInt8](sensor.uuid))

            // When end user has changed sensor we cannot trust the current(new) calibrationdata
            // to apply for both old and new sensor.
            // Since we don't support multiple sets of calibration datas we chooce to remove
            // all buffered calibration data
            if let currentSensorUUID = metadata?.uid {
                if let lastSensorUUID,
                    lastSensorUUID != currentSensorUUID {
                    bufferedTrends.removeAll()

                }
                lastSensorUUID = currentSensorUUID
            }

            // todo: reset when sensor changes, but we currently don't need this
            // due to requirement of deleting cgmmanager when changing sensors
            if let latestGlucose = sensorUpdate.trend.last,
               let oldestGlucose = sensorUpdate.trend.first {
                // ensures captured trends are recent enough
                // but also older than the trends sent by sensor this time around
                let latestGlucoseDate = latestGlucose.date - TimeInterval(minutes: 20)
                let oldestGlucoseDate = oldestGlucose.date

                let filtered = bufferedTrends.array.filter {
                    $0.date > latestGlucoseDate &&
                    $0.date < oldestGlucoseDate
                }.removingDuplicates(byKey: { $0.idValue})

                // Could refactor this to be more performant, but decided not to
                // This is more explicit and easier to grasp than doing above and below
                // in one operation
                for trend in sensorUpdate.trend {
                    if !bufferedTrends.array.contains(where: { $0.date > trend.date}) {
                        bufferedTrends.enqueue(trend)
                    }

                }

                logger.debug("sensor updated with trends: \((sensorUpdate.trend.count)): \(sensorUpdate.trend)")

                if !filtered.isEmpty {
                    logger.debug("Adding previously captured trends \((filtered.count)): \(filtered)")
                    sensorUpdate.trend += filtered
                }
            }

            delegate?.libreSensorDidUpdate(with: sensorUpdate, and: metadata!)

            print("libre2 got sensorupdate: \(String(describing: sensorUpdate))")
    }

    // MARK: - Gen2 message handling

    /// Reassembles gen2 BLE notifications into whole messages and drives the
    /// handshake/stream state machine.
    ///
    /// Framing as in LibreLink's BLE callback class:
    ///
    ///   - Handshake on F001 (login characteristic):
    ///       * challenge    — ONE 14-byte notification.
    ///       * session info — a 7-byte and an 18-byte notification, at 0 and 7.
    ///   - Stream on F002 (raw glucose characteristic), enabled only once the
    ///     session is open:
    ///       * each 46-byte record — a 20, an 18 and an 8-byte notification,
    ///         at 0, 20 and 38.
    ///
    /// The source characteristic is not available here (the BLE router
    /// forwards only the value), so reassembly is keyed on `gen2Phase`. Since
    /// F002 is only enabled once the handshake is done, the handshake never
    /// sees record fragments. A fragment of a length the phase does not expect
    /// is dropped. A missing fragment is covered by the shared inter-
    /// notification timeout in LibreTransmitterProxyManager, which calls
    /// reset() to drop the partial message without rewinding the phase.
    ///
    /// GEN2-TRANSPORT-NOTE: this is LibreLink's sequence, not yet seen on a
    /// real gen2 sensor here; the fragments are logged so a capture can
    /// confirm it.
    private func updateValueForGen2(_ value: Data, peripheral: CBPeripheral, writeCharacteristic: CBCharacteristic?) {
        delegate?.libreDeviceLogMessage(payload: "gen2 received value: \(value.toDebugString())", type: .receive)

        let lengths = gen2Phase.fragmentLengths
        guard lengths.contains(value.count) else {
            logger.debug("gen2: ignoring \(value.count)-byte notification in phase \(String(describing: self.gen2Phase))")
            return
        }
        gen2Fragments[value.count] = value

        guard lengths.allSatisfy({ gen2Fragments[$0] != nil }) else {
            // Still waiting for the remaining fragment(s) of this message.
            logger.debug("gen2: reassembling in phase \(String(describing: self.gen2Phase)): have \(self.gen2Fragments.keys.sorted()) of \(lengths)")
            return
        }

        let message = lengths.flatMap { [UInt8](gen2Fragments[$0]!) }
        gen2Fragments.removeAll()

        guard let handler = gen2Handler else { return }
        switch handler.ingest(message) {
        case .write(let bytes):
            guard let writeCharacteristic else {
                logger.debug("gen2: no write characteristic to send command")
                return
            }
            // Challenge answered; the sensor now replies with session info on
            // F001 as a 7-byte then an 18-byte notification.
            gen2Phase = .awaitingSessionInfo
            delegate?.libreDeviceLogMessage(payload: "gen2 writing command: \(Data(bytes).hexEncodedString())", type: .send)
            peripheral.writeValue(Data(bytes), for: writeCharacteristic, type: .withResponse)

        case .payload(let payload):
            guard let sensor = UserDefaults.standard.preSelectedSensor else { return }
            emit(decryptedBLE: Data(payload), sensor: sensor)

        case .none:
            // Session info has opened the session: now enable notifications on
            // F002, where the glucose records arrive. (`.none` is also the no-op
            // for a message that did not open it, which must leave the phase alone.)
            if case .awaitingSessionInfo = gen2Phase, handler.isOpen {
                gen2Phase = .streaming
                guard let gen2NotifyCharacteristic else {
                    logger.error("gen2: session open but no notify characteristic to enable")
                    return
                }
                logger.debug("gen2: session open, enabling notify on notify characteristic")
                peripheral.setNotifyValue(true, for: gen2NotifyCharacteristic)
            }

        case .failure:
            delegate?.libreSensorDidUpdate(with: .checksumValidationError)
            reset()
        }
    }

}
