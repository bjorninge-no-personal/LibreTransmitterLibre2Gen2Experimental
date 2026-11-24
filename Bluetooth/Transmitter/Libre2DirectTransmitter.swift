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
        let handler = Libre2Gen2DirectHandler(sensor: sensor, keyStore: Libre2Gen2RuntimeKeyStore.shared)
        if handler == nil {
            self.logger.debug("gen2 sensor paired but handler unavailable (missing NFC credentials or keys)")
        }
        return handler
    }()

    // Where we are in the gen2 BLE exchange. Reassembly (updateValueForGen2) is
    // keyed on this phase rather than on raw notification length, because the
    // individual notification fragments collide across phases: an 18-byte
    // fragment is both the second half of session info (7 + 18) and the middle
    // of a glucose record (20 + 18 + 8). The handshake drives the phase
    // deterministically: kickoff -> challenge -> command -> session info ->
    // stream. See updateValueForGen2 for the reverse-engineered framing.
    private enum Gen2Phase {
        case awaitingChallenge    // F001: a single 14-byte challenge notification
        case awaitingSessionInfo  // F001: a 7-byte then an 18-byte notification (total 25)
        case streaming            // F002: 20 + 18 + 8 notifications per 46-byte record
    }
    private var gen2Phase: Gen2Phase = .awaitingChallenge

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
            // unlock. Per DiaBLE's and Juggluco's Abbott gen2 BLE path, the
            // exchange is kicked off by writing the "read security challenge"
            // opcode (0x20); the sensor then notifies its 14-byte challenge on the
            // *write* characteristic (F001), which updateValueForGen2 answers with
            // the session-info command. Glucose packets later arrive on the notify
            // characteristic (F002).
            //
            // Both DiaBLE and Juggluco enable notifications on the write
            // characteristic for gen2 (the handshake rides on it), so do that here
            // before the kickoff. CoreBluetooth serialises GATT operations per
            // peripheral, so the CCCD (enable-notify) write completes before the
            // kickoff write is delivered. (Cross-referenced against both projects;
            // exact on-wire timing still warrants verification on a real sensor.)
            peripheral.setNotifyValue(true, for: writeCharacteristics)
            // Fresh connection: restart reassembly at the top of the handshake.
            // (reset() is left phase-agnostic so the shared inter-notification
            // timeout can drop a partial buffer mid-stream without rewinding the
            // handshake; the phase is only rewound here, on a new kickoff.)
            gen2Phase = .awaitingChallenge
            rxBuffer.resetAllBytes()
            let kickoff = Data([Libre2Gen2.cmdReadChallenge])
            logger.debug("gen2: enabled notify on write characteristic; writing read-security-challenge kickoff: \(kickoff.hexEncodedString())")
            delegate?.libreDeviceLogMessage(payload: "gen2 kickoff (read security challenge): \(kickoff.hexEncodedString())", type: .send)
            peripheral.writeValue(kickoff, for: writeCharacteristics, type: .withResponse)
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

        logger.debug("libre2: saving notifyCharacteristic")
        // peripheral.setNotifyValue(true, for: notifyCharacteristic)
        logger.debug("libre2 setting notify while discovering : \(String(describing: notifyCharacteristic.debugDescription))")
        peripheral.setNotifyValue(true, for: notifyCharacteristic)
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
    /// Framing reverse-engineered from the official Abbott app (treated as
    /// ground truth; the exact per-chunk boundaries still want confirmation on
    /// a real sensor — see the note below):
    ///
    ///   - Handshake on F001 (login characteristic):
    ///       * challenge   — ONE 14-byte notification.
    ///       * session info — TWO notifications, a 7-byte chunk THEN an 18-byte
    ///         chunk, reassembled in order  7 || 18 = 25.
    ///   - Stream on F002 (raw glucose characteristic):
    ///       * each 46-byte record — THREE notifications, 20 THEN 18 THEN 8,
    ///         reassembled in order  20 || 18 || 8 = 46.
    ///
    /// Why reassembly is keyed on the exchange phase and not on which
    /// characteristic a notification arrived on: the source characteristic is
    /// not available here. The BLE router
    /// (LibreTransmitterProxyManager.didUpdateValueFor) forwards only the
    /// write-target handle — always F001 — not the characteristic the
    /// notification actually came from, so F001-vs-F002 cannot be recovered at
    /// this point without plumbing a new argument through the plugin protocol.
    /// Instead we key on `gen2Phase`, which the handshake advances
    /// deterministically. That also disambiguates fragments whose raw lengths
    /// collide across phases (an 18-byte fragment is session info's 2nd chunk
    /// while awaiting session info, but a record's middle chunk while
    /// streaming).
    ///
    /// A missing fragment is covered by the shared ~10s inter-notification
    /// timeout in LibreTransmitterProxyManager, which calls reset() to drop the
    /// partial buffer. reset() is intentionally phase-agnostic, so a drop
    /// mid-stream clears the partial record without rewinding the completed
    /// handshake; the next record then reassembles cleanly in the same phase.
    ///
    /// GEN2-TRANSPORT-NOTE (needs a real-sensor capture): the message *totals*
    /// (14 / 25 / 46) are RE'd ground truth, but the exact chunk split within a
    /// message (7+18, and 20+18+8) is not yet device-confirmed. Reassembly is
    /// therefore tolerant of the split — fragments arrive in order and are
    /// appended, and a message is emitted once its phase's total is reached —
    /// but the observed fragmentation is logged so a capture can confirm the
    /// boundaries.
    private func updateValueForGen2(_ value: Data, peripheral: CBPeripheral, writeCharacteristic: CBCharacteristic?) {
        rxBuffer.append(value)
        delegate?.libreDeviceLogMessage(payload: "gen2 received value: \(value.toDebugString())", type: .receive)

        // Expected total length of the message currently being reassembled,
        // selected by phase (14 challenge / 25 session info / 46 record).
        let expectedLength: Int
        switch gen2Phase {
        case .awaitingChallenge:   expectedLength = Libre2Gen2.challengeLength   // 14, single notification
        case .awaitingSessionInfo: expectedLength = Libre2Gen2.sessionInfoLength // 25, as 7 || 18
        case .streaming:           expectedLength = Libre2Gen2.packetLength      // 46, as 20 || 18 || 8
        }

        if rxBuffer.count > expectedLength {
            // Overshoot: a dropped or duplicated fragment has desynced the
            // buffer. Drop the partial and wait for the next clean sequence;
            // the phase is retained (a mid-stream glitch must not rewind the
            // handshake).
            logger.debug("gen2: reassembly overshoot in phase \(String(describing: self.gen2Phase)) (\(self.rxBuffer.count) > \(expectedLength)); dropping partial buffer")
            rxBuffer.resetAllBytes()
            return
        }

        guard rxBuffer.count == expectedLength else {
            // Still waiting for the remaining fragment(s) of this message.
            logger.debug("gen2: reassembling in phase \(String(describing: self.gen2Phase)): \(self.rxBuffer.count)/\(expectedLength) bytes")
            return
        }

        let message = [UInt8](rxBuffer)
        rxBuffer.resetAllBytes()

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
            // Session info has opened the session: glucose records now stream on
            // F002 as 20 + 18 + 8. (`.none` is also the no-op for a record seen
            // before the handshake completed, which must leave the phase alone.)
            if case .awaitingSessionInfo = gen2Phase {
                gen2Phase = .streaming
            }

        case .failure:
            delegate?.libreSensorDidUpdate(with: .checksumValidationError)
            reset()
        }
    }

}
