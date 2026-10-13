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
            // unlock. Per DiaBLE's Abbott gen2 BLE path, the exchange is kicked
            // off by writing the "read security challenge" opcode (0x20); the
            // sensor then notifies its 14-byte challenge, which updateValueForGen2
            // answers with the session-info command.
            //
            // GEN2-TRANSPORT-TODO: DiaBLE also enables notifications on the
            // *write* characteristic for gen2, not only the notify one. Confirm
            // on a real sensor which characteristic carries the challenge;
            // LibreTransmitter currently notifies on the notify characteristic.
            let kickoff = Data([Libre2Gen2.cmdReadChallenge])
            logger.debug("gen2: writing read-security-challenge kickoff: \(kickoff.hexEncodedString())")
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

    /// GEN2-TRANSPORT-TODO: reassembly is by accumulating notifications until a
    /// recognised complete length is reached (14 challenge / 25 session info /
    /// 46 reading). This is a placeholder for the real on-wire framing, which
    /// must be confirmed against a sensor; a length-collision or a partial read
    /// would desync this buffer.
    private func updateValueForGen2(_ value: Data, peripheral: CBPeripheral, writeCharacteristic: CBCharacteristic?) {
        rxBuffer.append(value)
        delegate?.libreDeviceLogMessage(payload: "gen2 received value: \(value.toDebugString())", type: .receive)

        let recognised: Set<Int> = [Libre2Gen2.challengeLength,
                                    Libre2Gen2.sessionInfoLength,
                                    Libre2Gen2.packetLength]
        guard recognised.contains(rxBuffer.count) else {
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
            delegate?.libreDeviceLogMessage(payload: "gen2 writing command: \(Data(bytes).hexEncodedString())", type: .send)
            peripheral.writeValue(Data(bytes), for: writeCharacteristic, type: .withResponse)

        case .payload(let payload):
            guard let sensor = UserDefaults.standard.preSelectedSensor else { return }
            emit(decryptedBLE: Data(payload), sensor: sensor)

        case .none:
            break

        case .failure:
            delegate?.libreSensorDidUpdate(with: .checksumValidationError)
            reset()
        }
    }

}
