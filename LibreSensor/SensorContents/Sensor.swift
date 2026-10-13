public extension UserDefaults {
    private enum Key: String {
        case sensor = "com.loopkit.libre2sensor"
        case calibrationMapping = "com.loopkit.libre2sensor-calibrationmapping"
        case currentSensorUid = "com.loopkit.libre2sensor-currentSensorUid"

    }
    
    var currentSensor: String? {
        get {
            string(forKey: Key.currentSensorUid.rawValue)
        }
        
        set {
            if let newValue {
                set(newValue, forKey: Key.currentSensorUid.rawValue)
            }
            else {
                removeObject(forKey: Key.currentSensorUid.rawValue)
            }
        }
    }

    var preSelectedSensor: Sensor? {
        get {

            if let sensor = object(forKey: Key.sensor.rawValue) as? Data {
                let decoder = JSONDecoder()
                return try? decoder.decode(Sensor.self, from: sensor)
            }

            return nil

        }
        set {
            if let newValue {
                let encoder = JSONEncoder()
                if let encoded = try? encoder.encode(newValue) {
                    set(encoded, forKey: Key.sensor.rawValue)
                }
            } else {
                removeObject(forKey: Key.sensor.rawValue)
            }
        }
    }

    var calibrationMapping: CalibrationToSensorMapping? {
        get {
            if let sensor = object(forKey: Key.calibrationMapping.rawValue) as? Data {
                let decoder = JSONDecoder()
                return try? decoder.decode(CalibrationToSensorMapping.self, from: sensor)
            }

            return nil

        }
        set {
            if let newValue {
                let encoder = JSONEncoder()
                if let encoded = try? encoder.encode(newValue) {
                    set(encoded, forKey: Key.calibrationMapping.rawValue)
                }
            } else {
                removeObject(forKey: Key.calibrationMapping.rawValue)
            }
        }
    }
}

public struct CalibrationToSensorMapping: Codable {
    public let uuid: Data
    public let reverseFooterCRC: Int

    public init(uuid: Data, reverseFooterCRC: Int) {
        self.uuid = uuid
        self.reverseFooterCRC = reverseFooterCRC
    }
}

public struct Sensor: Codable {
    public let uuid: Data
    public let patchInfo: Data

    public var age: Int?
    public var maxAge: Int

    public var unlockCount: Int
    
    var sensorName : String?
    var macAddress : String?

    // Libre 2 "generation 2" credentials, captured once over NFC. Both are
    // absent for generation 1 sensors (and for records paired before gen2
    // support existed, which is why they are optional: synthesized Codable
    // decodes a missing key as nil, keeping old stored sensors readable).
    //
    //   keyIndex            the row index, NFC 02 A1 07 22 (u16 LE)
    //   streamingAuthData   10 bytes, NFC 0x1e
    public var keyIndex: Int?
    public var streamingAuthData: Data?

    public init(uuid: Data, patchInfo: Data, maxAge: Int, unlockCount: Int = 0, sensorName: String? = nil, macAddress: String? = nil, keyIndex: Int? = nil, streamingAuthData: Data? = nil) {
        self.uuid = uuid
        self.patchInfo = patchInfo
        self.unlockCount = 0
        self.maxAge = maxAge
        // self.calibrationInfo = calibrationInfo
        self.sensorName = sensorName
        self.macAddress = macAddress
        self.keyIndex = keyIndex
        self.streamingAuthData = streamingAuthData
    }

    /// 2 for a gen2 sensor (product type 3, security >= 9), 1 or 0 otherwise.
    public var securityGeneration: Int {
        (try? Libre2Gen2.securityGeneration(patchInfo: [UInt8](patchInfo))) ?? 0
    }

    /// A gen2 sensor can only stream once both NFC-only credentials are known.
    public var isGen2Ready: Bool {
        securityGeneration == 2 && keyIndex != nil
            && streamingAuthData?.count == Libre2Gen2.streamingAuthLength
    }

    public var description: String {
        return [
            "uuid: (\(uuid.hex))",
            "patchInfo: (\(patchInfo.hex))"
            // "calibrationInfo: (\(calibrationInfo.description))",
            // "family: \(family.description)",
            // "type: \(type.description)",
            // "region: \(region.description)",
            // "serial: \(serial ?? "Unknown")",
            // "state: \(state.description)",
            // "lifetime: \(lifetime.inTime)",
        ].joined(separator: ", ")
    }
}

private enum Key: String, CaseIterable {
    case sensorUnlockCount = "libre-direct.settings.sensor.unlockCount"
}
