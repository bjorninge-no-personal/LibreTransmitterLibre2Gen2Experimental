//
//  Libre2Gen2Credentials.swift
//  LibreTransmitter
//
//  The REAL Libre 2 "generation 2" root key tables, transcribed verbatim from
//  Juggluco's `protocol.c` (the authoritative open-source reference). These are
//  compiled-in constants: they are NOT account-tied and NOT secret to a user —
//  the sensor holds the same roots. A "root slot" (1 or 2) selects a pair of
//  roots; the actual per-sensor keys are DERIVED from them with the Speck-CMAC
//  SP 800-108 KDF in `Libre2Gen2.swift`.
//
//    sensor key  = derive_key(sensor_roots[slot-1],  sensorLabel,  UID[0..<uidSize-2])
//    session key = derive_key(session_roots[slot-1], sessionLabel, sessionContext16)
//
//  The default slot is 1. In this codebase the slot is carried as the
//  `Libre2Gen2Credential.index`, matching the `credential(forIndex:)` contract
//  of `Libre2Gen2KeyStore` (the BLE handler passes the NFC-read key index as
//  the slot).
//

import Foundation

extension Libre2Gen2 {

    /// `sensor_roots` from Juggluco protocol.c — selected by `root_slot - 1`.
    static let sensorRoots: [[UInt8]] = [
        // sensor_roots[0]
        [0xa1, 0xaa, 0x73, 0x8f, 0x0c, 0xf7, 0x58, 0x01,
         0xa1, 0x6d, 0xd4, 0xf7, 0x90, 0x6e, 0x97, 0x2a],
        // sensor_roots[1]
        [0x3c, 0xe8, 0xbd, 0xbb, 0x8c, 0xb3, 0x0a, 0x48,
         0xa7, 0xd6, 0x93, 0xf7, 0xb7, 0x2e, 0xec, 0x6c],
    ]

    /// `session_roots` from Juggluco protocol.c — selected by `root_slot - 1`.
    static let sessionRoots: [[UInt8]] = [
        // session_roots[0]
        [0xe8, 0x2f, 0x8f, 0xc3, 0x21, 0x99, 0x56, 0x3c,
         0xfd, 0xa8, 0x0c, 0x7f, 0x6c, 0x2a, 0x67, 0x21],
        // session_roots[1]
        [0x4e, 0x28, 0x73, 0xbd, 0x16, 0xc5, 0x4a, 0xdc,
         0xe0, 0x38, 0xea, 0xd5, 0xb2, 0x5b, 0x68, 0xa3],
    ]

    /// Juggluco's default `root_slot`.
    static let defaultRootSlot = 1

    /// The credential for a given root slot (1 or 2), or `nil` if out of range.
    static func credential(rootSlot: Int) -> Libre2Gen2Credential? {
        let i = rootSlot - 1
        guard sensorRoots.indices.contains(i), sessionRoots.indices.contains(i) else {
            return nil
        }
        return Libre2Gen2Credential(index: rootSlot,
                                    authKey: sensorRoots[i],
                                    sessionGeneratorKey: sessionRoots[i])
    }
}

/// The authoritative keystore backed by the compiled-in Juggluco root tables.
/// `index` is the root slot (1 or 2). An out-of-range slot fails closed.
struct Libre2Gen2RootKeyStore: Libre2Gen2KeyStore {
    /// The slot used when a caller has no NFC-read index to offer.
    let defaultRootSlot: Int

    init(defaultRootSlot: Int = Libre2Gen2.defaultRootSlot) {
        self.defaultRootSlot = defaultRootSlot
    }

    func credential(forIndex index: Int) -> Libre2Gen2Credential? {
        Libre2Gen2.credential(rootSlot: index)
    }

    /// Convenience: the credential for the configured default slot.
    func defaultCredential() -> Libre2Gen2Credential? {
        Libre2Gen2.credential(rootSlot: defaultRootSlot)
    }
}
