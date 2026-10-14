//
//  SensorPairingService+Gen2.swift
//  LibreTransmitter
//
//  NFC side of pairing a Libre 2 "generation 2" sensor. On top of the gen1
//  inputs, gen2 needs two credentials that only NFC can provide: the key index
//  and streamingAuthData. The cryptography lives in Libre2Gen2.swift.
//
//  Entry point: `pairGen2`, called from `tagReaderSession(_:didDetect:)` as
//  soon as patchInfo says generation 2, before the gen1 block read (gen2
//  sensors do not support the standard ISO 15693 read).
//
//  Order matters: everything read-only comes first, and enable-streaming (the
//  one command that changes sensor state, handing BLE to this app) is sent
//  last, only once FRAM and the key index are known good. Every failure is
//  closed: nothing is handed to setup unless all of it succeeded.
//
//  GEN2-NFC-TODO, from DiaBLE's removed gen2 code (8d5531a) and NFC notes:
//    - FRAM: gen2 reads it with `A1 21 <block> <count-1>`, replies preceded by
//      8 0xA5 filler bytes. DiaBLE also names a GEN2_CMD_DECRYPT_NFC_STREAM
//      operation, so this FRAM is probably encrypted; its decryption is not in
//      the reference. If so, the CRC check below rejects it.
//    - enable streaming: DiaBLE and Juggluco both build the gen2 0x1e request as
//      an *authenticated* NFC command and derive streamingAuthData from the
//      *verified* response. That authenticated request is still not in the
//      reference, so the gen1 request is sent instead (likely wrong). The reply
//      *length* is now handled: 10 bytes on older US2 sensors, 12 on newer ones
//      (the extra 2 bytes carry the key index; see pairGen2).
//

import Foundation
import CoreNFC
import os.log

extension SensorPairingService {

    /// CoreNFC returns custom-command responses without the leading ISO 15693
    /// response-flags byte; the reference parses a raw frame that has it. The
    /// reference's offset 2 is therefore 1 here. DiaBLE agrees: the same `A1 22`
    /// ("read attribute") reply is 6 bytes with the sensor state at byte 0.
    static let gen2KeyIndexOffset = 1

    static let gen2FRAMBlocks = 43
    static let gen2FRAMBlocksPerRequest = 3
    static let gen2FRAMFillerLength = 8

    func pairGen2(session: NFCTagReaderSession, tag: NFCISO15693Tag, sensorUID: Data, patchInfo: Data) {
        let logger = Logger(forType: Self.self)

        func fail(_ error: PairingError) {
            session.invalidate(errorMessage: error.localizedDescription)
            sendError(error)
        }

        guard sensorUID.count == Libre2Gen2.uidLength, patchInfo.count == 6 else {
            fail(.noSensorData)
            return
        }

        readGen2FRAM(tag: tag) { fram in
            guard let fram else {
                fail(.noSensorData)
                return
            }

            // Calibration comes from FRAM, and glucose is computed from it. Never
            // store calibration from bytes that are not self-consistent.
            guard let sensorData = SensorData(bytes: [UInt8](fram)), sensorData.hasValidCRCs else {
                logger.error("gen2: FRAM does not pass its CRCs (probably still encrypted); refusing to pair")
                fail(.decryptionError)
                return
            }

            self.readKeyIndex(tag: tag) { keyIndex in
                guard let keyIndex else {
                    fail(.gen2CredentialsUnavailable)
                    return
                }

                let request = self.enableStreamingRequest(patchInfo: patchInfo, sensorUID: sensorUID)
                tag.customCommand(requestFlags: .highDataRate,
                                  customCommandCode: request.code,
                                  customRequestParameters: request.parameters) { response, error in
                    if let error {
                        logger.error("gen2: enable streaming failed: \(error.localizedDescription)")
                        fail(.gen2CredentialsUnavailable)
                        return
                    }
                    logger.debug("gen2: 0x1e response (\(response.count) bytes): \(response.hexEncodedString())")

                    // The enable-streaming reply is the 10-byte auth blob, but
                    // newer gen2 sensors append a 2-byte little-endian key index
                    // (10 + 2 = 12 bytes). Cross-referenced with Juggluco's
                    // Gen2.lastenaable / authenticateStream: for the 12-byte form
                    // the key index is auth[10..11] and the crypto uses only the
                    // first 10 bytes; for the 10-byte (older US2) form the key
                    // index is the one read over NFC (A1 22). DiaBLE documents the
                    // same 10-vs-12 split.
                    let bytes = [UInt8](response)
                    let effectiveKeyIndex: Int
                    switch bytes.count {
                    case Libre2Gen2.streamingAuthLength:        // 10: older US2 sensor
                        effectiveKeyIndex = keyIndex
                    case Libre2Gen2.streamingAuthLength + 2:    // 12: newer sensor
                        effectiveKeyIndex = Int(bytes[10]) | (Int(bytes[11]) << 8)
                    default:
                        logger.error("gen2: unexpected enable-streaming reply length \(bytes.count)")
                        fail(.gen2CredentialsUnavailable)
                        return
                    }
                    let streamingAuthData = Data(bytes.prefix(Libre2Gen2.streamingAuthLength))

                    // gen1 takes the MAC address from the 0x1e response; for gen2
                    // that response is the auth blob, so the MAC is unknown here
                    // and peripheral matching falls back to the advertised name.
                    self.sendUpdate(SensorPairingInfo(uuid: sensorUID, patchInfo: patchInfo, fram: fram,
                                                      streamingEnabled: true, macAddress: nil,
                                                      keyIndex: effectiveKeyIndex, streamingAuthData: streamingAuthData))
                    session.invalidate()
                }
            }
        }
    }

    /// Read the 43 FRAM blocks with gen2's `A1 21 <block> <count-1>`, three
    /// blocks per request as DiaBLE does. Completes with nil on any error or
    /// unexpected reply length.
    func readGen2FRAM(tag: NFCISO15693Tag, completion: @escaping (Data?) -> Void) {
        let logger = Logger(forType: Self.self)
        var fram = Data()

        func readNext() {
            let block = fram.count / 8
            guard block < Self.gen2FRAMBlocks else {
                completion(fram)
                return
            }
            let count = min(Self.gen2FRAMBlocksPerRequest, Self.gen2FRAMBlocks - block)

            tag.customCommand(requestFlags: .highDataRate,
                              customCommandCode: 0xA1,
                              customRequestParameters: Data([0x21, UInt8(block), UInt8(count - 1)])) { response, error in
                if let error {
                    logger.error("gen2: A1 21 read of block \(block) failed: \(error.localizedDescription)")
                    completion(nil)
                    return
                }

                // GEN2-NFC-TODO: DiaBLE drops 8 leading filler bytes; accept the
                // reply with or without them, and nothing else.
                let expected = count * 8
                let blocks: Data
                switch response.count {
                case expected + Self.gen2FRAMFillerLength:
                    blocks = response.suffix(expected)
                case expected:
                    blocks = response
                default:
                    logger.error("gen2: A1 21 block \(block) reply of \(response.count) bytes: \(response.hexEncodedString())")
                    completion(nil)
                    return
                }
                fram.append(blocks)
                readNext()
            }
        }

        readNext()
    }

    /// Read the key index with NFC `02 A1 <uid[6]> 22`. CoreNFC supplies the
    /// flags and manufacturer code, so the request parameter is just `0x22`.
    func readKeyIndex(tag: NFCISO15693Tag, completion: @escaping (Int?) -> Void) {
        let logger = Logger(forType: Self.self)

        tag.customCommand(requestFlags: .highDataRate,
                          customCommandCode: 0xA1,
                          customRequestParameters: Data([0x22])) { response, error in
            if let error {
                logger.error("gen2: key-index command failed: \(error.localizedDescription)")
                completion(nil)
                return
            }
            logger.debug("gen2: key-index response: \(response.hexEncodedString())")
            do {
                let index = try Libre2Gen2.parseKeyIndex(response: [UInt8](response),
                                                         offset: Self.gen2KeyIndexOffset)
                logger.debug("gen2: KeyIndex is \(index)")
                completion(index)
            } catch {
                logger.error("gen2: cannot parse key index: \(error.localizedDescription)")
                completion(nil)
            }
        }
    }
}
