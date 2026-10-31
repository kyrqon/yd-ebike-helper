import XCTest
@testable import YDEbikeHelper

final class YDEbikeProtocolTests: XCTestCase {
    func testMACNormalization() throws {
        XCTAssertEqual(
            try YDEbikeProtocol.normalizedMAC("a1-b2-c3-d4-e5-f6"),
            "A1:B2:C3:D4:E5:F6"
        )
        XCTAssertThrowsError(try YDEbikeProtocol.normalizedMAC("1234"))
    }

    func testAuthenticationPacketOutput() throws {
        let packet = try YDEbikeProtocol.authenticationPacket(
            challenge: Data([0x12, 0x34, 0x56]),
            macAddress: "A1:B2:C3:D4:E5:F6",
            hour: 10,
            minute: 20,
            second: 30
        )

        XCTAssertEqual(packet.count, 14)
        XCTAssertEqual(
            packet,
            Data([
                0x1A, 0x34, 0x5E,
                0xBB, 0x86, 0x9D,
                0xCE, 0xD1, 0xA8,
                0x41, 0x05, 0x01, 0x10, 0x55
            ])
        )
    }

    func testAuthenticationProfileDistinguishesCapabilitiesFromVersion() throws {
        let short = try YDEbikeProtocol.authenticationProfile(
            challenge: Data([0x12, 0x34, 0x56])
        )
        XCTAssertEqual(short.challengeLength, 3)
        XCTAssertNil(short.rawFlags)
        XCTAssertEqual(short.flow, .legacy)

        // Flags are fixtures of the observed layout, not evidence that a
        // particular vehicle model supports one of these authentication flows.
        let cases: [(UInt8, YDEbikeProtocol.AuthenticationFlow, Bool, Bool, Bool)] = [
            (0x00, .legacy, false, false, false),
            (0x08, .legacy, true, false, false),
            (0x40, .legacy, false, false, false),
            (0x10, .secretKey, false, true, true),
            (0x18, .secretKey, true, true, true),
            (0x50, .unsupportedVersion, false, true, false),
            (0x58, .tokenV2, true, true, false),
            (0x59, .tokenV2, true, true, false),
            (0x60, .unsupportedVersion, false, false, false),
            (0x70, .unsupportedVersion, false, false, false),
        ]
        for (flags, flow, tokenAuth, authVersion2, requiresSecretKey) in cases {
            let profile = try YDEbikeProtocol.authenticationProfile(
                challenge: authenticationChallenge(flags: flags)
            )
            XCTAssertEqual(profile.challengeLength, 16)
            XCTAssertEqual(profile.rawFlags, flags)
            XCTAssertEqual(profile.flow, flow, "flags=\(flags)")
            XCTAssertEqual(profile.tokenAuth, tokenAuth, "flags=\(flags)")
            XCTAssertEqual(profile.authVersion2, authVersion2, "flags=\(flags)")
            XCTAssertEqual(profile.requiresSecretKey, requiresSecretKey, "flags=\(flags)")
        }
    }

    func testAuthenticationRejectsMalformedChallengeBeforeBuildingAnAnswer() {
        for length in 0..<3 {
            XCTAssertThrowsError(try YDEbikeProtocol.authenticationPacket(
                challenge: Data(repeating: 0, count: length),
                macAddress: "A1:B2:C3:D4:E5:F6",
                hour: 10, minute: 20, second: 30
            )) { error in
                XCTAssertEqual(error as? YDEbikeProtocolError, .challengeTooShort)
            }
        }
        for length in [4, 9, 13, 14, 15, 17, 32] {
            XCTAssertThrowsError(try YDEbikeProtocol.authenticationPacket(
                challenge: Data(repeating: 0, count: length),
                macAddress: "A1:B2:C3:D4:E5:F6",
                hour: 10, minute: 20, second: 30
            )) { error in
                XCTAssertEqual(error as? YDEbikeProtocolError, .unsupportedChallengeLength(length))
            }
        }
    }

    func testExtendedLegacyChallengePreservesOriginalAnswer() throws {
        let original = try YDEbikeProtocol.authenticationPacket(
            challenge: Data([0x12, 0x34, 0x56]),
            macAddress: "A1:B2:C3:D4:E5:F6",
            hour: 10, minute: 20, second: 30
        )
        for flags in [UInt8(0x00), 0x08, 0x40] {
            let extended = try YDEbikeProtocol.authenticationPacket(
                challenge: authenticationChallenge(flags: flags),
                macAddress: "A1:B2:C3:D4:E5:F6",
                hour: 10, minute: 20, second: 30
            )
            XCTAssertEqual(extended, original)
        }
    }

    func testAuthenticationKeepsHighRandomBytesUnsigned() throws {
        var challenge = authenticationChallenge(flags: 0x00)
        challenge.replaceSubrange(0..<3, with: [0xF2, 0x80, 0xFF])
        let packet = try YDEbikeProtocol.authenticationPacket(
            challenge: challenge,
            macAddress: "A1:B2:C3:D4:E5:F6",
            hour: 10, minute: 20, second: 30
        )
        XCTAssertEqual(packet, Data([
            0xFA, 0x94, 0xFF,
            0x5B, 0x26, 0x3C,
            0x2E, 0x71, 0x09,
            0x41, 0x05, 0x01, 0x10, 0x55,
        ]))
    }

    func testV2TokenChallengeCannotFallBackToLegacyAnswer() {
        XCTAssertThrowsError(try YDEbikeProtocol.authenticationPacket(
            challenge: authenticationChallenge(flags: 0x58),
            macAddress: "A1:B2:C3:D4:E5:F6",
            hour: 10, minute: 20, second: 30
        )) { error in
            XCTAssertEqual(error as? YDEbikeProtocolError, .unsupportedTokenAuthentication)
        }
        // The date overload must enforce the same capability guard.
        XCTAssertThrowsError(try YDEbikeProtocol.authenticationPacket(
            challenge: authenticationChallenge(flags: 0x59),
            macAddress: "A1:B2:C3:D4:E5:F6",
            date: Date(timeIntervalSince1970: 0)
        )) { error in
            XCTAssertEqual(error as? YDEbikeProtocolError, .unsupportedTokenAuthentication)
        }
    }

    func testSecretKeyAndUnknownVersionsCannotFallBackToLegacyAnswer() {
        for flags in [UInt8(0x10), 0x18] {
            XCTAssertThrowsError(try YDEbikeProtocol.authenticationPacket(
                challenge: authenticationChallenge(flags: flags),
                macAddress: "A1:B2:C3:D4:E5:F6",
                hour: 10, minute: 20, second: 30
            )) { error in
                XCTAssertEqual(error as? YDEbikeProtocolError, .unsupportedSecretKeyAuthentication)
            }
        }
        for flags in [UInt8(0x50), 0x60, 0x70] {
            XCTAssertThrowsError(try YDEbikeProtocol.authenticationPacket(
                challenge: authenticationChallenge(flags: flags),
                macAddress: "A1:B2:C3:D4:E5:F6",
                hour: 10, minute: 20, second: 30
            )) { error in
                XCTAssertEqual(error as? YDEbikeProtocolError, .unsupportedAuthenticationVersion(flags))
            }
        }
    }

    private func authenticationChallenge(flags: UInt8) -> Data {
        var challenge = Data(repeating: 0, count: 16)
        challenge.replaceSubrange(0..<3, with: [0x12, 0x34, 0x56])
        challenge[13] = flags
        return challenge
    }

    func testControlPacketsAndChecksums() {
        let debug = [UInt8](YDEbikeProtocol.debugPacket())
        XCTAssertEqual(debug.count, 15)
        XCTAssertEqual(debug.prefix(4), [0x59, 0x44, 0x39, 0x08])
        XCTAssertEqual(debug[12], debug[2..<12].reduce(UInt8(0), &+))
        XCTAssertEqual(debug.suffix(2), [0x4B, 0x4A])

        let restore = [UInt8](YDEbikeProtocol.restorePacket())
        XCTAssertEqual(restore.count, 15)
        XCTAssertEqual(restore[12], restore[2..<12].reduce(UInt8(0), &+))

        for level in [4, 6, 7] {
            let volume = [UInt8](YDEbikeProtocol.volumePacket(level: level))
            XCTAssertEqual(volume.count, 56)
            XCTAssertEqual(volume[53], volume[2..<53].reduce(UInt8(0), &+))
            XCTAssertEqual(volume.suffix(2), [0x4B, 0x4A])
        }
        XCTAssertEqual([UInt8](YDEbikeProtocol.volumePacket(level: 4))[52], 0x3F)
        XCTAssertEqual([UInt8](YDEbikeProtocol.volumePacket(level: 6))[52], 0x5F)
        XCTAssertEqual([UInt8](YDEbikeProtocol.volumePacket(level: 7))[52], 0x7F)
    }

    func testCommandResponseParser() {
        var response = Data(repeating: 0, count: 40)
        response[2] = 0x2A
        response[39] = 0x08
        XCTAssertEqual(YDEbikeProtocol.commandResponseCode(from: response), 1)
        XCTAssertNil(YDEbikeProtocol.commandResponseCode(from: Data([0x59, 0x44])))
    }

    func testHexParser() throws {
        XCTAssertEqual(
            try YDEbikeProtocol.parseHex("0x59 44:3E-31"),
            Data([0x59, 0x44, 0x3E, 0x31])
        )
        XCTAssertThrowsError(try YDEbikeProtocol.parseHex("ABC"))
    }

    func testMACCandidateFromDeviceName() {
        let candidates = MACCandidateExtractor.candidates(
            localName: "YD-A1B2C3D4E5F6",
            manufacturerData: nil,
            serviceData: [:]
        )

        XCTAssertEqual(candidates.first?.address, "A1:B2:C3:D4:E5:F6")
        XCTAssertEqual(candidates.first?.confidence, .high)
        XCTAssertEqual(candidates.first?.source, "设备名")
    }

    func testSystemAddressIsHighestConfidenceCandidate() {
        let candidates = MACCandidateExtractor.candidates(
            systemAddress: "12:34:56:78:9A:BC",
            localName: "YD-A1B2C3D4E5F6",
            manufacturerData: nil,
            serviceData: [:]
        )

        XCTAssertEqual(candidates.first?.address, "12:34:56:78:9A:BC")
        XCTAssertEqual(candidates.first?.confidence, .high)
        XCTAssertEqual(candidates.first?.source, "macOS 系统 BDAddress（私有接口）")
    }

    func testMACCandidatesFromManufacturerDataIncludeBothOrders() {
        let candidates = MACCandidateExtractor.candidates(
            localName: "YD-Test",
            manufacturerData: Data([0x34, 0x12, 0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6]),
            serviceData: [:]
        )

        XCTAssertTrue(candidates.contains { $0.address == "A1:B2:C3:D4:E5:F6" })
        XCTAssertTrue(candidates.contains { $0.address == "F6:E5:D4:C3:B2:A1" })
    }

    func testYDNameSuffixLocatesFullMACInsideManufacturerData() {
        let candidates = MACCandidateExtractor.candidates(
            localName: "YD5C034643",
            manufacturerData: Data([
                0xFF, 0xFF, 0xFF, 0xFF,
                0xC1, 0x28, 0x5C, 0x03, 0x46, 0x43,
                0xE0, 0x0B, 0x1B, 0x02
            ]),
            serviceData: [:]
        )

        XCTAssertEqual(candidates.first?.address, "C1:28:5C:03:46:43")
        XCTAssertEqual(candidates.first?.confidence, .high)
        XCTAssertEqual(candidates.first?.source, "YD 名称后缀与厂商数据匹配")
        XCTAssertTrue(candidates.contains { $0.address == "43:46:03:5C:28:C1" })
    }

    func testMACCandidateRejectsEmptyBinaryValues() {
        XCTAssertTrue(
            MACCandidateExtractor.candidates(
                localName: nil,
                manufacturerData: Data(repeating: 0, count: 6),
                serviceData: [:]
            ).isEmpty
        )
    }

    func testAdvertisementMergeRetainsEarlierManufacturerData() {
        let first = BLEAdvertisementSnapshot(
            localName: "YD-Test",
            systemAddress: "12:34:56:78:9A:BC",
            manufacturerData: Data([0x34, 0x12, 0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6]),
            serviceData: [:],
            txPower: nil,
            isConnectable: true,
            solicitedServices: [],
            overflowServices: []
        )
        let later = BLEAdvertisementSnapshot(
            localName: nil,
            manufacturerData: nil,
            serviceData: ["FFF0": Data([0x01, 0x02])],
            txPower: -4,
            isConnectable: nil,
            solicitedServices: [],
            overflowServices: []
        )

        let merged = first.merging(later)
        XCTAssertEqual(merged.manufacturerData, first.manufacturerData)
        XCTAssertEqual(merged.systemAddress, "12:34:56:78:9A:BC")
        XCTAssertEqual(merged.txPower, -4)
        XCTAssertEqual(merged.serviceData["FFF0"], Data([0x01, 0x02]))
        XCTAssertTrue(merged.macCandidates.contains { $0.address == "A1:B2:C3:D4:E5:F6" })
    }
}

