import Foundation
import XCTest
@testable import YDEbikeHelper

final class YadeaV2HandshakeTests: XCTestCase {
    private let token = "00112233445566778899AABBCCDDEEFF"
    private let mac = "A1:B2:C3:D4:E5:F6"
    private let roles = YadeaAccountRoles(accountList: [1, 0, 1, 0, 1, 0], userNo: 2)
    private let clock = Date(timeIntervalSince1970: 37_230) // 10:20:30 UTC

    private var calendar: Calendar {
        var value = Calendar(identifier: .gregorian)
        value.timeZone = TimeZone(secondsFromGMT: 0)!
        return value
    }

    private func challenge(flags: UInt8 = 0x5F) throws -> Data {
        var bytes = try YDEbikeProtocol.parseHex("000102030405060708090A0B0C5F0E0F")
        bytes[13] = flags
        return bytes
    }

    private func packet(
        token: String? = nil, challenge: Data? = nil,
        roles: YadeaAccountRoles? = nil, protocolVersion: Int = 1
    ) throws -> Data {
        let selectedChallenge: Data
        if let challenge {
            selectedChallenge = challenge
        } else {
            selectedChallenge = try self.challenge()
        }
        return try YadeaV2Handshake.plaintextPacket(
            dkInfo: token ?? self.token, challenge: selectedChallenge,
            macAddress: mac, roles: roles ?? self.roles,
            protocolVersion: protocolVersion, date: clock, calendar: calendar
        )
    }

    func testV2PlaintextAndCiphertextMatchIndependentFixture() throws {
        // Synthetic credentials and clock; these are algorithm fixtures, not a
        // captured successful vehicle handshake. Python + OpenSSL checked them.
        let expectedPlaintext = try YDEbikeProtocol.parseHex(
            "00112233445566778899AABBCCDDEEFF5944FFFFFFFFFE10DEF0E8FEA2FFFF69"
        )
        let expectedCiphertext = try YDEbikeProtocol.parseHex(
            "02F64362CE7FB9C8E2D2580DD9579D83CAFC2604E6ACCA6D64BF1F125EE39FC1"
        )
        XCTAssertEqual(try packet(), expectedPlaintext)
        let encrypted = try YadeaV2Handshake.encryptedPacket(
            dkInfo: token, challenge: challenge(), macAddress: mac, roles: roles,
            date: clock, calendar: calendar
        )
        XCTAssertEqual(encrypted, expectedCiphertext)
        // A continuous CBC implementation gives a different second block.
        let continuousCBC = try YDEbikeProtocol.parseHex(
            "02F64362CE7FB9C8E2D2580DD9579D8329CB802C76AB2114A3E2ED7DCF8E4C41"
        )
        XCTAssertNotEqual(encrypted, continuousCBC)
    }

    func testHighRandomBytesUseV2UnsignedMixing() throws {
        var random = try challenge()
        random.replaceSubrange(0..<3, with: [0xF2, 0x80, 0xFF])
        let expected = try YDEbikeProtocol.parseHex(
            "00112233445566778899AABBCCDDEEFF5944FFFFFFFFFE102E7109FEA2FFFFF9"
        )
        XCTAssertEqual(try packet(challenge: random), expected)
        XCTAssertEqual(try YadeaV2Handshake.encryptedPacket(
            dkInfo: token, challenge: random, macAddress: mac, roles: roles,
            date: clock, calendar: calendar
        ), try YDEbikeProtocol.parseHex(
            "708975C6FFF90F22F9E8CFCB8A2CA479A92EF0E344A2C5742C9B914581ABE4E3"
        ))
    }

    func testEachRoleUsesItsObservedWireBit() throws {
        let cases: [([Int], UInt8, UInt8)] = [
            ([1, 0, 0, 0, 0, 0], 0xFE, 0x05),
            ([0, 1, 0, 0, 0, 0], 0xFD, 0x05),
            ([0, 0, 1, 0, 0, 0], 0xFC, 0x85),
            ([0, 0, 0, 1, 0, 0], 0xFC, 0x45),
            ([0, 0, 0, 0, 1, 0], 0xFC, 0x25),
            ([0, 0, 0, 0, 0, 1], 0xFC, 0x15),
        ]
        for (list, first, second) in cases {
            let bytes = [UInt8](try packet(roles: .init(accountList: list, userNo: 5)))
            XCTAssertEqual(bytes[27], first)
            XCTAssertEqual(bytes[28], second)
        }
    }

    func testRoleFieldsFollowTheChallengeCapabilityBit() throws {
        let bytes = try packet(challenge: challenge(flags: 0x5E))
        XCTAssertEqual(bytes, try YDEbikeProtocol.parseHex(
            "00112233445566778899AABBCCDDEEFF5944FFFFFFFFFE10DEF0E8FFFFFFFF35"
        ))
    }

    func testShortTokenIsZeroPaddedWithoutTruncatingFields() throws {
        let bytes = try packet(token: "0x1122")
        XCTAssertEqual(bytes, try YDEbikeProtocol.parseHex(
            "11225944FFFFFFFFFE10DEF0E8FEA2FFFF00000000000000000000000000005A"
        ))
        XCTAssertEqual(bytes.count, 32)
    }

    func testInvalidTokensAndRolesAreRejectedBeforeEncryption() {
        for token in ["", "0x", "ABC", "GG", "11 22", String(repeating: "00", count: 17)] {
            XCTAssertThrowsError(try packet(token: token)) { error in
                XCTAssertEqual(error as? YadeaV2HandshakeError, .invalidToken)
            }
        }
        for invalid in [
            YadeaAccountRoles(accountList: [1, 0, 0, 0, 0], userNo: 0),
            YadeaAccountRoles(accountList: [1, 0, 0, 0, 0, 0, 0], userNo: 0),
            YadeaAccountRoles(accountList: [2, 0, 0, 0, 0, 0], userNo: 0),
            YadeaAccountRoles(accountList: [-1, 0, 0, 0, 0, 0], userNo: 0),
            YadeaAccountRoles(accountList: [1, 0, 0, 0, 0, 0], userNo: -1),
            YadeaAccountRoles(accountList: [1, 0, 0, 0, 0, 0], userNo: 6),
        ] {
            XCTAssertThrowsError(try packet(roles: invalid)) { error in
                XCTAssertEqual(error as? YadeaV2HandshakeError, .invalidRoles)
            }
        }
    }

    func testUnsupportedChallengesAndChannelsAreRejected() throws {
        for length in [0, 3, 15, 17] {
            XCTAssertThrowsError(try packet(challenge: Data(count: length))) { error in
                XCTAssertEqual(error as? YadeaV2HandshakeError, .invalidChallengeLength(length))
            }
        }
        for flags in [UInt8(0x00), 0x08, 0x10, 0x18, 0x50, 0x60, 0x70] {
            XCTAssertThrowsError(try packet(challenge: challenge(flags: flags))) { error in
                XCTAssertEqual(error as? YadeaV2HandshakeError, .unsupportedAuthenticationFlags(flags))
            }
        }
        XCTAssertThrowsError(try packet(protocolVersion: 2)) { error in
            XCTAssertEqual(error as? YadeaV2HandshakeError, .unsupportedProtocolVersion(2))
        }
        // The two supported GATT channel versions change an unused extension,
        // so the selected three-byte slice in a V2 handshake remains the same.
        XCTAssertEqual(try packet(protocolVersion: 0xF1), try packet(protocolVersion: 1))
    }

    func testResponseRequiresFiveBytesAndUsesTheResultField() throws {
        for length in 0..<5 {
            XCTAssertThrowsError(try YadeaV2Handshake.response(Data(count: length))) { error in
                XCTAssertEqual(error as? YadeaV2HandshakeError, .malformedResponse)
            }
        }
        let success = try YadeaV2Handshake.response(Data([0x10, 0x20, 7, 0x30, 0]))
        XCTAssertTrue(success.success)
        XCTAssertEqual(success.remainingUses, 7)
        let failure = try YadeaV2Handshake.response(Data([0, 0, 3, 0, 2]))
        XCTAssertFalse(failure.success)
        XCTAssertEqual(failure.result, 2)
        let invalid = try YadeaV2Handshake.response(Data([0, 0, 0xFF, 0, 0xFF]))
        XCTAssertFalse(invalid.success)
        XCTAssertEqual(invalid.result, -1)
        XCTAssertEqual(invalid.remainingUses, -1)
    }
}
