import Foundation
import XCTest
@testable import YDEbikeHelper

final class YadeaCryptoTests: XCTestCase {
    private let key = Data((0..<16).map(UInt8.init))

    func testECBMatchesNISTBlockAndIndependentPKCS7Fixture() throws {
        let plaintext = try YDEbikeProtocol.parseHex("00112233445566778899AABBCCDDEEFF")
        // First block is the FIPS-197 AES-128 example; the padding block was
        // independently checked with OpenSSL and Windows System.Security AES.
        let ciphertext = try YDEbikeProtocol.parseHex(
            "69C4E0D86A7B0430D8CDB78070B4C55A954F64F2E4E86E9EEE82D20216684899"
        )
        XCTAssertEqual(try YadeaCrypto.ecbEncrypt(plaintext, key: key), ciphertext)
        XCTAssertEqual(try YadeaCrypto.ecbDecrypt(ciphertext, key: key), plaintext)
    }

    func testECBEmptyPlaintextStillProducesOnePaddingBlock() throws {
        let ciphertext = try YDEbikeProtocol.parseHex("954F64F2E4E86E9EEE82D20216684899")
        XCTAssertEqual(try YadeaCrypto.ecbEncrypt(Data(), key: key), ciphertext)
        XCTAssertEqual(try YadeaCrypto.ecbDecrypt(ciphertext, key: key), Data())
    }

    func testECBPreservesUTF8WithAllSupportedAESKeyLengths() throws {
        let plaintext = Data("车辆授权：测试 / + = %".utf8)
        for length in [16, 24, 32] {
            let key = Data(repeating: 0xA5, count: length)
            let encrypted = try YadeaCrypto.ecbEncrypt(plaintext, key: key)
            XCTAssertEqual(try YadeaCrypto.ecbDecrypt(encrypted, key: key), plaintext)
        }
    }

    func testECBRejectsInvalidKeysCiphertextAndPadding() throws {
        XCTAssertThrowsError(try YadeaCrypto.ecbEncrypt(Data(), key: Data(count: 15))) { error in
            XCTAssertEqual(error as? YadeaCryptoError, .invalidKeyLength)
        }
        for invalid in [Data(), Data(count: 15), Data(count: 17)] {
            XCTAssertThrowsError(try YadeaCrypto.ecbDecrypt(invalid, key: key)) { error in
                XCTAssertEqual(error as? YadeaCryptoError, .invalidCiphertextLength)
            }
        }
        // This decrypts to the NIST example block ending in FF, not PKCS7.
        let unpadded = try YDEbikeProtocol.parseHex("69C4E0D86A7B0430D8CDB78070B4C55A")
        XCTAssertThrowsError(try YadeaCrypto.ecbDecrypt(unpadded, key: key)) { error in
            XCTAssertEqual(error as? YadeaCryptoError, .invalidPadding)
        }
    }

    func testHandshakeRestartsCBCForEachBlock() throws {
        let block = try YDEbikeProtocol.parseHex("00112233445566778899AABBCCDDEEFF")
        let expected = try YDEbikeProtocol.parseHex(
            "76D0627DA1D290436E21A4AF7FCA94B776D0627DA1D290436E21A4AF7FCA94B7"
        )
        XCTAssertEqual(try YadeaCrypto.encryptHandshake(block + block, randomKey: key), expected)
    }

    func testHandshakeRejectsInvalidKeyOrAlignment() {
        for (plaintext, randomKey) in [
            (Data(count: 32), Data(count: 15)),
            (Data(count: 31), key),
            (Data(), key),
        ] {
            XCTAssertThrowsError(try YadeaCrypto.encryptHandshake(plaintext, randomKey: randomKey)) { error in
                XCTAssertEqual(error as? YadeaCryptoError, .invalidHandshakeLength)
            }
        }
    }
}
