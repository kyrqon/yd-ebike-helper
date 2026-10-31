import XCTest
@testable import YDEbikeHelper

final class ConnectionPolicyTests: XCTestCase {
    func testManualAddressWinsOverSystemAndAdvertisement() throws {
        let actual = try ConnectionMACSelection.resolve(
            userInput: "  a1-b2-c3-d4-e5-f6  ",
            systemAddress: "11:22:33:44:55:66",
            preferredCandidate: "77:88:99:AA:BB:CC"
        )
        XCTAssertEqual(actual, "A1:B2:C3:D4:E5:F6")
    }

    func testInvalidManualAddressIsNotSilentlyReplaced() {
        XCTAssertThrowsError(try ConnectionMACSelection.resolve(
            userInput: "invalid",
            systemAddress: "11:22:33:44:55:66",
            preferredCandidate: "77:88:99:AA:BB:CC"
        ))
    }

    func testOnlyEmptyInputUsesSuggestions() throws {
        XCTAssertEqual(try ConnectionMACSelection.resolve(
            userInput: " ",
            systemAddress: "11:22:33:44:55:66",
            preferredCandidate: "77:88:99:AA:BB:CC"
        ), "11:22:33:44:55:66")
        XCTAssertEqual(try ConnectionMACSelection.resolve(
            userInput: "",
            systemAddress: "invalid",
            preferredCandidate: "77:88:99:AA:BB:CC"
        ), "77:88:99:AA:BB:CC")
        XCTAssertThrowsError(try ConnectionMACSelection.resolve(
            userInput: "", systemAddress: nil, preferredCandidate: nil
        ))
    }

    func testAutomaticWriteRespectsAdvertisedCapabilities() {
        XCTAssertEqual(AuthenticationWriteSelection.usesResponse(
            mode: .automatic, supportsResponse: true, supportsWithoutResponse: true
        ), false)
        XCTAssertEqual(AuthenticationWriteSelection.usesResponse(
            mode: .automatic, supportsResponse: true, supportsWithoutResponse: false
        ), true)
        XCTAssertNil(AuthenticationWriteSelection.usesResponse(
            mode: .automatic, supportsResponse: false, supportsWithoutResponse: false
        ))
    }

    func testExplicitWriteModeNeverSilentlyFallsBack() {
        XCTAssertNil(AuthenticationWriteSelection.usesResponse(
            mode: .withResponse, supportsResponse: false, supportsWithoutResponse: true
        ))
        XCTAssertNil(AuthenticationWriteSelection.usesResponse(
            mode: .withoutResponse, supportsResponse: true, supportsWithoutResponse: false
        ))
        XCTAssertEqual(AuthenticationWriteSelection.usesResponse(
            mode: .withResponse, supportsResponse: true, supportsWithoutResponse: true
        ), true)
        XCTAssertEqual(AuthenticationWriteSelection.usesResponse(
            mode: .withoutResponse, supportsResponse: true, supportsWithoutResponse: true
        ), false)
    }
}
