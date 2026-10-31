import Foundation
import XCTest
@testable import YDEbikeHelper

final class YadeaAccountTests: XCTestCase {
    private let vehicleMAC = "A1:B2:C3:D4:E5:F6"
    private let session = YadeaAccountSession(token: "fixture-session-token", userID: 7, deviceID: "fixture-device")

    func testSignedRequestUsesFixedEndpointAndEncryptedSortedBusinessFields() throws {
        let gateway = YadeaGateway(timestamp: { 1_700_000_000_000 })
        let request = try gateway.makeRequest(.loginSMS,
            fields: ["mobile": "13800138000", "code": "1234", "loginAppType": "1"],
            token: "", deviceID: "fixture-device")
        XCTAssertEqual(request.url?.absoluteString, "https://gw.yadeaiot.com.cn/api/app/user/loginBySms")
        XCTAssertEqual(request.httpMethod, "POST")
        XCTAssertEqual(request.value(forHTTPHeaderField: "gatewayAppId"), "0e7b1d094c7b4073b7c958edbbbc1115")
        let body = try XCTUnwrap(String(data: XCTUnwrap(request.httpBody), encoding: .utf8))
        XCTAssertFalse(body.contains("13800138000"))
        XCTAssertFalse(body.contains("1234"))
        let parameters = try XCTUnwrap(URLComponents(string: "https://example.invalid/?" + body)?.queryItems)
        let sign = try XCTUnwrap(parameters.first(where: { $0.name == "gatewaySign" })?.value)
        let encrypted = try XCTUnwrap(Data(base64Encoded: sign))
        let plain = try YadeaCrypto.ecbDecrypt(encrypted, key: YadeaGateway.formatKey)
        XCTAssertEqual(String(data: plain, encoding: .utf8),
            "gatewayTimestamp=1700000000000&json={\"_gateway\":\"True\",\"code\":\"1234\",\"loginAppType\":\"1\",\"mobile\":\"13800138000\"}")
    }

    func testGETQueriesAreSignedAndAuthorizationIsHeaderOnly() throws {
        let request = try YadeaGateway().makeRequest(.accountRoles, fields: ["bikeId": "42"],
            token: session.token, deviceID: session.deviceID)
        XCTAssertEqual(request.httpMethod, "GET")
        XCTAssertNil(request.httpBody)
        XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "Bearer fixture-session-token")
        XCTAssertFalse(try XCTUnwrap(request.url?.absoluteString).contains(session.token))
        XCTAssertEqual(request.url?.host, YadeaGateway.host)
        XCTAssertTrue(request.url?.query?.contains("gatewaySign=") == true)
    }

    func testFormEncodingMatchesJavaURLEncoderForReservedCharacters() {
        XCTAssertEqual(YadeaGateway.formEncode("a+b/c= x~*"), "a%2Bb%2Fc%3D+x%7E*")
    }

    func testEncryptedResponseAndBusinessFailureAreParsedWithoutExposingBody() throws {
        let json = Data("{\"success\":true,\"code\":0,\"data\":{\"dkInfo\":\"aabb\"}}".utf8)
        let encrypted = try YadeaCrypto.ecbEncrypt(json, key: YadeaGateway.formatKey)
        let encoded = Data(YadeaGateway.formEncode(encrypted.base64EncodedString()).utf8)
        let response = try YadeaGateway.decodeResponse(encoded)
        XCTAssertEqual(try YadeaGateway.tokenHex(from: response), "AABB")
        let sensitive = Data("{\"success\":false,\"code\":403,\"msg\":\"fixture-session-token 13800138000\"}".utf8)
        XCTAssertThrowsError(try YadeaGateway.decodeResponse(sensitive)) { error in
            XCTAssertEqual(error as? YadeaAccountError, .business(403))
            XCTAssertFalse(error.localizedDescription.contains("fixture-session-token"))
            XCTAssertFalse(error.localizedDescription.contains("13800138000"))
        }
    }

    func testMissingOrExpiredSessionResponseIsRejected() {
        XCTAssertThrowsError(try YadeaGateway.decodeResponse(Data("{\"data\":{}}".utf8)))
        XCTAssertThrowsError(try YadeaGateway.decodeResponse(Data("{\"success\":false,\"code\":\"101000\"}".utf8))) { error in
            XCTAssertEqual(error as? YadeaAccountError, .sessionExpired)
        }
    }

    func testPlainJSONPreservesLiteralPlusCharacters() throws {
        let response = try YadeaGateway.decodeResponse(Data("{\"success\":true,\"data\":{\"token\":\"fixture+a+b\"}}".utf8))
        XCTAssertEqual((response["data"] as? [String: Any])?["token"] as? String, "fixture+a+b")
    }

    func testLoggedOutRestorationTombstoneSkipsKeychainRead() throws {
        let suiteName = "YadeaAccountTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suiteName))
        defer { defaults.removePersistentDomain(forName: suiteName) }
        defaults.set(true, forKey: YadeaKeychainSessionStore.restorationBlockedKey)
        let restoredStore = YadeaKeychainSessionStore(defaults: defaults)
        XCTAssertNil(try restoredStore.load())
    }

    func testCrossOriginAndRedirectResponsesAreRejectedEvenWithSuccessfulBody() async throws {
        for (url, code) in [("https://example.invalid/api/app/userBike/queryBindingBike", 200),
                            ("https://gw.yadeaiot.com.cn/api/app/userBike/queryBindingBike", 302)] {
            let gateway = YadeaGateway(transport: { _ in
                (Data("{\"success\":true,\"data\":[]}".utf8),
                 HTTPURLResponse(url: URL(string: url)!, statusCode: code, httpVersion: nil, headerFields: nil)!)
            })
            do {
                _ = try await gateway.request(.vehicles, token: session.token, deviceID: session.deviceID)
                XCTFail("Untrusted response accepted")
            } catch { XCTAssertEqual(error as? YadeaAccountError, .untrustedResponse) }
        }
    }

    func testVehicleParsingRequiresCompleteBindingAndNormalizesOnlyMAC() throws {
        let response: [String: Any] = ["data": [["bikeId": "42", "vin": "fixture-vin", "mac": "a1b2c3d4e5f6", "modelName": "Q17 Pro Y"]]]
        let vehicles = try YadeaGateway.vehicles(from: response)
        XCTAssertEqual(vehicles, [YadeaBoundVehicle(id: "fixture-vin", bikeID: 42,
            vin: "fixture-vin", macAddress: vehicleMAC, name: "Q17 Pro Y")])
        XCTAssertThrowsError(try YadeaGateway.vehicles(from: ["data": [["bikeId": 42, "vin": "fixture-vin"]]]))
        XCTAssertThrowsError(try YadeaGateway.normalizedMAC("prefix A1:B2:C3:D4:E5:F6"))
        XCTAssertThrowsError(try YadeaGateway.normalizedMAC("00:00:00:00:00:00"))
    }

    func testRolesRequireCurrentUserAndReverseAccountOrderBits() throws {
        let response: [String: Any] = ["data": [["id": 7, "accountOrder": 1], ["id": 8, "accountOrder": 5]]]
        let roles = try YadeaGateway.roles(from: response, userID: 7)
        XCTAssertEqual(roles.accountList, [1, 0, 0, 0, 1, 0])
        XCTAssertEqual(roles.userNo, 1)
        XCTAssertThrowsError(try YadeaGateway.roles(from: response, userID: 99))
        XCTAssertThrowsError(try YadeaGateway.roles(from: ["data": [["id": 7, "accountOrder": 6]]], userID: 7))
        XCTAssertThrowsError(try YadeaGateway.roles(from: ["data": [["id": 7, "accountOrder": 1], ["id": 7, "accountOrder": 2]]], userID: 7))
    }

    func testMalformedTokenMaterialIsRejected() {
        for token in ["", "0x", "ABC", "GG00", "AA BB"] {
            XCTAssertThrowsError(try YadeaGateway.tokenHex(from: ["data": ["dkInfo": token]]))
        }
        XCTAssertEqual(try YadeaGateway.tokenHex(from: ["data": ["dkInfo": "0x12ab"]]), "12AB")
    }

    @MainActor
    func testRestoringSessionDoesNotAutomaticallyMakeNetworkRequests() async {
        var requests = 0
        let account = YadeaAccount(gateway: YadeaGateway(transport: { _ in
            requests += 1
            throw YadeaAccountError.network
        }), sessionStore: MemoryYadeaSessionStore(session))
        XCTAssertTrue(account.isLoggedIn)
        XCTAssertTrue(account.vehicles.isEmpty)
        XCTAssertEqual(requests, 0)
    }

    @MainActor
    func testCredentialsRequireMatchingSelectedBindingBeforeAnyCredentialRequest() async throws {
        var requestedPaths: [String] = []
        let gateway = YadeaGateway(transport: { request in
            requestedPaths.append(request.url!.path)
            return Self.response(request, data: [["bikeId": 42, "vin": "fixture-vin", "mac": "A1:B2:C3:D4:E5:F6"]])
        })
        let account = YadeaAccount(gateway: gateway, sessionStore: MemoryYadeaSessionStore(session))
        await account.refreshVehicles()
        XCTAssertEqual(account.selectedVehicleID, "fixture-vin")
        do {
            _ = try await account.credentials(for: "11:22:33:44:55:66")
            XCTFail("Cross-vehicle credentials accepted")
        } catch { XCTAssertEqual(error as? YadeaAccountError, .vehicleMismatch) }
        XCTAssertEqual(requestedPaths, ["/api/app/userBike/queryBindingBike"])
    }

    @MainActor
    func testCredentialsUseBoundVINAndCurrentUserRolesAndDoNotCacheDKInfo() async throws {
        var paths: [String] = []
        let gateway = YadeaGateway(transport: { request in
            paths.append(request.url!.path)
            XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "Bearer fixture-session-token")
            switch request.url!.lastPathComponent {
            case "queryBindingBike":
                return Self.response(request, data: [["bikeId": 42, "vin": "fixture-vin", "mac": "A1:B2:C3:D4:E5:F6"]])
            case "queryUserListByBikeId":
                return Self.response(request, data: [["id": 7, "accountOrder": 0]])
            case "token":
                let form = String(data: request.httpBody!, encoding: .utf8)!
                let parameters = URLComponents(string: "https://example.invalid/?" + form)!.queryItems!
                let encrypted = Data(base64Encoded: parameters.first(where: { $0.name == "gatewaySign" })!.value!)!
                let plain = String(data: try YadeaCrypto.ecbDecrypt(encrypted, key: YadeaGateway.formatKey), encoding: .utf8)!
                XCTAssertTrue(plain.contains("\"vin\":\"fixture-vin\""))
                XCTAssertTrue(plain.contains("\"mac\":\"A1:B2:C3:D4:E5:F6\""))
                return Self.response(request, data: ["dkInfo": "AABBCCDDEEFF0011"])
            default: throw YadeaAccountError.invalidResponse
            }
        })
        let store = MemoryYadeaSessionStore(session)
        let account = YadeaAccount(gateway: gateway, sessionStore: store)
        await account.refreshVehicles()
        let credentials = try await account.credentials(for: "a1-b2-c3-d4-e5-f6")
        XCTAssertEqual(credentials.macAddress, vehicleMAC)
        XCTAssertEqual(credentials.vin, "fixture-vin")
        XCTAssertEqual(credentials.tokenHex, "AABBCCDDEEFF0011")
        XCTAssertEqual(credentials.roles.userNo, 0)
        XCTAssertEqual(store.value, session)
        XCTAssertEqual(paths, ["/api/app/userBike/queryBindingBike", "/api/app/userBike/queryUserListByBikeId", "/api/app/iot-auth/ble/token"])
    }

    @MainActor
    func testLogoutWhileFetchingRolesDoesNotFetchTokenOrReturnOldCredentials() async throws {
        var account: YadeaAccount!
        var tokenRequests = 0
        let gateway = YadeaGateway(transport: { request in
            switch request.url!.lastPathComponent {
            case "queryBindingBike":
                return Self.response(request, data: [["bikeId": 42, "vin": "fixture-vin", "mac": "A1:B2:C3:D4:E5:F6"]])
            case "queryUserListByBikeId":
                await MainActor.run { account.logout() }
                return Self.response(request, data: [["id": 7, "accountOrder": 0]])
            default:
                tokenRequests += 1
                return Self.response(request, data: ["dkInfo": "AABB"])
            }
        })
        let store = MemoryYadeaSessionStore(session)
        account = YadeaAccount(gateway: gateway, sessionStore: store)
        await account.refreshVehicles()
        do {
            _ = try await account.credentials(for: vehicleMAC)
            XCTFail("Logged-out operation returned credentials")
        } catch { XCTAssertEqual(error as? YadeaAccountError, .cancelled) }
        XCTAssertEqual(tokenRequests, 0)
        XCTAssertNil(store.value)
        XCTAssertFalse(account.isLoggedIn)
    }

    private static func response(_ request: URLRequest, data: Any) -> (Data, HTTPURLResponse) {
        (try! JSONSerialization.data(withJSONObject: ["success": true, "code": 0, "data": data]),
         HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!)
    }
}

private final class MemoryYadeaSessionStore: YadeaSessionStore {
    var value: YadeaAccountSession?
    init(_ value: YadeaAccountSession? = nil) { self.value = value }
    func load() throws -> YadeaAccountSession? { value }
    func save(_ session: YadeaAccountSession) throws { value = session }
    func delete() throws { value = nil }
}
