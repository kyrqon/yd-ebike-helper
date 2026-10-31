import Combine
import Foundation
import Security

struct YadeaBoundVehicle: Identifiable, Equatable {
    let id: String
    let bikeID: Int64
    let vin: String
    let macAddress: String
    let name: String
}

struct YadeaV2Credentials {
    let tokenHex: String
    let roles: YadeaAccountRoles
    let vin: String
    let macAddress: String
    var protocolVersion: Int = 1
}

enum YadeaAccountError: LocalizedError, Equatable {
    case invalidInput(String)
    case notLoggedIn
    case busy
    case noSelectedVehicle
    case vehicleMismatch
    case missingAccountRole
    case invalidResponse
    case untrustedResponse
    case network
    case http(Int)
    case business(Int?)
    case sessionExpired
    case secureStorage
    case cancelled

    var errorDescription: String? {
        switch self {
        case .invalidInput(let message): return message
        case .notLoggedIn: return "请先登录本人雅迪账号。"
        case .busy: return "账号请求正在进行，请稍后重试。"
        case .noSelectedVehicle: return "请先选择本人账号下的绑定车辆。"
        case .vehicleMismatch: return "所选绑定车辆的 MAC 与当前蓝牙设备不一致，已停止获取凭证。"
        case .missingAccountRole: return "未取得当前账号在该车辆上的有效角色，已停止认证。"
        case .invalidResponse: return "官方服务响应缺少有效资料，请刷新或稍后重试。"
        case .untrustedResponse: return "官方服务返回了不允许的地址或重定向，已停止请求。"
        case .network: return "无法连接官方服务，请检查网络后重试。"
        case .http(let code): return "官方服务请求失败（HTTP \(code)）。"
        case .business(let code):
            return code.map { "官方服务拒绝请求（业务码 \($0)）。" } ?? "官方服务拒绝请求。"
        case .sessionExpired: return "账号登录已失效，请重新登录。"
        case .secureStorage: return "无法访问钥匙串，登录凭证未保存。"
        case .cancelled: return "账号或所选车辆已变化，请重新连接。"
        }
    }
}

struct YadeaAccountSession: Codable, Equatable {
    let token: String
    let userID: Int64
    let deviceID: String
}

protocol YadeaSessionStore {
    func load() throws -> YadeaAccountSession?
    func save(_ session: YadeaAccountSession) throws
    func delete() throws
}

struct YadeaKeychainSessionStore: YadeaSessionStore {
    private let service = "YDEbikeHelper.YadeaAccount"
    private let account = "official-account-session-v1"
    static let restorationBlockedKey = "yd-account-restoration-blocked-v1"
    private let defaults: UserDefaults

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    private var query: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: account]
    }

    func load() throws -> YadeaAccountSession? {
        // Non-secret tombstone: a failed Keychain delete must not restore a logged-out session.
        guard !defaults.bool(forKey: Self.restorationBlockedKey) else { return nil }
        var search = query
        search[kSecReturnData as String] = true
        search[kSecMatchLimit as String] = kSecMatchLimitOne
        search[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUIFail
        var result: CFTypeRef?
        let status = SecItemCopyMatching(search as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data,
              let session = try? JSONDecoder().decode(YadeaAccountSession.self, from: data),
              !session.token.isEmpty, session.userID > 0, !session.deviceID.isEmpty
        else { throw YadeaAccountError.secureStorage }
        return session
    }

    func save(_ session: YadeaAccountSession) throws {
        let data = try JSONEncoder().encode(session)
        let attributes = [kSecValueData as String: data]
        let updated = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if updated == errSecSuccess {
            defaults.removeObject(forKey: Self.restorationBlockedKey)
            return
        }
        guard updated == errSecItemNotFound else { throw YadeaAccountError.secureStorage }
        var item = query
        item[kSecValueData as String] = data
        item[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        guard SecItemAdd(item as CFDictionary, nil) == errSecSuccess else {
            throw YadeaAccountError.secureStorage
        }
        defaults.removeObject(forKey: Self.restorationBlockedKey)
    }

    func delete() throws {
        defaults.set(true, forKey: Self.restorationBlockedKey)
        let result = SecItemDelete(query as CFDictionary)
        guard result == errSecSuccess || result == errSecItemNotFound else {
            throw YadeaAccountError.secureStorage
        }
    }
}

/// Only the official endpoint and these explicit operations can be requested.
struct YadeaGateway {
    enum Endpoint: String, CaseIterable {
        case sendSMS = "user/sendCode"
        case loginSMS = "user/loginBySms"
        case loginPassword = "user/loginByPassword"
        case vehicles = "userBike/queryBindingBike"
        case accountRoles = "userBike/queryUserListByBikeId"
        case bleToken = "iot-auth/ble/token"

        var isGET: Bool { self == .vehicles || self == .accountRoles }
    }

    typealias Transport = (URLRequest) async throws -> (Data, HTTPURLResponse)
    static let host = "gw.yadeaiot.com.cn"
    static let basePath = "/api/app/"
    // Published original-client format key; this is not an account credential.
    static let formatKey = Data("cIDJ9f05d1604703".utf8)
    let transport: Transport
    var timestamp: () -> Int64 = { Int64(Date().timeIntervalSince1970 * 1000) }

    init(transport: Transport? = nil, timestamp: @escaping () -> Int64 = {
        Int64(Date().timeIntervalSince1970 * 1000)
    }) {
        if let transport {
            self.transport = transport
        } else {
            let configuration = URLSessionConfiguration.ephemeral
            configuration.httpCookieStorage = nil
            configuration.urlCredentialStorage = nil
            configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
            configuration.timeoutIntervalForRequest = 20
            configuration.timeoutIntervalForResource = 30
            let session = URLSession(configuration: configuration, delegate: YadeaRedirectBlocker(), delegateQueue: nil)
            self.transport = { request in
                let (data, response) = try await session.data(for: request)
                guard let response = response as? HTTPURLResponse else {
                    throw YadeaAccountError.invalidResponse
                }
                return (data, response)
            }
        }
        self.timestamp = timestamp
    }

    func request(_ endpoint: Endpoint, fields: [String: String] = [:],
                 token: String = "", deviceID: String) async throws -> [String: Any] {
        let request = try makeRequest(endpoint, fields: fields, token: token, deviceID: deviceID)
        let result: (Data, HTTPURLResponse)
        do { result = try await transport(request) }
        catch let error as YadeaAccountError { throw error }
        catch { throw YadeaAccountError.network }
        let (data, response) = result
        guard let responseURL = response.url, isExpectedURL(responseURL, endpoint: endpoint) else {
            throw YadeaAccountError.untrustedResponse
        }
        if (300..<400).contains(response.statusCode) { throw YadeaAccountError.untrustedResponse }
        guard (200..<300).contains(response.statusCode) else {
            throw YadeaAccountError.http(response.statusCode)
        }
        return try Self.decodeResponse(data)
    }

    func makeRequest(_ endpoint: Endpoint, fields: [String: String],
                     token: String, deviceID: String) throws -> URLRequest {
        var business = fields
        business["_gateway"] = "True"
        let json = try JSONSerialization.data(withJSONObject: business, options: [.sortedKeys, .withoutEscapingSlashes])
        guard let text = String(data: json, encoding: .utf8) else { throw YadeaAccountError.invalidResponse }
        let milliseconds = timestamp()
        let signed = try YadeaCrypto.ecbEncrypt(
            Data("gatewayTimestamp=\(milliseconds)&json=\(text)".utf8), key: Self.formatKey
        )
        let form = "gatewaySign=\(Self.formEncode(signed.base64EncodedString()))&gatewayTimestamp=\(milliseconds)"
        var components = URLComponents()
        components.scheme = "https"
        components.host = Self.host
        components.path = Self.basePath + endpoint.rawValue
        if endpoint.isGET { components.percentEncodedQuery = form }
        guard let url = components.url else { throw YadeaAccountError.invalidResponse }
        var request = URLRequest(url: url)
        request.httpMethod = endpoint.isGET ? "GET" : "POST"
        if !endpoint.isGET {
            request.httpBody = Data(form.utf8)
            request.setValue("application/x-www-form-urlencoded; charset=utf-8", forHTTPHeaderField: "Content-Type")
        }
        let headers = [
            "gatewayAppId": "0e7b1d094c7b4073b7c958edbbbc1115",
            "req-id": UUID().uuidString.lowercased(), "request-agent": "2", "deviceId": deviceID,
            "os": "android", "app-version": "8.8.9", "app-version-num": "8890",
            "app-market": "Yadea", "app-version-type": "1", "bike-series-code": "4",
            "app-name": "YADEA", "device-brand": "", "phone-model": "",
            "language": "zh_CN", "push-operator": "2"
        ]
        for (key, value) in headers { request.setValue(value, forHTTPHeaderField: key) }
        if !token.isEmpty { request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization") }
        return request
    }

    func isExpectedURL(_ url: URL, endpoint: Endpoint) -> Bool {
        url.scheme?.lowercased() == "https" && url.host?.lowercased() == Self.host
            && (url.port == nil || url.port == 443) && url.user == nil && url.password == nil
            && url.path == Self.basePath + endpoint.rawValue
    }

    static func decodeResponse(_ data: Data) throws -> [String: Any] {
        guard let raw = String(data: data, encoding: .utf8) else { throw YadeaAccountError.invalidResponse }
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        let plain: Data
        if trimmed.hasPrefix("{") {
            plain = Data(trimmed.utf8)
        } else {
            let decoded = trimmed.replacingOccurrences(of: "+", with: " ").removingPercentEncoding ?? trimmed
            if decoded.hasPrefix("{") {
                plain = Data(decoded.utf8)
            } else {
                guard let encrypted = Data(base64Encoded: decoded) else { throw YadeaAccountError.invalidResponse }
                do { plain = try YadeaCrypto.ecbDecrypt(encrypted, key: formatKey) }
                catch { throw YadeaAccountError.invalidResponse }
            }
        }
        guard let object = try? JSONSerialization.jsonObject(with: plain) as? [String: Any] else {
            throw YadeaAccountError.invalidResponse
        }
        let code = integer(object["code"])
        if code == 101000 || code == 100995 { throw YadeaAccountError.sessionExpired }
        guard object["success"] as? Bool == true else {
            throw YadeaAccountError.business(code.map(Int.init))
        }
        return object
    }

    static func formEncode(_ text: String) -> String {
        text.utf8.map { byte -> String in
            switch byte {
            case 65...90, 97...122, 48...57, 45, 46, 95, 42: return String(UnicodeScalar(byte))
            case 32: return "+"
            default: return String(format: "%%%02X", byte)
            }
        }.joined()
    }

    static func integer(_ value: Any?) -> Int64? {
        if let number = value as? NSNumber {
            guard CFGetTypeID(number) != CFBooleanGetTypeID() else { return nil }
            let result = number.int64Value
            guard number.doubleValue == Double(result) else { return nil }
            return result
        }
        return (value as? String).flatMap(Int64.init)
    }

    static func text(_ value: Any?) -> String {
        (value as? String)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    }

    static func normalizedMAC(_ raw: String) throws -> String {
        let allowed = CharacterSet(charactersIn: "0123456789abcdefABCDEF:- \t\r\n")
        guard raw.unicodeScalars.allSatisfy({ allowed.contains($0) }),
              let result = try? YDEbikeProtocol.normalizedMAC(raw),
              result != "00:00:00:00:00:00", result != "FF:FF:FF:FF:FF:FF"
        else { throw YadeaAccountError.invalidResponse }
        return result
    }

    static func vehicles(from response: [String: Any]) throws -> [YadeaBoundVehicle] {
        guard let rows = response["data"] as? [[String: Any]] else { throw YadeaAccountError.invalidResponse }
        let vehicles = rows.compactMap { row -> YadeaBoundVehicle? in
            let vin = text(row["vin"])
            guard let bikeID = integer(row["bikeId"]), bikeID > 0, !vin.isEmpty,
                  let mac = try? normalizedMAC(text(row["mac"])) else { return nil }
            let name = ["bikeNickName", "modelName", "bluetoothName"].map { text(row[$0]) }
                .first(where: { !$0.isEmpty }) ?? "雅迪车辆"
            return YadeaBoundVehicle(id: vin, bikeID: bikeID, vin: vin, macAddress: mac, name: name)
        }
        guard rows.isEmpty || !vehicles.isEmpty else { throw YadeaAccountError.invalidResponse }
        return vehicles
    }

    static func roles(from response: [String: Any], userID: Int64) throws -> YadeaAccountRoles {
        guard userID > 0, let rows = response["data"] as? [[String: Any]] else {
            throw YadeaAccountError.missingAccountRole
        }
        var accountList = [Int](repeating: 0, count: 6)
        var userNo: Int?
        for row in rows {
            guard let order = integer(row["accountOrder"]), (0...5).contains(order) else { continue }
            accountList[5 - Int(order)] = 1
            if integer(row["id"]) == userID {
                guard userNo == nil || userNo == Int(order) else { throw YadeaAccountError.missingAccountRole }
                userNo = Int(order)
            }
        }
        guard let userNo else { throw YadeaAccountError.missingAccountRole }
        return YadeaAccountRoles(accountList: accountList, userNo: userNo)
    }

    static func tokenHex(from response: [String: Any]) throws -> String {
        guard let object = response["data"] as? [String: Any] else { throw YadeaAccountError.invalidResponse }
        var token = text(object["dkInfo"])
        if token.lowercased().hasPrefix("0x") { token.removeFirst(2) }
        guard !token.isEmpty, token.count.isMultiple(of: 2),
              token.unicodeScalars.allSatisfy({ CharacterSet(charactersIn: "0123456789abcdefABCDEF").contains($0) })
        else { throw YadeaAccountError.invalidResponse }
        return token.uppercased()
    }
}

private final class YadeaRedirectBlocker: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        // No forwarding of Authorization, signed parameters, passwords or SMS codes.
        completionHandler(nil)
    }
}

@MainActor
final class YadeaAccount: ObservableObject {
    static let shared = YadeaAccount()
    @Published private(set) var isLoggedIn = false
    @Published private(set) var isBusy = false
    @Published private(set) var status = "尚未登录"
    @Published private(set) var vehicles: [YadeaBoundVehicle] = []
    @Published var selectedVehicleID: String?

    private let gateway: YadeaGateway
    private let sessionStore: YadeaSessionStore
    private var session: YadeaAccountSession?
    private var deviceID = UUID().uuidString
    private var generation = UUID()

    init(gateway: YadeaGateway = YadeaGateway(), sessionStore: YadeaSessionStore = YadeaKeychainSessionStore()) {
        self.gateway = gateway
        self.sessionStore = sessionStore
        do {
            if let saved = try sessionStore.load() {
                session = saved
                deviceID = saved.deviceID
                isLoggedIn = true
                status = "已恢复本机登录，请刷新绑定车辆。"
            }
        } catch { status = YadeaAccountError.secureStorage.localizedDescription }
    }

    @discardableResult
    func sendSMS(phone: String) async -> Bool {
        guard !isBusy else { return false }
        let phone = phone.trimmingCharacters(in: .whitespacesAndNewlines)
        guard phone.range(of: "^1[0-9]{10}$", options: .regularExpression) != nil else {
            status = "请输入正确的 11 位手机号。"
            return false
        }
        isBusy = true
        let attempt = generation
        defer { isBusy = false }
        do {
            _ = try await gateway.request(.sendSMS, fields: [
                "appType": "1", "mobile": phone, "registrationId": "", "sendCode": "1"
            ], deviceID: deviceID)
            try ensureCurrent(attempt)
            status = "验证码已发送。"
            return true
        } catch {
            if generation == attempt { status = safeMessage(error) }
            return false
        }
    }

    func loginSMS(phone: String, code: String) async {
        let phone = phone.trimmingCharacters(in: .whitespacesAndNewlines)
        let code = code.trimmingCharacters(in: .whitespacesAndNewlines)
        guard phone.range(of: "^1[0-9]{10}$", options: .regularExpression) != nil,
              code.range(of: "^[0-9]{4}$", options: .regularExpression) != nil else {
            status = "请输入正确的手机号及 4 位验证码。"
            return
        }
        await login(.loginSMS, fields: ["mobile": phone, "code": code, "loginAppType": "1", "oppoPushId": "", "registrationId": ""])
    }

    func loginPassword(account: String, password: String) async {
        let account = account.trimmingCharacters(in: .whitespacesAndNewlines)
        let isPhone = account.range(of: "^1[0-9]{10}$", options: .regularExpression) != nil
        let isEmail = account.range(of: "^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$", options: .regularExpression) != nil
        guard (isPhone || isEmail), !password.isEmpty else {
            status = "请输入正确的手机号或邮箱及密码。"
            return
        }
        await login(.loginPassword, fields: ["account": account, "password": password,
            "accountType": isPhone ? "1" : "2", "appType": "1", "oppoPushId": "", "registrationId": ""])
    }

    private func login(_ endpoint: YadeaGateway.Endpoint, fields: [String: String]) async {
        guard !isBusy else { return }
        isBusy = true
        var attempt = generation
        status = "正在登录官方服务…"
        defer { isBusy = false }
        do {
            let response = try await gateway.request(endpoint, fields: fields, deviceID: deviceID)
            try ensureCurrent(attempt)
            guard let user = response["data"] as? [String: Any],
                  let userID = YadeaGateway.integer(user["id"]), userID > 0 else {
                throw YadeaAccountError.invalidResponse
            }
            let token = YadeaGateway.text(user["token"])
            guard !token.isEmpty else { throw YadeaAccountError.invalidResponse }
            let newSession = YadeaAccountSession(token: token, userID: userID, deviceID: deviceID)
            do { try sessionStore.save(newSession) }
            catch { throw YadeaAccountError.secureStorage }
            generation = UUID()
            attempt = generation
            session = newSession
            isLoggedIn = true
            vehicles = []
            selectedVehicleID = nil
            NotificationCenter.default.post(name: Notification.Name("YadeaAccountAuthorizationChanged"), object: nil)
            status = "登录成功，正在读取绑定车辆…"
            try await loadVehicles(session: newSession, attempt: attempt)
        } catch {
            if generation == attempt { handle(error) }
        }
    }

    func refreshVehicles() async {
        guard !isBusy else { return }
        guard let session else { status = YadeaAccountError.notLoggedIn.localizedDescription; return }
        isBusy = true
        let attempt = generation
        status = "正在刷新绑定车辆…"
        defer { isBusy = false }
        do { try await loadVehicles(session: session, attempt: attempt) }
        catch { if generation == attempt { handle(error) } }
    }

    private func loadVehicles(session: YadeaAccountSession, attempt: UUID) async throws {
        let response = try await gateway.request(.vehicles, token: session.token, deviceID: session.deviceID)
        try ensureCurrent(attempt, expectedSession: session)
        vehicles = try YadeaGateway.vehicles(from: response)
        if !vehicles.contains(where: { $0.id == selectedVehicleID }) {
            selectedVehicleID = vehicles.count == 1 ? vehicles.first?.id : nil
        }
        status = vehicles.isEmpty ? "账号已登录，未返回资料完整的绑定车辆。" : "已获取 \(vehicles.count) 辆绑定车辆。"
    }

    func logout() {
        generation = UUID()
        session = nil
        isLoggedIn = false
        vehicles = []
        selectedVehicleID = nil
        NotificationCenter.default.post(name: Notification.Name("YadeaAccountAuthorizationChanged"), object: nil)
        do { try sessionStore.delete(); status = "已退出登录并清除本机凭证。" }
        catch { status = "已退出当前会话，但钥匙串清除失败，请稍后重试退出。" }
    }

    func credentials(for mac: String) async throws -> YadeaV2Credentials {
        guard !isBusy else { throw YadeaAccountError.busy }
        guard let session, isLoggedIn else { throw YadeaAccountError.notLoggedIn }
        guard let selected = vehicles.first(where: { $0.id == selectedVehicleID }) else {
            throw YadeaAccountError.noSelectedVehicle
        }
        guard let target = try? YadeaGateway.normalizedMAC(mac),
              let vehicleMAC = try? YadeaGateway.normalizedMAC(selected.macAddress), target == vehicleMAC else {
            throw YadeaAccountError.vehicleMismatch
        }
        isBusy = true
        let attempt = generation
        status = "正在获取所选绑定车辆的蓝牙凭证…"
        defer { isBusy = false }
        do {
            let roleResponse = try await gateway.request(.accountRoles, fields: ["bikeId": String(selected.bikeID)],
                token: session.token, deviceID: session.deviceID)
            try ensureCurrent(attempt, vehicleID: selected.id, expectedSession: session)
            let roles = try YadeaGateway.roles(from: roleResponse, userID: session.userID)
            let tokenResponse = try await gateway.request(.bleToken, fields: ["vin": selected.vin,
                "mac": target, "version": "1", "refreshToken": "0"],
                token: session.token, deviceID: session.deviceID)
            try ensureCurrent(attempt, vehicleID: selected.id, expectedSession: session)
            let token = try YadeaGateway.tokenHex(from: tokenResponse)
            status = "所选绑定车辆的蓝牙凭证已取得。"
            return YadeaV2Credentials(tokenHex: token, roles: roles, vin: selected.vin, macAddress: target)
        } catch {
            if generation == attempt { handle(error) }
            throw error
        }
    }

    private func ensureCurrent(_ attempt: UUID, vehicleID: String? = nil,
                               expectedSession: YadeaAccountSession? = nil) throws {
        guard generation == attempt, !Task.isCancelled,
              vehicleID == nil || selectedVehicleID == vehicleID,
              expectedSession == nil || session == expectedSession else { throw YadeaAccountError.cancelled }
    }

    private func handle(_ error: Error) {
        if error as? YadeaAccountError == .sessionExpired {
            logout()
            status = YadeaAccountError.sessionExpired.localizedDescription
        } else {
            status = safeMessage(error)
        }
    }

    private func safeMessage(_ error: Error) -> String {
        (error as? YadeaAccountError)?.localizedDescription ?? YadeaAccountError.network.localizedDescription
    }
}
