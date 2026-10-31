import Foundation

enum YDEbikeProtocolError: LocalizedError, Equatable {
    case invalidMACAddress
    case challengeTooShort
    case unsupportedChallengeLength(Int)
    case unsupportedTokenAuthentication
    case unsupportedSecretKeyAuthentication
    case unsupportedAuthenticationVersion(UInt8)
    case invalidHex

    var errorDescription: String? {
        switch self {
        case .invalidMACAddress:
            return "MAC 地址必须包含 12 个十六进制字符，例如 A1:B2:C3:D4:E5:F6。"
        case .challengeTooShort:
            return "认证挑战值少于 3 字节。"
        case .unsupportedChallengeLength(let count):
            return "认证挑战值为 \(count) 字节：当前仅识别 3 字节旧版随机数或 16 字节 RandKey，已停止认证。"
        case .unsupportedTokenAuthentication:
            return "设备使用 V2 Token 鉴权，不能发送旧版应答。请先登录雅迪账号并选择本人绑定车辆。"
        case .unsupportedSecretKeyAuthentication:
            return "设备的认证能力标志指向 SecretKey 流程，当前版本不支持，已停止发送旧版认证应答。"
        case .unsupportedAuthenticationVersion(let flags):
            return "设备返回尚未支持的认证版本标志（\(String(format: "0x%02X", Int(flags)))），已停止发送旧版认证应答。"
        case .invalidHex:
            return "HEX 数据格式无效，请输入成对的十六进制字符。"
        }
    }
}

enum YDEbikeProtocol {
    enum AuthenticationWriteMode: String, CaseIterable, Identifiable {
        case automatic
        case withResponse
        case withoutResponse

        var id: String { rawValue }

        var title: String {
            switch self {
            case .automatic: return "自动（兼容）"
            case .withResponse: return "需要确认"
            case .withoutResponse: return "无需确认"
            }
        }
    }

    enum AuthenticationFlow: Equatable {
        case legacy
        case tokenV2
        case secretKey
        case unsupportedVersion
    }

    struct AuthenticationProfile: Equatable {
        let challengeLength: Int
        let rawFlags: UInt8?

        // Observed RandKey layout documented by ghhccghk/YuRong, not a
        // manufacturer specification or a model compatibility guarantee.
        var tokenAuth: Bool { rawFlags.map { $0 & 0x08 != 0 } ?? false }
        var versionSelector: UInt8? { rawFlags.map { ($0 >> 4) & 0x03 } }
        var authVersion2: Bool { versionSelector == 1 }

        // YuRong tests bit 6 inversely in its V2 branch. A clear bit alone
        // is not enough to infer SecretKey requirements for legacy devices.
        var requiresSecretKey: Bool {
            guard authVersion2, let rawFlags else { return false }
            return rawFlags & 0x40 == 0
        }

        var flow: AuthenticationFlow {
            guard let versionSelector else { return .legacy }
            switch versionSelector {
            case 0: return .legacy
            case 1:
                if requiresSecretKey { return .secretKey }
                return tokenAuth ? .tokenV2 : .unsupportedVersion
            default: return .unsupportedVersion
            }
        }

        var diagnosticDescription: String {
            guard let rawFlags else {
                return "3 字节随机数：没有版本标志，保留原有旧版应答；协议版本未经确认"
            }
            let flags = String(format: "0x%02X", Int(rawFlags))
            let description: String
            switch flow {
            case .legacy: description = "旧版认证候选，兼容性仍需实车确认"
            case .tokenV2: description = "V2 Token 鉴权，需要本人账号及车辆授权"
            case .secretKey: description = "V2 SecretKey 流程，当前不支持"
            case .unsupportedVersion: description = "尚未支持的认证版本"
            }
            return "RandKey \(challengeLength) 字节，flags=\(flags)，\(description)"
        }
    }

    static let authenticationService = "E7810B92-73AE-499D-8C15-FAA9AEF0C3F2"
    static let authenticationReadWriteCharacteristic = "BEF8E7E0-9C21-4C9E-B632-BD58C1009F9F"
    static let authenticationNotifyCharacteristic = "BEF8E7E1-9C21-4C9E-B632-BD58C1009F9F"

    static let commandService = "E7810BD2-73AE-499D-8C15-FAA9AEF0C3F2"
    static let commandNotifyCharacteristic = "BEF8E820-9C21-4C9E-B632-BD58C1009F9F"
    static let commandWriteCharacteristic = "BEF8E821-9C21-4C9E-B632-BD58C1009F9F"

    static func normalizedMAC(_ value: String) throws -> String {
        let hex = value.uppercased().filter { $0.isHexDigit }
        guard hex.count == 12 else {
            throw YDEbikeProtocolError.invalidMACAddress
        }
        return stride(from: 0, to: 12, by: 2)
            .map { index in
                let start = hex.index(hex.startIndex, offsetBy: index)
                let end = hex.index(start, offsetBy: 2)
                return String(hex[start..<end])
            }
            .joined(separator: ":")
    }

    static func authenticationPacket(
        challenge: Data,
        macAddress: String,
        hour: Int,
        minute: Int,
        second: Int
    ) throws -> Data {
        _ = try requireLegacyAuthentication(challenge: challenge)

        let normalized = try normalizedMAC(macAddress)
        let compactMAC = normalized.replacingOccurrences(of: ":", with: "")
        guard
            let firstHalf = Int(compactMAC.prefix(6), radix: 16),
            let secondHalf = Int(compactMAC.suffix(6), radix: 16)
        else {
            throw YDEbikeProtocolError.invalidMACAddress
        }

        let bytes = [UInt8](challenge)
        let challengeValue = (Int(bytes[0]) << 16) | (Int(bytes[1]) << 8) | Int(bytes[2])
        let timeValue = ((hour & 0xFF) << 16) | ((minute & 0xFF) << 8) | (second & 0xFF)
        let combined = challengeValue | timeValue
        let firstKey = combined ^ firstHalf
        let secondKey = combined ^ secondHalf

        return Data(
            bytes24(combined)
                + bytes24(firstKey)
                + bytes24(secondKey)
                + [0x41, 0x05, 0x01, 0x10, 0x55]
        )
    }

    static func authenticationProfile(challenge: Data) throws -> AuthenticationProfile {
        guard challenge.count >= 3 else {
            throw YDEbikeProtocolError.challengeTooShort
        }
        // Preserve the original three-byte input contract. Other shortened
        // reads must not silently discard the version flags of a RandKey.
        guard challenge.count == 3 || challenge.count == 16 else {
            throw YDEbikeProtocolError.unsupportedChallengeLength(challenge.count)
        }
        let bytes = [UInt8](challenge)
        return AuthenticationProfile(
            challengeLength: bytes.count,
            rawFlags: bytes.count == 16 ? bytes[13] : nil
        )
    }

    static func requireLegacyAuthentication(challenge: Data) throws -> AuthenticationProfile {
        let profile = try authenticationProfile(challenge: challenge)
        switch profile.flow {
        case .legacy:
            return profile
        case .tokenV2:
            throw YDEbikeProtocolError.unsupportedTokenAuthentication
        case .secretKey:
            throw YDEbikeProtocolError.unsupportedSecretKeyAuthentication
        case .unsupportedVersion:
            throw YDEbikeProtocolError.unsupportedAuthenticationVersion(profile.rawFlags ?? 0)
        }
    }

    static func authenticationPacket(
        challenge: Data,
        macAddress: String,
        date: Date = Date(),
        calendar: Calendar = .current
    ) throws -> Data {
        let components = calendar.dateComponents([.hour, .minute, .second], from: date)
        return try authenticationPacket(
            challenge: challenge,
            macAddress: macAddress,
            hour: components.hour ?? 0,
            minute: components.minute ?? 0,
            second: components.second ?? 0
        )
    }

    static func debugPacket() -> Data {
        checksummed([
            0x59, 0x44, 0x39, 0x08, 0x55, 0xFD, 0xFE, 0xFE,
            0xFE, 0xFE, 0xFE, 0xFF, 0x00, 0x4B, 0x4A
        ])
    }

    static func restorePacket() -> Data {
        checksummed([
            0x59, 0x44, 0x39, 0x08, 0x00, 0xFC, 0xFD, 0xFD,
            0xFD, 0xFD, 0xFD, 0xFF, 0x00, 0x4B, 0x4A
        ])
    }

    static func volumePacket(level: Int) -> Data {
        let value: UInt8
        switch level {
        case 4: value = 0x3F
        case 6: value = 0x5F
        case 7: value = 0x7F
        default: value = 0x3F
        }

        var packet: [UInt8] = [0x59, 0x44, 0x3E, 0x31, 0x01, 0x00, 0x01, 0x01]
        packet.append(contentsOf: repeatElement(0xFF, count: 44))
        packet.append(contentsOf: [value, 0x00, 0x4B, 0x4A])
        return checksummed(packet)
    }

    static func commandResponseCode(from data: Data) -> Int? {
        let bytes = [UInt8](data)
        guard bytes.count >= 40, bytes[2] == 0x2A else {
            return nil
        }
        return Int((bytes[39] >> 3) & 0x03)
    }

    static func parseHex(_ input: String) throws -> Data {
        let compact = input
            .replacingOccurrences(of: "0x", with: "", options: .caseInsensitive)
            .filter { !$0.isWhitespace && $0 != ":" && $0 != "-" && $0 != "," }

        guard !compact.isEmpty, compact.count.isMultiple(of: 2) else {
            throw YDEbikeProtocolError.invalidHex
        }

        var result = Data()
        var index = compact.startIndex
        while index < compact.endIndex {
            let end = compact.index(index, offsetBy: 2)
            guard let byte = UInt8(compact[index..<end], radix: 16) else {
                throw YDEbikeProtocolError.invalidHex
            }
            result.append(byte)
            index = end
        }
        return result
    }

    private static func bytes24(_ value: Int) -> [UInt8] {
        [
            UInt8((value >> 16) & 0xFF),
            UInt8((value >> 8) & 0xFF),
            UInt8(value & 0xFF)
        ]
    }

    private static func checksummed(_ source: [UInt8]) -> Data {
        var packet = source
        guard packet.count >= 5 else {
            return Data(packet)
        }

        let checksumIndex = Int(packet[3]) + 4
        guard checksumIndex < packet.count else {
            return Data(packet)
        }

        packet[checksumIndex] = packet[2..<checksumIndex].reduce(UInt8(0)) {
            $0 &+ $1
        }
        return Data(packet)
    }
}

