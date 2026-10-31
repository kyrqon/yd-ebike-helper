import Foundation

struct YadeaAccountRoles: Codable, Equatable {
    let accountList: [Int]
    let userNo: Int
}

enum YadeaV2HandshakeError: LocalizedError, Equatable {
    case invalidChallengeLength(Int)
    case unsupportedAuthenticationFlags(UInt8)
    case invalidToken
    case invalidRoles
    case unsupportedProtocolVersion(Int)
    case invalidClock
    case malformedResponse

    var errorDescription: String? {
        switch self {
        case .invalidChallengeLength(let length):
            return "V2 鉴权需要 16 字节 RandKey，实际为 \(length) 字节。"
        case .unsupportedAuthenticationFlags(let flags):
            return "车辆认证标志 \(String(format: "0x%02X", Int(flags))) 不支持当前 V2 Token 流程。"
        case .invalidToken:
            return "云端 BLE Token 无效：dkInfo 必须是 1 至 16 字节的十六进制数据。"
        case .invalidRoles:
            return "账号角色数据无效，不能构造 V2 鉴权请求。"
        case .unsupportedProtocolVersion(let version):
            return "尚未支持车辆通道版本 \(version)。"
        case .invalidClock:
            return "无法读取本机时间，不能构造 V2 鉴权请求。"
        case .malformedResponse:
            return "车辆认证回包不足 5 字节，不能判断认证结果。"
        }
    }
}

// Wire layout cross-checked against ghhccghk/YuRong at 0df37d80fa747c1c55de278bfa487e5db71e7af6.
// This is an independent implementation of observed behavior, not a vendor specification.
enum YadeaV2Handshake {
    struct Response: Equatable {
        let result: Int
        let remainingUses: Int
        var success: Bool { result == 0 }
    }

    static func encryptedPacket(
        dkInfo: String,
        challenge: Data,
        macAddress: String,
        roles: YadeaAccountRoles,
        protocolVersion: Int = 1,
        date: Date = Date(),
        calendar: Calendar = .current
    ) throws -> Data {
        let plaintext = try plaintextPacket(
            dkInfo: dkInfo, challenge: challenge, macAddress: macAddress,
            roles: roles, protocolVersion: protocolVersion, date: date, calendar: calendar
        )
        return try YadeaCrypto.encryptHandshake(plaintext, randomKey: challenge)
    }

    static func plaintextPacket(
        dkInfo: String,
        challenge: Data,
        macAddress: String,
        roles: YadeaAccountRoles,
        protocolVersion: Int = 1,
        date: Date = Date(),
        calendar: Calendar = .current
    ) throws -> Data {
        guard challenge.count == 16 else {
            throw YadeaV2HandshakeError.invalidChallengeLength(challenge.count)
        }
        let profile = try YDEbikeProtocol.authenticationProfile(challenge: challenge)
        guard profile.flow == .tokenV2 else {
            throw YadeaV2HandshakeError.unsupportedAuthenticationFlags(profile.rawFlags ?? 0)
        }
        guard protocolVersion == 1 || protocolVersion == 0xF1 else {
            throw YadeaV2HandshakeError.unsupportedProtocolVersion(protocolVersion)
        }
        guard roles.accountList.count == 6,
            roles.accountList.allSatisfy({ $0 == 0 || $0 == 1 }),
            (0..<6).contains(roles.userNo)
        else {
            throw YadeaV2HandshakeError.invalidRoles
        }
        let token = try tokenBytes(dkInfo)
        let normalized = try YDEbikeProtocol.normalizedMAC(macAddress)
        let compactMAC = normalized.replacingOccurrences(of: ":", with: "")
        guard let macSuffix = UInt32(compactMAC.suffix(6), radix: 16) else {
            throw YDEbikeProtocolError.invalidMACAddress
        }
        let components = calendar.dateComponents([.hour, .minute, .second], from: date)
        guard let hour = components.hour, let minute = components.minute,
            let second = components.second,
            (0..<24).contains(hour), (0..<60).contains(minute), (0..<60).contains(second)
        else {
            throw YadeaV2HandshakeError.invalidClock
        }
        let random = [UInt8](challenge)
        // V2 uses zero-extended bytes. The reference's signed Java-byte
        // compatibility path belongs to its separate legacy scooter handshake.
        let nonce = (UInt32(random[0]) << 16) | (UInt32(random[1]) << 8) | UInt32(random[2])
        let clock = (UInt32(hour) << 16) | (UInt32(minute) << 8) | UInt32(second)
        let mixed = macSuffix ^ (nonce | clock)

        var frame = [UInt8](token)
        frame += [0x59, 0x44, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0x10]
        // Only bytes 6...8 of the intermediate random block enter a V2 frame.
        // The protocol-version-dependent extension comes after that slice.
        frame += [UInt8(truncatingIfNeeded: mixed >> 16),
                  UInt8(truncatingIfNeeded: mixed >> 8), UInt8(truncatingIfNeeded: mixed)]
        if random[13] & 1 != 0 {
            let role = roles.accountList
            let first = 0xFC | (role[0] << 1) | role[1]
            let second = roles.userNo | (role[5] << 4) | (role[4] << 5)
                | (role[3] << 6) | (role[2] << 7)
            frame += [UInt8(first), UInt8(second)]
        } else {
            frame += [0xFF, 0xFF]
        }
        frame += [0xFF, 0xFF]
        // Short tokens are padded exactly as in the observed 32-byte format;
        // oversized tokens are rejected rather than truncating role fields.
        frame += repeatElement(UInt8(0), count: 31 - frame.count)
        frame.append(frame.reduce(UInt8(0), ^))
        return Data(frame)
    }

    static func response(_ data: Data) throws -> Response {
        guard data.count >= 5 else { throw YadeaV2HandshakeError.malformedResponse }
        let bytes = [UInt8](data)
        // 0xFF is the reference parser's invalid-value sentinel, never success.
        return Response(
            result: bytes[4] == 0xFF ? -1 : Int(bytes[4]),
            remainingUses: bytes[2] == 0xFF ? -1 : Int(bytes[2])
        )
    }

    private static func tokenBytes(_ value: String) throws -> Data {
        var hex = value.trimmingCharacters(in: .whitespacesAndNewlines)
        if hex.hasPrefix("0x") || hex.hasPrefix("0X") { hex.removeFirst(2) }
        let characters = Array(hex.utf8)
        guard !characters.isEmpty, characters.count <= 32,
            characters.count.isMultiple(of: 2),
            characters.allSatisfy({ (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0) })
        else {
            throw YadeaV2HandshakeError.invalidToken
        }
        var token = Data()
        for index in stride(from: 0, to: characters.count, by: 2) {
            let pair = String(decoding: characters[index..<(index + 2)], as: UTF8.self)
            guard let byte = UInt8(pair, radix: 16) else { throw YadeaV2HandshakeError.invalidToken }
            token.append(byte)
        }
        return token
    }
}
