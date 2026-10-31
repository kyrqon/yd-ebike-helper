import CommonCrypto
import Foundation

enum YadeaCryptoError: LocalizedError, Equatable {
    case invalidKeyLength
    case invalidCiphertextLength
    case invalidPadding
    case invalidHandshakeLength
    case operationFailed(Int32)

    var errorDescription: String? {
        switch self {
        case .invalidKeyLength:
            return "AES 密钥长度无效。"
        case .invalidCiphertextLength:
            return "加密响应长度无效，无法解密。"
        case .invalidPadding:
            return "加密响应的补位无效，已拒绝解密结果。"
        case .invalidHandshakeLength:
            return "V2 握手需要 16 字节 RandKey 和按 16 字节对齐的明文。"
        case .operationFailed(let status):
            return "系统加密操作失败（\(status)）。"
        }
    }
}

enum YadeaCrypto {
    static func ecbEncrypt(_ data: Data, key: Data) throws -> Data {
        try crypt(data, key: key, operation: CCOperation(kCCEncrypt),
                  options: CCOptions(kCCOptionECBMode | kCCOptionPKCS7Padding))
    }

    static func ecbDecrypt(_ data: Data, key: Data) throws -> Data {
        guard !data.isEmpty, data.count.isMultiple(of: kCCBlockSizeAES128) else {
            throw YadeaCryptoError.invalidCiphertextLength
        }
        let plaintext = try crypt(data, key: key, operation: CCOperation(kCCDecrypt),
                                  options: CCOptions(kCCOptionECBMode))
        let padding = Int(plaintext.last ?? 0)
        guard (1...kCCBlockSizeAES128).contains(padding),
            padding <= plaintext.count,
            plaintext.suffix(padding).allSatisfy({ $0 == UInt8(padding) })
        else { throw YadeaCryptoError.invalidPadding }
        return Data(plaintext.dropLast(padding))
    }

    static func encryptHandshake(_ plaintext: Data, randomKey: Data) throws -> Data {
        guard randomKey.count == kCCKeySizeAES128,
            !plaintext.isEmpty,
            plaintext.count.isMultiple(of: kCCBlockSizeAES128)
        else {
            throw YadeaCryptoError.invalidHandshakeLength
        }

        // The observed Java implementation restarts CBC for each block.
        // A single continuous CBC call would produce a different second block.
        let bytes = [UInt8](plaintext)
        var ciphertext = Data()
        ciphertext.reserveCapacity(bytes.count)
        for offset in stride(from: 0, to: bytes.count, by: kCCBlockSizeAES128) {
            let block = Data(bytes[offset..<(offset + kCCBlockSizeAES128)])
            ciphertext.append(try crypt(
                block, key: randomKey, operation: CCOperation(kCCEncrypt),
                options: 0, iv: randomKey
            ))
        }
        return ciphertext
    }

    private static func crypt(
        _ data: Data,
        key: Data,
        operation: CCOperation,
        options: CCOptions,
        iv: Data? = nil
    ) throws -> Data {
        guard [kCCKeySizeAES128, kCCKeySizeAES192, kCCKeySizeAES256].contains(key.count) else {
            throw YadeaCryptoError.invalidKeyLength
        }
        let outputCapacity = data.count + kCCBlockSizeAES128
        var output = Data(count: outputCapacity)
        var outputLength: size_t = 0
        let initializationVector = iv ?? Data(repeating: 0, count: kCCBlockSizeAES128)
        let status = key.withUnsafeBytes { (keyBytes: UnsafeRawBufferPointer) in
            initializationVector.withUnsafeBytes { (ivBytes: UnsafeRawBufferPointer) in
                data.withUnsafeBytes { (inputBytes: UnsafeRawBufferPointer) in
                    output.withUnsafeMutableBytes { (outputBytes: UnsafeMutableRawBufferPointer) in
                        CCCrypt(
                            operation, CCAlgorithm(kCCAlgorithmAES), options,
                            keyBytes.baseAddress, key.count, ivBytes.baseAddress,
                            inputBytes.baseAddress, data.count,
                            outputBytes.baseAddress, outputCapacity, &outputLength
                        )
                    }
                }
            }
        }
        guard status == kCCSuccess else {
            throw YadeaCryptoError.operationFailed(status)
        }
        return Data(output.prefix(Int(outputLength)))
    }
}
