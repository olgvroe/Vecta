import Foundation

/// Interoperability facts supplied for independent implementation, not device acceptance
/// evidence or a clean-room claim. No socket, authorization, deletion or BLE behavior.
public enum WiFiCommand: Int16, Codable, CaseIterable {
    case handshake = 1
    case sayHello = 2
    case heartbeat = 3
    /// Battery report the recorder pushes unprompted (SDK `wifiPower(power, voltage)`), seen about
    /// 15 s after a file completes. Ignored, never a reason to abort the transfer.
    case power = 4
    case list = 11
    case download = 12
    case content = 13
}

public enum WiFiProtocolError: Error, Equatable {
    case invalidLimit, frameTooLarge, invalidFrameSize, truncatedFrame, trailingBytes
    case unsupportedVersion(UInt8), unsupportedCommand(Int16), invalidJSONSize, invalidJSON
    case unexpectedCommand, unexpectedRequestID, unexpectedBinary, invalidMetadata, decoderFailed
    case remoteStatus(Int32), inconsistentInventory, unexpectedOffset, duplicateFile
    case transferNotStarted, transferAlreadyStarted, transferComplete
    case wrongSession, wrongTotal, wrongLength, invalidTerminal, fileTooLarge, incompleteTransfer
}

/// [u24le total][u8 version][s16le command][s16le JSON length][JSON object][tail].
/// A u24 cannot represent exactly 16 MiB; the largest legal frame is 16 MiB - 1.
public struct WiFiEnvelope: Equatable {
    public static let headerSize = 8
    public static let maximumFrameSize = 0x00ff_ffff
    public static let maximumJSONSize = Int(Int16.max)
    public let version: UInt8
    public let command: WiFiCommand
    public let json: Data
    public let binary: Data

    public init(command: WiFiCommand, json: Data, binary: Data = Data(), version: UInt8 = 1) throws {
        guard version == 1 || version == 2 else { throw WiFiProtocolError.unsupportedVersion(version) }
        try Self.validateJSON(json)
        guard binary.count <= Self.maximumFrameSize - Self.headerSize - json.count else {
            throw WiFiProtocolError.frameTooLarge
        }
        self.version = version
        self.command = command
        self.json = json
        self.binary = binary
    }

    public func encoded(maximumFrameSize limit: Int = maximumFrameSize) throws -> Data {
        try Self.validateLimit(limit)
        let total = Self.headerSize + json.count + binary.count
        guard total <= limit else { throw WiFiProtocolError.frameTooLarge }
        let type = UInt16(bitPattern: command.rawValue)
        var result = Data([
            UInt8(total & 0xff), UInt8((total >> 8) & 0xff), UInt8((total >> 16) & 0xff), version,
            UInt8(type & 0xff), UInt8(type >> 8),
            UInt8(json.count & 0xff), UInt8(json.count >> 8)
        ])
        result.append(json)
        result.append(binary)
        return result
    }

    /// Decodes exactly one frame, rejecting both truncation and trailing frames/bytes.
    public static func decode(_ data: Data, maximumFrameSize limit: Int = maximumFrameSize) throws -> Self {
        let header = try parseHeader(data, limit: limit)
        guard data.count >= header.total else { throw WiFiProtocolError.truncatedFrame }
        guard data.count == header.total else { throw WiFiProtocolError.trailingBytes }
        let jsonStart = data.startIndex + headerSize
        let tailStart = jsonStart + header.jsonSize
        return try Self(command: header.command, json: Data(data[jsonStart..<tailStart]),
                        binary: Data(data[tailStart..<data.endIndex]), version: header.version)
    }

    fileprivate static func validateLimit(_ limit: Int) throws {
        guard limit >= headerSize, limit <= maximumFrameSize else { throw WiFiProtocolError.invalidLimit }
    }

    private static func validateJSON(_ json: Data) throws {
        guard json.count <= maximumJSONSize else { throw WiFiProtocolError.invalidJSONSize }
        guard String(data: json, encoding: .utf8) != nil,
              let value = try? JSONSerialization.jsonObject(with: json),
              value is [String: Any] else { throw WiFiProtocolError.invalidJSON }
    }

    fileprivate static func parseHeader(_ data: Data, limit: Int) throws -> (total: Int, version: UInt8, command: WiFiCommand, jsonSize: Int) {
        try validateLimit(limit)
        guard data.count >= headerSize else { throw WiFiProtocolError.truncatedFrame }
        let h = Array(data.prefix(headerSize))
        let total = Int(h[0]) | Int(h[1]) << 8 | Int(h[2]) << 16
        guard total >= headerSize else { throw WiFiProtocolError.invalidFrameSize }
        guard total <= limit else { throw WiFiProtocolError.frameTooLarge }
        guard h[3] == 1 || h[3] == 2 else { throw WiFiProtocolError.unsupportedVersion(h[3]) }
        let rawType = Int16(bitPattern: UInt16(h[4]) | UInt16(h[5]) << 8)
        guard let command = WiFiCommand(rawValue: rawType) else {
            throw WiFiProtocolError.unsupportedCommand(rawType)
        }
        let jsonSize = Int(h[6]) | Int(h[7]) << 8
        guard jsonSize <= maximumJSONSize, jsonSize <= total - headerSize else {
            throw WiFiProtocolError.invalidJSONSize
        }
        return (total, h[3], command, jsonSize)
    }
}

/// Fragment/coalescing-safe TCP framing. Retains at most one bounded frame.
/// An error poisons the decoder; callers must abandon the stream, not resynchronize it.
public struct WiFiEnvelopeStreamDecoder {
    private let limit: Int
    private var buffer = Data()
    private var failed = false
    public var bufferedByteCount: Int { buffer.count }

    public init(maximumFrameSize: Int = WiFiEnvelope.maximumFrameSize) throws {
        try WiFiEnvelope.validateLimit(maximumFrameSize)
        self.limit = maximumFrameSize
    }

    public mutating func append(_ data: Data) throws -> [WiFiEnvelope] {
        guard !failed else { throw WiFiProtocolError.decoderFailed }
        do {
            var cursor = data.startIndex
            var result: [WiFiEnvelope] = []
            while cursor < data.endIndex {
                if buffer.count < WiFiEnvelope.headerSize {
                    let count = min(WiFiEnvelope.headerSize - buffer.count, data.endIndex - cursor)
                    buffer.append(data[cursor..<(cursor + count)])
                    cursor += count
                    if buffer.count < WiFiEnvelope.headerSize { break }
                }
                let header = try WiFiEnvelope.parseHeader(buffer, limit: limit)
                let count = min(header.total - buffer.count, data.endIndex - cursor)
                buffer.append(data[cursor..<(cursor + count)])
                cursor += count
                if buffer.count == header.total {
                    result.append(try WiFiEnvelope.decode(buffer, maximumFrameSize: limit))
                    buffer = Data()
                }
            }
            return result
        } catch {
            failed = true
            buffer = Data()
            throw error
        }
    }

    /// Call at EOF. A partial final frame is never silently discarded.
    public mutating func finish() throws {
        guard !failed else { throw WiFiProtocolError.decoderFailed }
        guard buffer.isEmpty else {
            failed = true
            buffer = Data()
            throw WiFiProtocolError.truncatedFrame
        }
    }
}
