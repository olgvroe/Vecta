import Foundation
import XCTest
@testable import NotePinTransport

/// Synthetic interoperability fixtures, not physical recorder acceptance.
final class WiFiEnvelopeTests: XCTestCase {
    func testGoldenHeaderAndBinaryRoundTrip() throws {
        let json = Data("{\"a\":1}".utf8)
        let envelope = try WiFiEnvelope(command: .content, json: json, binary: Data([0xff, 0, 0x80]))
        let wire = try envelope.encoded()
        XCTAssertEqual(wire, Data([18, 0, 0, 1, 13, 0, 7, 0]) + json + Data([0xff, 0, 0x80]))
        XCTAssertEqual(try WiFiEnvelope.decode(wire), envelope)
        var prefixed = Data([0xaa, 0xbb]) + wire
        prefixed.removeFirst(2)
        XCTAssertEqual(try WiFiEnvelope.decode(prefixed), envelope)
    }

    func testBothKnownVersionsPreserveHeaderAndFragmentedRoundTrip() throws {
        for version: UInt8 in [1, 2] {
            for command in WiFiCommand.allCases {
                let envelope = try WiFiEnvelope(command: command, json: Data("{}".utf8), version: version)
                let wire = try envelope.encoded()
                XCTAssertEqual(wire[3], version)
                XCTAssertEqual(try WiFiEnvelope.decode(wire), envelope)
                for boundary in 0...wire.count {
                    var decoder = try WiFiEnvelopeStreamDecoder()
                    let first = try decoder.append(Data(wire.prefix(boundary)))
                    let second = try decoder.append(Data(wire.dropFirst(boundary)))
                    XCTAssertEqual(first + second, [envelope])
                    try decoder.finish()
                }
            }
        }
        for version: UInt8 in [0, 3, 255] {
            XCTAssertThrowsError(try WiFiEnvelope(command: .sayHello, json: Data("{}".utf8), version: version))
        }
    }

    func testCommandConstants() {
        XCTAssertEqual(WiFiCommand.allCases.map(\.rawValue), [1, 2, 3, 4, 11, 12, 13])
    }

    func testExactJSONLimitAndNoSignedWrapping() throws {
        let json = Data(("{\"p\":\"" + String(repeating: "x", count: 32759) + "\"}").utf8)
        XCTAssertEqual(json.count, 32767)
        let wire = try WiFiEnvelope(command: .heartbeat, json: json).encoded()
        XCTAssertEqual(Array(wire[6..<8]), [0xff, 0x7f])
        XCTAssertEqual(try WiFiEnvelope.decode(wire).json, json)
        XCTAssertThrowsError(try WiFiEnvelope(command: .heartbeat, json: json + Data([0x20]))) {
            XCTAssertEqual($0 as? WiFiProtocolError, .invalidJSONSize)
        }
        var invalid = wire
        invalid[7] = 0x80
        XCTAssertThrowsError(try WiFiEnvelope.decode(invalid))
    }

    func testMaximumU24FrameAndOneByteTooLarge() throws {
        let tailSize = WiFiEnvelope.maximumFrameSize - 10
        let envelope = try WiFiEnvelope(command: .content, json: Data("{}".utf8),
                                        binary: Data(repeating: 0xa5, count: tailSize))
        let wire = try envelope.encoded()
        XCTAssertEqual(wire.count, 16 * 1024 * 1024 - 1)
        XCTAssertEqual(Array(wire.prefix(3)), [255, 255, 255])
        XCTAssertEqual(try WiFiEnvelope.decode(wire).binary.count, tailSize)
        XCTAssertThrowsError(try WiFiEnvelope(command: .content, json: Data("{}".utf8),
                                              binary: Data(repeating: 0, count: tailSize + 1)))
    }

    func testConfiguredBoundsFailBeforeCollectingBody() throws {
        let wire = try WiFiEnvelope(metadata: WiFiHeartbeat()).encoded()
        XCTAssertThrowsError(try WiFiEnvelope.decode(wire, maximumFrameSize: 9)) {
            XCTAssertEqual($0 as? WiFiProtocolError, .frameTooLarge)
        }
        XCTAssertThrowsError(try WiFiEnvelope(metadata: WiFiHeartbeat()).encoded(maximumFrameSize: 9))
        for limit in [-1, 0, 7, 16 * 1024 * 1024, Int.max] {
            XCTAssertThrowsError(try WiFiEnvelopeStreamDecoder(maximumFrameSize: limit))
        }
        var decoder = try WiFiEnvelopeStreamDecoder(maximumFrameSize: 10)
        XCTAssertThrowsError(try decoder.append(Data([11, 0, 0, 1, 13, 0, 2, 0])))
        XCTAssertEqual(decoder.bufferedByteCount, 0)
        XCTAssertThrowsError(try decoder.append(wire)) {
            XCTAssertEqual($0 as? WiFiProtocolError, .decoderFailed)
        }
    }

    func testDecodesUnpromptedBatteryReport() throws {
        // NotePin S pushes type 4 about 15 s after a file completes; rejecting it aborted
        // the transfer while the received file was still being converted.
        var wire = try WiFiEnvelope(metadata: WiFiHeartbeat()).encoded()
        wire[4] = 4; wire[5] = 0
        XCTAssertEqual(try WiFiEnvelope.decode(wire).command, .power)
    }

    func testRejectsVersionUnknownSignedTypesAndImpossibleSizes() throws {
        let base = try WiFiEnvelope(metadata: WiFiHeartbeat()).encoded()
        for version: UInt8 in [0, 3, 255] {
            var wire = base; wire[3] = version
            XCTAssertThrowsError(try WiFiEnvelope.decode(wire)) {
                XCTAssertEqual($0 as? WiFiProtocolError, .unsupportedVersion(version))
            }
        }
        for type: UInt16 in [0, 5, 10, 14, 0xffff, 0x8000] {
            var wire = base; wire[4] = UInt8(type & 255); wire[5] = UInt8(type >> 8)
            XCTAssertThrowsError(try WiFiEnvelope.decode(wire)) {
                XCTAssertEqual($0 as? WiFiProtocolError, .unsupportedCommand(Int16(bitPattern: type)))
            }
        }
        for size: UInt8 in [0, 1, 7] {
            var wire = base; wire[0] = size
            XCTAssertThrowsError(try WiFiEnvelope.decode(wire))
        }
        var wire = base; wire[6] = 3
        XCTAssertThrowsError(try WiFiEnvelope.decode(wire))
    }

    func testRejectsEveryTruncationAndTrailingBytes() throws {
        let wire = try WiFiEnvelope(metadata: WiFiContentMetadata(session: 9, offset: 0, length: 2, last: 1),
                                    binary: Data([1, 2])).encoded()
        for size in 0..<wire.count {
            XCTAssertThrowsError(try WiFiEnvelope.decode(Data(wire.prefix(size))))
        }
        XCTAssertThrowsError(try WiFiEnvelope.decode(wire + Data([0]))) {
            XCTAssertEqual($0 as? WiFiProtocolError, .trailingBytes)
        }
        XCTAssertThrowsError(try WiFiEnvelope.decode(wire + wire))
    }

    func testStrictUTF8JSONObject() throws {
        for json in [Data(), Data("null".utf8), Data("[]".utf8), Data("1".utf8),
                     Data("\"text\"".utf8), Data("{".utf8), Data("{}{}".utf8),
                     Data([0x7b, 0x22, 0x78, 0x22, 0x3a, 0x22, 0xff, 0x22, 0x7d])] {
            XCTAssertThrowsError(try WiFiEnvelope(command: .heartbeat, json: json)) {
                XCTAssertEqual($0 as? WiFiProtocolError, .invalidJSON)
            }
        }
        let json = Data("{\"name\":\"Тест\"}".utf8)
        XCTAssertEqual(try WiFiEnvelope.decode(WiFiEnvelope(command: .sayHello, json: json).encoded()).json, json)
        let malformed = Data([9, 0, 0, 1, 3, 0, 1, 0, 0x7b])
        XCTAssertThrowsError(try WiFiEnvelope.decode(malformed))
    }

    func testFragmentationAtEveryBoundaryAndCoalescedFrames() throws {
        let a = try WiFiEnvelope(metadata: WiFiHeartbeat())
        let b = try WiFiEnvelope(metadata: WiFiContentMetadata(session: 1, offset: 0, length: 3, last: 1),
                                 binary: Data([0, 255, 7]))
        let bytes = try a.encoded() + b.encoded() + a.encoded()
        for boundary in 0...bytes.count {
            var decoder = try WiFiEnvelopeStreamDecoder()
            let first = try decoder.append(Data(bytes.prefix(boundary)))
            let second = try decoder.append(Data(bytes.dropFirst(boundary)))
            XCTAssertEqual(first + second, [a, b, a])
            XCTAssertEqual(decoder.bufferedByteCount, 0)
            try decoder.finish()
        }
        var decoder = try WiFiEnvelopeStreamDecoder()
        var frames: [WiFiEnvelope] = []
        for byte in bytes { frames += try decoder.append(Data([byte])) }
        XCTAssertEqual(frames, [a, b, a])
        XCTAssertEqual(try decoder.append(Data()), [])
        try decoder.finish()
    }

    func testEOFRejectsPartialAndPoisonsStream() throws {
        let wire = try WiFiEnvelope(metadata: WiFiHeartbeat()).encoded()
        for size in 1..<wire.count {
            var decoder = try WiFiEnvelopeStreamDecoder()
            XCTAssertEqual(try decoder.append(Data(wire.prefix(size))), [])
            XCTAssertThrowsError(try decoder.finish()) {
                XCTAssertEqual($0 as? WiFiProtocolError, .truncatedFrame)
            }
            XCTAssertThrowsError(try decoder.append(wire))
        }
        var decoder = try WiFiEnvelopeStreamDecoder()
        XCTAssertThrowsError(try decoder.append(Data([9, 0, 0, 1, 3, 0, 1, 0, 0xff])))
        XCTAssertThrowsError(try decoder.finish())
    }

    func testTypedRequestsAndHandshakePadding() throws {
        let handshake = try WiFiHandshake(token: "owner", stamp: 1_700_000_000)
        XCTAssertEqual(handshake.token, "owner" + String(repeating: "0", count: 27))
        let envelope = try WiFiEnvelope(metadata: handshake)
        XCTAssertEqual(try envelope.metadata(as: WiFiHandshake.self), handshake)
        XCTAssertEqual(try JSONSerialization.jsonObject(with: envelope.json) as? [String: AnyHashable],
                       ["token": handshake.token, "stamp": 1_700_000_000])
        let long = String(repeating: "A", count: 40)
        XCTAssertEqual(try WiFiHandshake(token: long, stamp: 0).token, long)
        for token in ["", "contains space", "line\nbreak", "не ASCII", "nul\0"] {
            XCTAssertThrowsError(try WiFiHandshake(token: token, stamp: 0))
        }
        let list = WiFiListRequest(uid: 0x12345678, start: 0xabcdef01, single: 1)
        XCTAssertEqual(try WiFiEnvelope(metadata: list).metadata(as: WiFiListRequest.self), list)
        let download = WiFiDownloadRequest(session: UInt32.max, scene: UInt16.max, start: 0, end: UInt32.max)
        XCTAssertEqual(try WiFiEnvelope(metadata: download).metadata(as: WiFiDownloadRequest.self), download)
    }

    func testHandshakeResponseRequiresStatusButNotSession() throws {
        for json in ["{\"status\":0}", "{\"status\":0,\"session\":\"\"}"] {
            let envelope = try WiFiEnvelope(command: .handshake, json: Data(json.utf8))
            XCTAssertTrue(try envelope.metadata(as: WiFiHandshakeResponse.self).accepted)
        }
        XCTAssertFalse(try WiFiEnvelope(metadata: WiFiHandshakeResponse(status: 1)).metadata(as: WiFiHandshakeResponse.self).accepted)
        XCTAssertThrowsError(try WiFiEnvelope(command: .handshake, json: Data("{}".utf8)).metadata(as: WiFiHandshakeResponse.self))
        XCTAssertThrowsError(try WiFiEnvelope(command: .handshake, json: Data("{\"status\":\"0\"}".utf8)).metadata(as: WiFiHandshakeResponse.self))
    }

    func testSayHelloPreservesVersionFormsAndOptionalIdentityFields() throws {
        let hello = WiFiSayHello(sn: "SYNTHETIC", version: .string("1.2"), token: "opaque", pVer: .number(20))
        XCTAssertEqual(try WiFiEnvelope(metadata: hello).metadata(as: WiFiSayHello.self), hello)
        XCTAssertEqual(hello.pVer?.numericValue, 20)
        let minimal = try WiFiEnvelope(command: .sayHello, json: Data("{\"sn\":\"SYNTHETIC\"}".utf8))
        XCTAssertEqual(try minimal.metadata(as: WiFiSayHello.self), WiFiSayHello(sn: "SYNTHETIC"))
        let stringProtocol = try WiFiEnvelope(command: .sayHello, json: Data("{\"sn\":\"SYNTHETIC\",\"pVer\":\"20\"}".utf8))
        XCTAssertNil(try stringProtocol.metadata(as: WiFiSayHello.self).pVer?.numericValue)
        for json in ["{\"sn\":20}", "{\"sn\":\"s\",\"version\":true}",
                     "{\"sn\":\"s\",\"pVer\":1.5}", "{\"sn\":\"s\",\"pVer\":{}}",
                     "{\"sn\":\"s\",\"pVer\":[]}", "{\"sn\":\"s\",\"token\":null}"] {
            XCTAssertThrowsError(try WiFiEnvelope(command: .sayHello, json: Data(json.utf8)).metadata(as: WiFiSayHello.self))
        }
    }

    func testHelloIdentityMatchesOfficialSerialDigestWithoutConflatingProtocolVersions() throws {
        let serial = "882SYNTHETIC"
        // Independent MD5(UTF-8) vectors for synthetic identifiers only.
        let digest = "152314bcf440f78d369fabb1c8f4e0af"
        for token in [digest, digest.uppercased()] {
            for version: WiFiVersion? in [nil, .number(1), .number(2), .number(20), .string("2"), .signedNumber(-1)] {
                XCTAssertTrue(WiFiSayHello(token: token, pVer: version).matches(serial: serial))
                XCTAssertTrue(WiFiSayHello(sn: serial, token: token, pVer: version).matches(serial: serial))
            }
        }
        XCTAssertTrue(WiFiSayHello(sn: serial).matches(serial: serial))
        XCTAssertFalse(WiFiSayHello().matches(serial: serial))
        XCTAssertFalse(WiFiSayHello(sn: "").matches(serial: serial))
        XCTAssertFalse(WiFiSayHello(sn: "882OTHERDEVICE", token: digest).matches(serial: serial))
        XCTAssertTrue(WiFiSayHello(sn: serial, token: "opaque-owner-token").matches(serial: serial))
        XCTAssertTrue(WiFiSayHello(sn: "", token: digest).matches(serial: serial))
        XCTAssertFalse(WiFiSayHello(token: "64f21dea94ffaadd0743a4e0be694308").matches(serial: serial)) // gitleaks:allow — deliberately wrong synthetic digest
        for token in ["", "opaque", String(repeating: "0", count: 32), " " + digest, digest + " ", String(repeating: "g", count: 32)] {
            XCTAssertFalse(WiFiSayHello(token: token).matches(serial: serial))
        }
        for serial in ["", "882bad\nserial", String(repeating: "A", count: 129)] {
            XCTAssertFalse(WiFiSayHello(sn: serial).matches(serial: serial))
        }
        let raw = try WiFiEnvelope(command: .sayHello, json: Data("{\"token\":\"152314bcf440f78d369fabb1c8f4e0af\",\"pVer\":-1}".utf8), version: 2)
        let hello = try raw.metadata(as: WiFiSayHello.self)
        XCTAssertNil(hello.sn)
        XCTAssertEqual(hello.pVer, .signedNumber(-1))
        XCTAssertTrue(hello.matches(serial: serial))
    }

    func testDownloadAcknowledgmentRequiresSessionAndStatusButTotalMayBeUnspecified() throws {
        for json in ["{\"session\":9,\"status\":0}", "{\"session\":9,\"status\":0,\"total\":0}",
                     "{\"session\":9,\"status\":0,\"total\":4}"] {
            let response = try WiFiEnvelope(command: .download, json: Data(json.utf8)).metadata(as: WiFiDownloadResponse.self)
            XCTAssertEqual(response.session, 9)
            XCTAssertTrue(response.accepted)
        }
        for json in ["{\"status\":0}", "{\"session\":9}", "{\"session\":-1,\"status\":0}",
                     "{\"session\":4294967296,\"status\":0}", "{\"session\":\"9\",\"status\":0}"] {
            XCTAssertThrowsError(try WiFiEnvelope(command: .download, json: Data(json.utf8)).metadata(as: WiFiDownloadResponse.self))
        }
    }

    func testTypedMetadataRejectsWrongCommandBinaryAndFieldRanges() throws {
        let heartbeat = try WiFiEnvelope(metadata: WiFiHeartbeat())
        XCTAssertThrowsError(try heartbeat.metadata(as: WiFiDownloadResponse.self))
        XCTAssertThrowsError(try WiFiEnvelope(metadata: WiFiHeartbeat(), binary: Data([1])))
        XCTAssertThrowsError(try WiFiEnvelope(command: .heartbeat, json: Data("{}".utf8), binary: Data([1])).metadata(as: WiFiHeartbeat.self))
        for json in ["{}", "{\"status\":0,\"session\":9,\"total\":-1}", "{\"status\":0,\"session\":9,\"total\":4294967296}",
                     "{\"status\":false,\"session\":9,\"total\":1}", "{\"status\":0,\"session\":9,\"total\":1.5}"] {
            XCTAssertThrowsError(try WiFiEnvelope(command: .download, json: Data(json.utf8)).metadata(as: WiFiDownloadResponse.self))
        }
        XCTAssertThrowsError(try WiFiEnvelope(metadata: WiFiListRequest(uid: 1, single: 2)))
        XCTAssertThrowsError(try WiFiEnvelope(metadata: WiFiDownloadRequest(session: 1, scene: 1, start: 2, end: 1)))
        XCTAssertThrowsError(try WiFiEnvelope(metadata: WiFiContentMetadata(session: 1, offset: 0, length: 0, last: 2)))
        let raw = try WiFiEnvelope(command: .content, json: Data("{\"session\":1,\"offset\":0,\"length\":0,\"last\":2}".utf8))
        XCTAssertThrowsError(try raw.metadata(as: WiFiContentMetadata.self))
        XCTAssertThrowsError(try WiFiEnvelope(command: .handshake, json: Data("{\"token\":\"short\",\"stamp\":0}".utf8)).metadata(as: WiFiHandshake.self))
    }
}
