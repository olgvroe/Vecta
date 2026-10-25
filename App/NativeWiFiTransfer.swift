import Foundation
import Darwin
import OSLog
import CryptoKit
import NotePinTransport

/// Explicit BLE-to-WiFi handover. Network cleanup is separate from file publication.
@MainActor final class NativeWiFiTransfer {
    enum Failure: Error { case notReady, invalidPeer, rejectedHandshake, changedInventory, timeout, invalidFile, closed }
    private enum Phase { case idle, awaitingHello, handshake, listing, ready, receiving, closing, closed }
    private let driver: NativeBluetoothSession
    private let serial: String
    private let baseline: [ProtocolRecordingFile]
    private let network = NativeWiFiNetworkController()
    private let logger = Logger(subsystem: "app.vecta.mac", category: "FastTransfer")
    private var lease: NativeWiFiNetworkController.Lease?
    private var socket: NativeWiFiSocketServer?
    private var phase = Phase.idle
    private var deadline: Timer?
    private var list: WiFiFileListCollector?
    private let listRequestID = UInt32.random(in: 1...UInt32.max)
    private var files: [UInt32: WiFiRecordingFile] = [:]
    private var transfer: WiFiFileTransferState?
    private var sink: FileHandle?
    private var rawURL: URL?
    private var cleanupTask: Task<String?, Never>?
    private var joinCleanupMessage: String?
    private var lastProgress: TimeInterval = 0
    var onReady: (() -> Void)?
    var onProgress: ((Int, Int) -> Void)?
    var onFileReceived: ((URL) -> Void)?
    var onFailure: ((String) -> Void)?
    var onStatus: ((String) -> Void)?
    var isReady: Bool { phase == .ready }

    init(driver: NativeBluetoothSession, serial: String, baseline: [ProtocolRecordingFile]) {
        self.driver = driver; self.serial = serial; self.baseline = baseline
    }
    func prepare() async throws {
        logger.notice("WiFi preparation started")
        try await network.prepareForFastTransfer()
        logger.notice("WiFi preparation passed")
    }

    func start() async throws {
        guard phase == .idle, driver.canUseWiFi else { throw Failure.notReady }
        try Task.checkCancellation()
        let access: ProtocolWiFiAccessPoint = try await withCheckedThrowingContinuation { continuation in
            driver.openWiFiForTransfer { continuation.resume(with: $0) }
        }
        try Task.checkCancellation()
        logger.notice("Recorder AP acknowledged; directed WiFi join started")
        onStatus?(VL.text("Подключаем Mac к точке доступа PLAUD…"))
        let joined: NativeWiFiNetworkController.Lease
        do { joined = try await network.join(ssidCandidates: access.ssidCandidates, password: access.password) }
        catch {
            if let failure = error as? NativeWiFiNetworkController.Failure {
                joinCleanupMessage = failure.cleanup?.message
                logger.error("WiFi join failed: \(String(describing: failure.reason), privacy: .public)")
            }
            throw error
        }
        lease = joined
        logger.notice("Recorder WiFi association and local IPv4 confirmed")
        try Task.checkCancellation()
        let server = NativeWiFiSocketServer()
        socket = server; phase = .awaitingHello
        server.onReady = { [weak self] in
            self?.logger.notice("WiFi listener ready; awaiting encrypted recorder hello")
            self?.onStatus?(VL.text("Ожидаем защищённое Wi‑Fi-подключение диктофона…"))
        }
        server.onMessage = { [weak self] bytes in self?.receive(bytes) }
        server.onFailure = { [weak self] _ in self?.fail(VL.text("Wi‑Fi-соединение прервалось. Незавершённый файл не добавлен в библиотеку.")) }
        do { try await server.start(localAddress: joined.localIPv4, interfaceName: joined.interfaceName) }
        catch {
            if let failure = error as? NativeWiFiSocketServer.Failure {
                logger.error("WiFi listener startup failed: \(String(describing: failure), privacy: .public)")
            } else {
                logger.error("WiFi listener startup failed")
            }
            throw error
        }
        armDeadline(seconds: 45)
    }
    private func armDeadline(seconds: TimeInterval) {
        deadline?.invalidate()
        deadline = Timer.scheduledTimer(withTimeInterval: seconds, repeats: false) { [weak self] _ in
            Task { @MainActor in self?.fail(VL.text("PLAUD не завершил Wi‑Fi-обмен вовремя. Сохранённые записи не изменены.")) }
        }
    }
    private func send<M: WiFiMetadata>(_ metadata: M) throws {
        let packet = try driver.sealWiFiPDU(WiFiEnvelope(metadata: metadata).encoded())
        guard let socket else { throw Failure.closed }
        socket.send(packet) { [weak self] error in
            if error != nil { self?.fail(VL.text("Не удалось отправить запрос по Wi‑Fi. Записи на диктофоне сохранены.")) }
        }
    }
    private func receive(_ bytes: Data) {
        guard phase != .closing, phase != .closed else { return }
        do {
            // Modern-device traffic must authenticate with this BLE-negotiated key.
            // No ciphertext heuristic or plaintext fallback is used.
            let envelope = try WiFiEnvelope.decode(driver.openWiFiPDU(bytes))
            if envelope.command == .power {
                logger.notice("Recorder battery report ignored in phase \(String(describing: self.phase), privacy: .public)")
                return
            }
            if envelope.command == .heartbeat {
                _ = try envelope.metadata(as: WiFiHeartbeat.self)
                try send(WiFiHeartbeat(stamp: UInt64(Date().timeIntervalSince1970)))
                return
            }
            switch phase {
            case .awaitingHello:
                let hello = try envelope.metadata(as: WiFiSayHello.self)
                guard hello.matches(serial: serial) else { throw Failure.invalidPeer }
                phase = .handshake
                logger.notice("Encrypted recorder hello verified; handshake started")
                try send(WiFiHandshake(token: driver.wifiOwnerToken, stamp: UInt64(Date().timeIntervalSince1970)))
            case .handshake:
                let response = try envelope.metadata(as: WiFiHandshakeResponse.self)
                guard response.accepted else { throw Failure.rejectedHandshake }
                list = try WiFiFileListCollector(expectedUID: listRequestID)
                phase = .listing
                logger.notice("WiFi handshake accepted; inventory requested")
                onStatus?(VL.text("Проверяем список записей по Wi‑Fi…"))
                try send(WiFiListRequest(uid: listRequestID))
                armDeadline(seconds: 45)
            case .listing:
                guard var collector = list else { throw Failure.notReady }
                let complete = try collector.accept(envelope)
                list = collector
                if let complete {
                    guard complete.count == baseline.count else { throw Failure.changedInventory }
                    var snapshot: [UInt32: UInt32] = [:]
                    for file in baseline {
                        guard snapshot.updateValue(file.byteSize, forKey: file.sessionID) == nil else { throw Failure.changedInventory }
                    }
                    var received: [UInt32: WiFiRecordingFile] = [:]
                    for file in complete {
                        guard snapshot[file.session] == file.size, received.updateValue(file, forKey: file.session) == nil else { throw Failure.changedInventory }
                    }
                    files = received; list = nil; phase = .ready; deadline?.invalidate()
                    logger.notice("WiFi inventory verified; transfer ready")
                    onStatus?(VL.text("Fast transfer готов. Передаём записи напрямую на Mac."))
                    onReady?()
                }
                // Continuation-request semantics are unverified. Only accept complete
                // pushed pages; never invent a cursor or publish a partial inventory.
            case .receiving:
                guard var state = transfer, let sink else { throw Failure.notReady }
                if envelope.command == .download {
                    try state.begin(envelope); transfer = state
                } else {
                    let complete = try state.accept(envelope)
                    try sink.write(contentsOf: envelope.binary)
                    transfer = state
                    if complete {
                        try state.finish()
                        try sink.synchronize(); try sink.close(); self.sink = nil
                        guard let rawURL else { throw Failure.invalidFile }
                        self.rawURL = nil; transfer = nil; phase = .ready; deadline?.invalidate()
                        logger.notice("WiFi recording received and byte count verified")
                        onProgress?(Int(state.receivedByteCount), Int(state.expectedSize))
                        onFileReceived?(rawURL)
                    } else {
                        if ProcessInfo.processInfo.systemUptime - lastProgress >= 0.2 {
                            lastProgress = ProcessInfo.processInfo.systemUptime
                            onProgress?(Int(state.receivedByteCount), Int(state.expectedSize))
                        }
                        armDeadline(seconds: 45)
                    }
                }
            case .ready: throw Failure.notReady
            case .idle, .closing, .closed: throw Failure.closed
            }
        } catch {
            let category: String
            if let failure = error as? WiFiProtocolError { category = "envelope-" + String(describing: failure) }
            else if let failure = error as? TransportDecodeError { category = "encrypted-packet-" + String(describing: failure) }
            else if let failure = error as? ProtocolWireError { category = "sequence-" + String(describing: failure) }
            else if error is CryptoKitError { category = "packet-authentication" }
            else if let failure = error as? Failure { category = "peer-state-" + String(describing: failure) }
            else { category = "other" }
            logger.error("WiFi response rejected in phase \(String(describing: self.phase), privacy: .public): \(category, privacy: .public); bytes=\(bytes.count, privacy: .public)")
            fail(VL.text("PLAUD передал несовместимый или неполный Wi‑Fi-ответ. Незавершённая запись не опубликована; файлы на диктофоне не удалялись."))
        }
    }
    func download(_ recording: ProtocolRecordingFile, to destination: URL) throws {
        guard phase == .ready, let file = files[recording.sessionID], file.size == recording.byteSize, file.size > 0 else { throw Failure.notReady }
        let directory = try destination.deletingLastPathComponent().resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
        guard directory.isDirectory == true, directory.isSymbolicLink != true else { throw Failure.invalidFile }
        let descriptor = Darwin.open(destination.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, mode_t(0o600))
        guard descriptor >= 0 else { throw Failure.invalidFile }
        sink = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        rawURL = destination
        transfer = WiFiFileTransferState(expectedSession: file.session, expectedSize: file.size)
        try driver.beginWiFiRecording(recording)
        phase = .receiving
        lastProgress = 0
        onStatus?(VL.text("Передаём запись по Wi‑Fi…"))
        armDeadline(seconds: 45)
        try send(WiFiDownloadRequest(session: file.session, scene: file.scene, start: 0, end: file.size))
    }
    private func fail(_ message: String) {
        guard phase != .closing, phase != .closed else { return }
        logger.error("WiFi transfer stopped in phase \(String(describing: self.phase), privacy: .public)")
        phase = .closing; deadline?.invalidate(); socket?.stop()
        try? sink?.close(); sink = nil; transfer = nil
        onFailure?(message)
    }
    /// Idempotent cleanup is awaited on completion, cancellation and app termination.
    func finish() async -> String? {
        if let cleanupTask { return await cleanupTask.value }
        phase = .closing; deadline?.invalidate(); socket?.stop()
        try? sink?.close(); sink = nil; transfer = nil
        let network = self.network, lease = self.lease, joinCleanupMessage = self.joinCleanupMessage
        let task = Task { @MainActor in
            guard let lease else { return joinCleanupMessage }
            return await network.restore(lease).message
        }
        cleanupTask = task
        let message = await task.value
        driver.closeWiFiAccessPoint()
        self.lease = nil; phase = .closed
        return message
    }
}
