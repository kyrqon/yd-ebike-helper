import Combine
import CoreBluetooth
import Foundation

final class BLEManager: NSObject, ObservableObject {
    @Published private(set) var devices: [DiscoveredDevice] = []
    @Published private(set) var logs: [BLELogEntry] = []
    @Published private(set) var isScanning = false
    @Published private(set) var bluetoothState = "正在初始化蓝牙"
    @Published private(set) var connectedDeviceID: UUID?
    @Published var deviceNamePrefix = "YD"
    @Published var minimumRSSI = -60
    @Published var lastError: String?
    @Published private(set) var authenticationStatus = "尚未认证"

    let isDemoMode: Bool
    let demoScreen: String?

    private var central: CBCentralManager!
    private var peripherals: [UUID: CBPeripheral] = [:]
    private var scanStopWorkItem: DispatchWorkItem?
    private var activePeripheral: CBPeripheral?
    private var activeMACAddress: String?
    private var authReadWriteCharacteristic: CBCharacteristic?
    private var authNotifyCharacteristic: CBCharacteristic?
    private var commandWriteCharacteristic: CBCharacteristic?
    private var commandNotifyCharacteristic: CBCharacteristic?
    private var authenticationStarted = false
    private var authenticationReadScheduled = false
    private var authenticationCompleted = false
    private var authenticationResponseStarted = false
    private var pendingAuthenticationChallenge: Data?
    private var commandNotificationPending = false
    private var authenticationUsesToken = false
    private var v2WriteConfirmed = false
    private var waitingForV2Result = false
    private var v2Result: YadeaV2Handshake.Response?
    private var tokenFetchTask: Task<Void, Never>?
    private var accountChangeObserver: NSObjectProtocol?
    private var activeAuthenticationWriteMode: YDEbikeProtocol.AuthenticationWriteMode = .automatic
    private var connectionAttemptID = UUID()
    private var connectionFailed = false
    private var disconnectRequested = false
    private var stageTimeoutWorkItem: DispatchWorkItem?
    private var connectionStage = "未连接"
    private let lastDiagnosticKey = "yd-last-failed-diagnostic-v1"

    var diagnosticReport: String {
        let current = currentDiagnosticReport
        if !logs.contains(where: { $0.direction == .error }),
            let previous = UserDefaults.standard.string(forKey: lastDiagnosticKey),
            !previous.isEmpty
        {
            return current + "\n\n===== 上次失败记录 =====\n" + previous
        }
        return current
    }

    private var currentDiagnosticReport: String {
        let formatter = ISO8601DateFormatter()
        let version = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "development"
        let build = Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "local"
        let revision = Bundle.main.infoDictionary?["YDSourceRevision"] as? String ?? "local"
        let entries = logs.map { entry in
            let payload = entry.data.map { "\n  HEX: \($0.spacedHex)" } ?? ""
            return "\(formatter.string(from: entry.timestamp)) [\(entry.direction.rawValue)] \(entry.message)\(payload)"
        }
        return ([
            "YD E-Bike Helper / authentication-diagnostics-3",
            "版本：\(version) (\(build))",
            "源码：\(revision)",
            "系统：\(ProcessInfo.processInfo.operatingSystemVersionString)",
            "阶段：\(connectionStage)",
            "认证状态：\(authenticationStatus)",
            "日志包含车辆地址与通信数据，分享前请核对。",
            ""
        ] + entries).joined(separator: "\n")
    }

    private struct PendingWrite {
        let data: Data
        let characteristic: CBCharacteristic
        let label: String
        let completesAuthentication: Bool
        let isSensitive: Bool
    }

    private var writeQueue: [PendingWrite] = []
    private var activeWrite: PendingWrite?
    private var activeWriteRequiresResponse = false

    override init() {
        let arguments = ProcessInfo.processInfo.arguments
        isDemoMode = arguments.contains("--demo-data")
        if let screenIndex = arguments.firstIndex(of: "--demo-screen"),
            arguments.indices.contains(screenIndex + 1)
        {
            demoScreen = arguments[screenIndex + 1]
        } else {
            demoScreen = nil
        }

        super.init()
        accountChangeObserver = NotificationCenter.default.addObserver(
            forName: Notification.Name("YadeaAccountAuthorizationChanged"),
            object: nil,
            queue: .main
        ) { [weak self] _ in
            guard let self, self.authenticationUsesToken, self.activePeripheral != nil else { return }
            self.failConnection("雅迪账号已退出或变更，请重新选择本人绑定车辆后连接。")
        }
        if isDemoMode {
            configureDemoData()
        } else {
            central = CBCentralManager(delegate: self, queue: .main)
        }
    }

    deinit {
        if let accountChangeObserver {
            NotificationCenter.default.removeObserver(accountChangeObserver)
        }
    }

    var demoInitialDeviceID: UUID? {
        guard isDemoMode, demoScreen != nil, demoScreen != "list" else { return nil }
        return devices.first?.id
    }

    var visibleDevices: [DiscoveredDevice] {
        devices.filter { device in
            let prefixMatches = deviceNamePrefix.isEmpty
                || device.name.range(
                    of: deviceNamePrefix,
                    options: [.anchored, .caseInsensitive]
                ) != nil
            return prefixMatches && device.rssi >= minimumRSSI
        }
    }

    var activeDevice: DiscoveredDevice? {
        guard let id = connectedDeviceID else { return nil }
        return devices.first { $0.id == id }
    }

    func savedMACAddress(for id: UUID) -> String {
        UserDefaults.standard.string(forKey: macDefaultsKey(id)) ?? ""
    }

    func preferredMACCandidate(for id: UUID) -> MACAddressCandidate? {
        devices
            .first(where: { $0.id == id })?
            .advertisement
            .macCandidates
            .first(where: { $0.confidence == .high })
    }

    func systemMACAddress(for id: UUID) -> String? {
        devices
            .first(where: { $0.id == id })?
            .advertisement
            .systemAddress
    }

    func saveMACAddress(_ address: String, for id: UUID) throws -> String {
        let normalized = try YDEbikeProtocol.normalizedMAC(address)
        UserDefaults.standard.set(normalized, forKey: macDefaultsKey(id))
        return normalized
    }

    func refreshScan() {
        if isDemoMode {
            configureDemoData()
            return
        }

        if let peripheral = activePeripheral {
            disconnectRequested = true
            resetProtocolState()
            authenticationStatus = "正在断开以重新扫描"
            updatePhase(.disconnecting, for: peripheral.identifier)
            central.cancelPeripheralConnection(peripheral)
        }
        devices.removeAll()
        peripherals.removeAll()
        startScan()
    }

    func startScan() {
        if isDemoMode {
            isScanning = true
            appendLog(.system, "开始扫描 BLE 设备（演示数据）")
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.6) { [weak self] in
                guard let self else { return }
                self.isScanning = false
                self.appendLog(.system, "扫描结束，发现 \(self.visibleDevices.count) 个匹配设备")
            }
            return
        }

        guard central.state == .poweredOn else {
            lastError = bluetoothState
            appendLog(.error, "无法扫描：\(bluetoothState)")
            return
        }

        scanStopWorkItem?.cancel()
        isScanning = true
        lastError = nil
        appendLog(.system, "开始扫描 BLE 设备（5 秒）")
        central.scanForPeripherals(
            withServices: nil,
            options: [CBCentralManagerScanOptionAllowDuplicatesKey: true]
        )

        let workItem = DispatchWorkItem { [weak self] in
            self?.stopScan()
        }
        scanStopWorkItem = workItem
        DispatchQueue.main.asyncAfter(deadline: .now() + 5, execute: workItem)
    }

    func stopScan() {
        if isDemoMode {
            isScanning = false
            return
        }

        scanStopWorkItem?.cancel()
        scanStopWorkItem = nil
        if isScanning {
            central.stopScan()
            isScanning = false
            appendLog(.system, "扫描结束，发现 \(visibleDevices.count) 个匹配设备")
        }
    }

    func connect(
        to id: UUID,
        macAddress: String,
        writeMode: YDEbikeProtocol.AuthenticationWriteMode = .automatic
    ) {
        if isDemoMode {
            do {
                let bestAddress = try ConnectionMACSelection.resolve(
                    userInput: macAddress,
                    systemAddress: systemMACAddress(for: id),
                    preferredCandidate: preferredMACCandidate(for: id)?.address
                )
                activeMACAddress = try saveMACAddress(bestAddress, for: id)
            } catch {
                reportError(error.localizedDescription)
                return
            }

            connectedDeviceID = id
            updatePhase(.ready, for: id)
            appendDemoAuthenticationLog(for: id)
            return
        }

        guard central.state == .poweredOn else {
            reportError(bluetoothState)
            return
        }
        guard activePeripheral == nil else {
            reportError("上次连接尚未断开，请等待断开完成后重试。")
            return
        }
        guard let peripheral = peripherals[id] else {
            reportError("设备已离开扫描范围，请刷新后重试。")
            return
        }

        do {
            let bestAddress = try ConnectionMACSelection.resolve(
                userInput: macAddress,
                systemAddress: systemMACAddress(for: id),
                preferredCandidate: preferredMACCandidate(for: id)?.address
            )
            activeMACAddress = try saveMACAddress(bestAddress, for: id)
        } catch {
            reportError(error.localizedDescription)
            return
        }

        stopScan()
        resetProtocolState()
        connectionAttemptID = UUID()
        connectionFailed = false
        disconnectRequested = false
        lastError = nil
        authenticationStatus = "等待建立蓝牙连接"
        activeAuthenticationWriteMode = writeMode
        activePeripheral = peripheral
        connectedDeviceID = id
        updatePhase(.connecting, for: id)
        appendLog(.system, "连接 \(displayName(for: peripheral))，认证 MAC \(activeMACAddress ?? "")")
        appendLog(.system, "认证写入方式：\(writeMode.title)；以本次输入的 MAC 为准")
        setStage("建立蓝牙连接", timeout: 20)
        central.connect(peripheral, options: nil)
    }

    func disconnect() {
        if isDemoMode {
            guard let id = connectedDeviceID else { return }
            updatePhase(.discovered, for: id)
            appendLog(.system, "已断开 \(devices.first(where: { $0.id == id })?.name ?? "演示车辆")")
            connectedDeviceID = nil
            activeMACAddress = nil
            return
        }

        guard let peripheral = activePeripheral else { return }
        disconnectRequested = true
        resetProtocolState()
        authenticationStatus = "正在断开"
        updatePhase(.disconnecting, for: peripheral.identifier)
        appendLog(.system, "正在断开 \(displayName(for: peripheral))")
        central.cancelPeripheralConnection(peripheral)
    }

    func sendDebugCommand() {
        unlockPower()
    }

    func sendRestoreCommand() {
        restorePowerLock()
    }

    func unlockPower() {
        sendCommand(YDEbikeProtocol.debugPacket(), label: "解除动力锁定")
    }

    func restorePowerLock() {
        sendCommand(YDEbikeProtocol.restorePacket(), label: "恢复动力锁定")
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.2) { [weak self] in
            self?.sendCommand(YDEbikeProtocol.volumePacket(level: 4), label: "恢复后音量 4")
        }
    }

    func sendVolume(_ level: Int) {
        sendCommand(YDEbikeProtocol.volumePacket(level: level), label: "音量 \(level)")
    }

    func sendCustomHex(_ input: String) {
        do {
            sendCommand(try YDEbikeProtocol.parseHex(input), label: "自定义 HEX")
        } catch {
            reportError(error.localizedDescription)
        }
    }

    func clearLogs() {
        logs.removeAll()
        UserDefaults.standard.removeObject(forKey: lastDiagnosticKey)
    }

    private func sendCommand(_ data: Data, label: String) {
        if isDemoMode {
            appendLog(.sent, label, data: data)
            appendLog(.received, "车辆响应", data: Data([0x5A, 0x96, 0x01]))
            appendLog(.system, "设备返回：操作成功")
            return
        }

        guard authenticationCompleted,
            activeDevice?.phase == .ready,
            let characteristic = commandWriteCharacteristic
        else {
            reportError("设备尚未完成认证，不能发送指令。")
            return
        }
        enqueueWrite(data, to: characteristic, label: label)
    }

    private func beginAuthenticationIfPossible() {
        guard
            !authenticationStarted,
            let peripheral = activePeripheral,
            let readWrite = authReadWriteCharacteristic,
            authNotifyCharacteristic != nil,
            commandWriteCharacteristic != nil
        else {
            return
        }

        authenticationStarted = true
        updatePhase(.authenticating, for: peripheral.identifier)
        authenticationStatus = "准备读取车辆认证能力"
        appendLog(.system, "服务已就绪：先读取挑战值，认证前不订阅命令通知")
        scheduleAuthenticationRead(peripheral: peripheral, characteristic: readWrite)
    }

    private func configureDemoData() {
        let primaryID = UUID(uuidString: "0DD1768C-BB0D-61D3-1B32-FE98D69F033A")!
        let secondaryID = UUID(uuidString: "90A4B532-571D-4D54-886E-11D2863C3118")!
        let readyScreens = ["list", "controls", "logs"]
        let primaryIsReady = readyScreens.contains(demoScreen ?? "")

        let primaryAdvertisement = BLEAdvertisementSnapshot(
            localName: "YD5C034643",
            manufacturerData: Data([
                0xFF, 0xFF, 0xC1, 0x28, 0x5C, 0x03, 0x46, 0x43,
                0x25, 0xFF, 0xFF, 0xFF, 0x03, 0xFF,
            ]),
            serviceData: [:],
            txPower: -8,
            isConnectable: true,
            solicitedServices: [],
            overflowServices: []
        )
        let secondaryAdvertisement = BLEAdvertisementSnapshot(
            localName: "YD7A24B109",
            manufacturerData: Data([0xFF, 0xFF, 0xD8, 0x42, 0x7A, 0x24, 0xB1, 0x09]),
            serviceData: [:],
            txPower: -12,
            isConnectable: true,
            solicitedServices: [],
            overflowServices: []
        )

        devices = [
            DiscoveredDevice(
                id: primaryID,
                name: "YD5C034643",
                rssi: -42,
                phase: primaryIsReady ? .ready : .discovered,
                lastSeen: Date(),
                advertisedServices: [
                    YDEbikeProtocol.authenticationService,
                    YDEbikeProtocol.commandService,
                ],
                advertisement: primaryAdvertisement
            ),
            DiscoveredDevice(
                id: secondaryID,
                name: "YD7A24B109",
                rssi: -55,
                phase: .discovered,
                lastSeen: Date().addingTimeInterval(-1.2),
                advertisedServices: [YDEbikeProtocol.authenticationService],
                advertisement: secondaryAdvertisement
            ),
        ]
        logs.removeAll()
        bluetoothState = "蓝牙已开启"
        isScanning = false
        lastError = nil
        connectedDeviceID = primaryIsReady ? primaryID : nil
        activeMACAddress = primaryIsReady ? "C1:28:5C:03:46:43" : nil

        appendLog(.system, "蓝牙已开启")
        appendLog(.system, "扫描结束，发现 2 个匹配设备")
        if primaryIsReady {
            appendDemoAuthenticationLog(for: primaryID)
            appendLog(.sent, "解除动力锁定", data: YDEbikeProtocol.debugPacket())
            appendLog(.received, "车辆响应", data: Data([0x5A, 0x96, 0x01]))
            appendLog(.system, "设备返回：操作成功")
        }
    }

    private func appendDemoAuthenticationLog(for id: UUID) {
        let name = devices.first(where: { $0.id == id })?.name ?? "YD 车辆"
        appendLog(.system, "连接 \(name)，认证 MAC \(activeMACAddress ?? "C1:28:5C:03:46:43")")
        appendLog(.system, "已连接 \(name)，开始发现 GATT 服务")
        appendLog(.system, "发现 2 个目标服务")
        appendLog(.system, "服务已就绪，先订阅认证通知")
        appendLog(.received, "读取认证挑战值", data: Data([
            0xE1, 0xCA, 0xC4, 0x2A, 0xB3, 0xFE, 0xF8, 0xC8,
            0x63, 0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xDA,
        ]))
        appendLog(.sent, "认证响应", data: Data([
            0xF1, 0xCE, 0xE5, 0x30, 0xE6, 0xB9, 0xF2,
            0x88, 0xA6, 0x41, 0x05, 0x01, 0x10, 0x55,
        ]))
        appendLog(.system, "认证响应已写入，设备可开始调试")
    }

    private func scheduleAuthenticationRead(
        peripheral: CBPeripheral,
        characteristic: CBCharacteristic
    ) {
        guard !authenticationReadScheduled else { return }
        guard characteristic.properties.contains(.read) else {
            failConnection("认证特征不支持 Read，不能读取挑战值。")
            return
        }
        authenticationReadScheduled = true
        setStage("读取认证挑战值", timeout: 8)
        appendLog(.system, "发现特征后等待 400 ms，再读取挑战值；尚未请求任何通知订阅")
        let attemptID = connectionAttemptID

        DispatchQueue.main.asyncAfter(deadline: .now() + 0.4) { [weak self, weak peripheral] in
            guard
                let self,
                let peripheral,
                self.activePeripheral === peripheral,
                self.connectionAttemptID == attemptID,
                !self.connectionFailed,
                !self.disconnectRequested
            else {
                return
            }

            self.authenticationStatus = "正在读取车辆认证能力"
            self.appendLog(.system, "请求读取认证挑战值：\(characteristic.uuid.uuidString)")
            peripheral.readValue(for: characteristic)
        }
    }

    private func prepareAuthentication(challenge: Data) {
        guard pendingAuthenticationChallenge == nil, !authenticationResponseStarted,
            let peripheral = activePeripheral,
            let notify = authNotifyCharacteristic
        else { return }
        setStage("识别认证能力")
        do {
            let profile = try YDEbikeProtocol.authenticationProfile(challenge: challenge)
            appendLog(.system, "读取成功，认证能力：\(profile.diagnosticDescription)")
            if profile.flow == .tokenV2 {
                authenticationUsesToken = true
                appendLog(.system, "采用 V2 Token 握手：需要已登录账号及匹配的本人绑定车辆")
            } else {
                _ = try YDEbikeProtocol.requireLegacyAuthentication(challenge: challenge)
            }
            pendingAuthenticationChallenge = challenge
            setStage("订阅认证通知", timeout: 8)
            authenticationStatus = "挑战值已读取，等待认证通知订阅确认"
            if notify.isNotifying {
                appendLog(.system, "认证通知已启用，继续生成应答")
                authenticate(challenge: challenge)
            } else if notify.properties.contains(.notify) || notify.properties.contains(.indicate) {
                appendLog(.system, "请求订阅认证通知：\(notify.uuid.uuidString)")
                peripheral.setNotifyValue(true, for: notify)
            } else {
                failConnection("认证通知特征不支持 Notify/Indicate。")
            }
        } catch {
            failConnection(error.localizedDescription)
        }
    }

    private func authenticate(challenge: Data) {
        guard !authenticationResponseStarted,
            pendingAuthenticationChallenge == challenge,
            authNotifyCharacteristic?.isNotifying == true
        else { return }
        authenticationResponseStarted = true
        pendingAuthenticationChallenge = nil
        guard
            activePeripheral != nil,
            let macAddress = activeMACAddress,
            let characteristic = authReadWriteCharacteristic
        else {
            reportError("认证上下文不完整。")
            return
        }

        do {
            let profile = try YDEbikeProtocol.authenticationProfile(challenge: challenge)
            appendLog(.system, "认证能力：\(profile.diagnosticDescription)")
            if authenticationUsesToken {
                fetchTokenAndAuthenticate(challenge: challenge, macAddress: macAddress)
                return
            }
            let packet = try YDEbikeProtocol.authenticationPacket(
                challenge: challenge,
                macAddress: macAddress
            )
            enqueueWrite(
                packet,
                to: characteristic,
                label: "认证响应",
                completesAuthentication: true
            )
            appendLog(.system, "已生成认证响应")
        } catch {
            failConnection(error.localizedDescription)
        }
    }

    private func fetchTokenAndAuthenticate(challenge: Data, macAddress: String) {
        setStage("获取本人车辆 V2 授权", timeout: 35)
        authenticationStatus = "正在获取所选本人绑定车辆的蓝牙授权"
        let attemptID = connectionAttemptID
        tokenFetchTask = Task { @MainActor [weak self] in
            guard let self else { return }
            do {
                let credentials = try await YadeaAccount.shared.credentials(for: macAddress)
                try Task.checkCancellation()
                guard self.connectionAttemptID == attemptID,
                    self.activePeripheral != nil,
                    !self.connectionFailed,
                    !self.disconnectRequested,
                    let characteristic = self.authReadWriteCharacteristic
                else { return }
                // The account layer has checked that the selected bound vehicle
                // matches this connection MAC. No token or plaintext enters logs.
                let packet = try YadeaV2Handshake.encryptedPacket(
                    dkInfo: credentials.tokenHex,
                    challenge: challenge,
                    macAddress: credentials.macAddress,
                    roles: credentials.roles,
                    protocolVersion: credentials.protocolVersion
                )
                self.appendLog(.system, "本人车辆授权已获取，V2 应答已生成（授权材料与密文不写入日志）")
                self.waitingForV2Result = true
                self.v2WriteConfirmed = false
                self.v2Result = nil
                self.enqueueWrite(
                    packet,
                    to: characteristic,
                    label: "V2 认证响应",
                    completesAuthentication: true,
                    isSensitive: true
                )
            } catch {
                guard self.connectionAttemptID == attemptID,
                    self.activePeripheral != nil,
                    !self.connectionFailed,
                    !self.disconnectRequested,
                    !(error is CancellationError)
                else { return }
                self.failConnection(error.localizedDescription)
            }
        }
    }

    private func receiveV2AuthenticationResult(_ data: Data) {
        guard authenticationUsesToken, waitingForV2Result else { return }
        do {
            let response = try YadeaV2Handshake.response(data)
            appendLog(.system, "V2 车端结果：result=\(response.result)，remaining=\(response.remainingUses)")
            guard response.success else {
                failConnection("车辆未通过 V2 认证（结果码 \(response.result)），未开放控制。")
                return
            }
            v2Result = response
            completeV2AuthenticationIfPossible()
        } catch {
            failConnection("无法解析 V2 认证结果：\(error.localizedDescription)")
        }
    }

    private func completeV2AuthenticationIfPossible() {
        guard authenticationUsesToken, waitingForV2Result,
            v2WriteConfirmed, v2Result?.success == true,
            let peripheral = activePeripheral
        else { return }
        waitingForV2Result = false
        authenticationCompleted = true
        authenticationStatus = "车辆已确认 V2 认证成功，正在准备命令通知"
        appendLog(.system, authenticationStatus)
        subscribeCommandNotifications(peripheral: peripheral)
    }

    private func enqueueWrite(
        _ data: Data,
        to characteristic: CBCharacteristic,
        label: String,
        completesAuthentication: Bool = false,
        isSensitive: Bool = false
    ) {
        writeQueue.append(
            PendingWrite(
                data: data,
                characteristic: characteristic,
                label: label,
                completesAuthentication: completesAuthentication,
                isSensitive: isSensitive
            )
        )
        drainWriteQueue()
    }

    private func drainWriteQueue() {
        guard
            activeWrite == nil,
            !writeQueue.isEmpty,
            let peripheral = activePeripheral
        else {
            return
        }

        let next = writeQueue.removeFirst()
        let properties = next.characteristic.properties
        let usesResponse: Bool?
        if next.completesAuthentication && authenticationUsesToken {
            usesResponse = activeAuthenticationWriteMode != .withoutResponse
                && properties.contains(.write) ? true : nil
        } else if next.completesAuthentication {
            usesResponse = AuthenticationWriteSelection.usesResponse(
                mode: activeAuthenticationWriteMode,
                supportsResponse: properties.contains(.write),
                supportsWithoutResponse: properties.contains(.writeWithoutResponse)
            )
        } else {
            usesResponse = properties.contains(.write) ? true
                : (properties.contains(.writeWithoutResponse) ? false : nil)
        }
        guard let usesResponse else {
            let message = "\(next.label)：特征不支持所选写入方式（properties=0x\(String(properties.rawValue, radix: 16))）。"
            if next.completesAuthentication { failConnection(message) }
            else { reportError(message); drainWriteQueue() }
            return
        }
        let writeType: CBCharacteristicWriteType = usesResponse ? .withResponse : .withoutResponse
        let maximum = peripheral.maximumWriteValueLength(for: writeType)
        guard next.data.count <= maximum else {
            let message = "\(next.label) 共 \(next.data.count) 字节，超过当前链路单次写入上限 \(maximum) 字节。"
            if next.completesAuthentication { failConnection(message) }
            else { reportError(message); drainWriteQueue() }
            return
        }

        if !usesResponse && !peripheral.canSendWriteWithoutResponse {
            writeQueue.insert(next, at: 0)
            setStage("等待蓝牙写入队列", timeout: 8)
            return
        }
        activeWrite = next
        activeWriteRequiresResponse = usesResponse
        setStage(next.completesAuthentication ? "写入认证应答" : "写入\(next.label)", timeout: 8)
        appendLog(.system, "\(next.label)使用 \(usesResponse ? "Write Request" : "Write Without Response")")
        appendLog(
            .sent,
            next.isSensitive ? "\(next.label)，\(next.data.count) 字节（内容已隐藏）" : next.label,
            data: next.isSensitive ? nil : next.data
        )
        peripheral.writeValue(next.data, for: next.characteristic, type: writeType)

        if writeType == .withoutResponse {
            finishActiveWrite(error: nil)
        }
    }

    private func finishActiveWrite(error: Error?) {
        guard let write = activeWrite else { return }
        let requiresResponse = activeWriteRequiresResponse
        activeWrite = nil
        stageTimeoutWorkItem?.cancel()
        stageTimeoutWorkItem = nil

        if let error {
            let message = "\(write.label)写入失败：\(errorDescription(error))"
            if write.completesAuthentication { failConnection(message) }
            else { reportError(message) }
        } else {
            appendLog(.system, requiresResponse
                ? "\(write.label)已获得 GATT 写确认；不等于车辆业务认证成功"
                : "\(write.label)已提交蓝牙发送队列；Write Without Response 没有车端写确认")
            if write.completesAuthentication, let peripheral = activePeripheral {
                if authenticationUsesToken {
                    v2WriteConfirmed = true
                    authenticationStatus = "V2 应答写入已确认，等待车辆认证结果"
                    setStage("等待 V2 认证结果", timeout: 8)
                    completeV2AuthenticationIfPossible()
                } else {
                    authenticationCompleted = true
                    authenticationStatus = "旧版应答已提交，正在准备命令通知"
                    appendLog(.system, authenticationStatus)
                    subscribeCommandNotifications(peripheral: peripheral)
                }
            }
        }
        drainWriteQueue()
    }

    private func subscribeCommandNotifications(peripheral: CBPeripheral) {
        guard let notify = commandNotifyCharacteristic else {
            failConnection("命令服务缺少通知特征，无法观察后续命令结果。")
            return
        }
        commandNotificationPending = true
        setStage("订阅命令通知", timeout: 8)
        if notify.isNotifying {
            finishConnectionSetup()
        } else if notify.properties.contains(.notify) || notify.properties.contains(.indicate) {
            appendLog(.system, "认证应答提交后，请求订阅命令通知：\(notify.uuid.uuidString)")
            peripheral.setNotifyValue(true, for: notify)
        } else {
            failConnection("命令通知特征不支持 Notify/Indicate。")
        }
    }

    private func finishConnectionSetup() {
        guard authenticationCompleted, commandNotificationPending,
            commandNotifyCharacteristic?.isNotifying == true,
            let peripheral = activePeripheral
        else { return }
        commandNotificationPending = false
        authenticationStatus = authenticationUsesToken
            ? "V2 车端认证成功，通知已就绪"
            : "旧版应答及通知已就绪，车端认证结果尚未验证"
        setStage(authenticationUsesToken ? "V2 认证及通知已就绪" : "旧版应答及通知已就绪")
        updatePhase(.ready, for: peripheral.identifier)
        appendLog(.system, authenticationStatus)
    }

    private func resetProtocolState() {
        tokenFetchTask?.cancel()
        tokenFetchTask = nil
        stageTimeoutWorkItem?.cancel()
        stageTimeoutWorkItem = nil
        authReadWriteCharacteristic = nil
        authNotifyCharacteristic = nil
        commandWriteCharacteristic = nil
        commandNotifyCharacteristic = nil
        authenticationStarted = false
        authenticationReadScheduled = false
        authenticationCompleted = false
        authenticationResponseStarted = false
        pendingAuthenticationChallenge = nil
        commandNotificationPending = false
        authenticationUsesToken = false
        v2WriteConfirmed = false
        waitingForV2Result = false
        v2Result = nil
        writeQueue.removeAll()
        activeWrite = nil
    }

    private func setStage(_ stage: String, timeout: TimeInterval? = nil) {
        stageTimeoutWorkItem?.cancel()
        stageTimeoutWorkItem = nil
        connectionStage = stage
        appendLog(.system, "阶段：\(stage)")
        guard let timeout else { return }
        let attemptID = connectionAttemptID
        let workItem = DispatchWorkItem { [weak self] in
            guard let self,
                self.connectionAttemptID == attemptID,
                self.activePeripheral != nil,
                !self.connectionFailed,
                !self.disconnectRequested
            else { return }
            self.failConnection("等待「\(stage)」超过 \(Int(timeout)) 秒，已断开。")
        }
        stageTimeoutWorkItem = workItem
        DispatchQueue.main.asyncAfter(deadline: .now() + timeout, execute: workItem)
    }

    private func failConnection(_ message: String) {
        connectionFailed = true
        authenticationStatus = "失败阶段：\(connectionStage)"
        reportError("[\(connectionStage)] \(message)")
        resetProtocolState()
        if let peripheral = activePeripheral {
            updatePhase(.failed, for: peripheral.identifier)
            central.cancelPeripheralConnection(peripheral)
        }
    }

    private func acceptsCallbacks(from peripheral: CBPeripheral) -> Bool {
        activePeripheral === peripheral && !connectionFailed && !disconnectRequested
    }

    private func updateDevice(
        id: UUID,
        name: String,
        rssi: Int,
        advertisedServices: [String],
        advertisement: BLEAdvertisementSnapshot
    ) {
        if let index = devices.firstIndex(where: { $0.id == id }) {
            devices[index].name = name
            devices[index].rssi = rssi
            devices[index].lastSeen = Date()
            devices[index].advertisedServices = Array(
                Set(devices[index].advertisedServices + advertisedServices)
            ).sorted()
            devices[index].advertisement = devices[index].advertisement.merging(advertisement)
        } else {
            devices.append(
                DiscoveredDevice(
                    id: id,
                    name: name,
                    rssi: rssi,
                    phase: .discovered,
                    lastSeen: Date(),
                    advertisedServices: advertisedServices,
                    advertisement: advertisement
                )
            )
        }

        devices.sort { lhs, rhs in
            if lhs.isConnected != rhs.isConnected {
                return lhs.isConnected
            }
            return lhs.rssi > rhs.rssi
        }
        if devices.count > 50 {
            devices.removeLast(devices.count - 50)
        }
    }

    private func updateSystemAddress(_ address: String, for id: UUID) {
        guard let index = devices.firstIndex(where: { $0.id == id }) else { return }
        let addressUpdate = BLEAdvertisementSnapshot(
            localName: nil,
            systemAddress: address,
            manufacturerData: nil,
            serviceData: [:],
            txPower: nil,
            isConnectable: nil,
            solicitedServices: [],
            overflowServices: []
        )
        devices[index].advertisement = devices[index].advertisement.merging(addressUpdate)
        devices = devices
    }

    private func updatePhase(_ phase: DeviceConnectionPhase, for id: UUID) {
        guard let index = devices.firstIndex(where: { $0.id == id }) else { return }
        devices[index].phase = phase
        devices = devices
    }

    private func displayName(for peripheral: CBPeripheral) -> String {
        peripheral.name ?? devices.first(where: { $0.id == peripheral.identifier })?.name ?? "未知设备"
    }

    private func macDefaultsKey(_ id: UUID) -> String {
        "yd-device-mac-\(id.uuidString)"
    }

    private func appendLog(
        _ direction: BLELogDirection,
        _ message: String,
        data: Data? = nil
    ) {
        logs.append(
            BLELogEntry(
                timestamp: Date(),
                direction: direction,
                message: message,
                data: data
            )
        )
        if logs.count > 500 {
            logs.removeFirst(logs.count - 500)
        }
    }

    private func reportError(_ message: String) {
        lastError = message
        appendLog(.error, message)
        UserDefaults.standard.set(currentDiagnosticReport, forKey: lastDiagnosticKey)
    }

    private func errorDescription(_ error: Error) -> String {
        let nsError = error as NSError
        let reason = nsError.localizedFailureReason.map { "；\($0)" } ?? ""
        let underlying = (nsError.userInfo[NSUnderlyingErrorKey] as? NSError)
            .map { "；底层 \($0.domain):\($0.code) \($0.localizedDescription)" } ?? ""
        return "\(error.localizedDescription) [\(nsError.domain):\(nsError.code)]\(reason)\(underlying)"
    }
}

extension BLEManager: CBCentralManagerDelegate {
    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        if central.state != .poweredOn {
            if activePeripheral != nil && !disconnectRequested {
                authenticationStatus = "蓝牙状态变化，连接已失效"
                reportError("[\(connectionStage)] 蓝牙连接不可用，请恢复蓝牙后重新扫描。")
            }
            connectionAttemptID = UUID()
            resetProtocolState()
            scanStopWorkItem?.cancel()
            scanStopWorkItem = nil
            activePeripheral = nil
            connectedDeviceID = nil
            activeMACAddress = nil
            peripherals.removeAll()
            devices.removeAll()
            isScanning = false
        }
        switch central.state {
        case .poweredOn:
            bluetoothState = "蓝牙已开启"
            appendLog(.system, bluetoothState)
            if devices.isEmpty, !isScanning {
                startScan()
            }
        case .poweredOff:
            bluetoothState = "蓝牙已关闭"
            isScanning = false
            appendLog(.error, bluetoothState)
        case .unauthorized:
            bluetoothState = "没有蓝牙权限"
            #if os(iOS)
            reportError("请在“设置 → 隐私与安全性 → 蓝牙”中允许本应用访问蓝牙。")
            #else
            reportError("请在“系统设置 → 隐私与安全性 → 蓝牙”中允许本应用访问蓝牙。")
            #endif
        case .unsupported:
            bluetoothState = "此设备不支持 BLE"
            appendLog(.error, bluetoothState)
        case .resetting:
            bluetoothState = "蓝牙正在重置"
        case .unknown:
            bluetoothState = "蓝牙状态未知"
        @unknown default:
            bluetoothState = "未知蓝牙状态"
        }
    }

    func centralManager(
        _ central: CBCentralManager,
        didDiscover peripheral: CBPeripheral,
        advertisementData: [String: Any],
        rssi RSSI: NSNumber
    ) {
        guard RSSI.intValue != 127 else { return }
        let localName = advertisementData[CBAdvertisementDataLocalNameKey] as? String
        let name = localName ?? peripheral.name ?? "未命名设备"
        let services = (advertisementData[CBAdvertisementDataServiceUUIDsKey] as? [CBUUID] ?? [])
            .map(\.uuidString)
        let serviceData = (advertisementData[CBAdvertisementDataServiceDataKey] as? [CBUUID: Data] ?? [:])
            .reduce(into: [String: Data]()) { result, item in
                result[item.key.uuidString] = item.value
            }
        let advertisement = BLEAdvertisementSnapshot(
            localName: localName,
            systemAddress: PeripheralAddressResolver.address(for: peripheral),
            manufacturerData: advertisementData[CBAdvertisementDataManufacturerDataKey] as? Data,
            serviceData: serviceData,
            txPower: (advertisementData[CBAdvertisementDataTxPowerLevelKey] as? NSNumber)?.intValue,
            isConnectable: (advertisementData[CBAdvertisementDataIsConnectable] as? NSNumber)?.boolValue,
            solicitedServices: (
                advertisementData[CBAdvertisementDataSolicitedServiceUUIDsKey] as? [CBUUID] ?? []
            ).map(\.uuidString),
            overflowServices: (
                advertisementData[CBAdvertisementDataOverflowServiceUUIDsKey] as? [CBUUID] ?? []
            ).map(\.uuidString)
        )
        peripherals[peripheral.identifier] = peripheral
        updateDevice(
            id: peripheral.identifier,
            name: name,
            rssi: RSSI.intValue,
            advertisedServices: services,
            advertisement: advertisement
        )
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        guard acceptsCallbacks(from: peripheral) else {
            central.cancelPeripheralConnection(peripheral)
            return
        }
        if let systemAddress = PeripheralAddressResolver.address(for: peripheral) {
            updateSystemAddress(systemAddress, for: peripheral.identifier)
            appendLog(
                .system,
                "系统读取到 BDAddress \(systemAddress)；保留本次输入的认证 MAC \(activeMACAddress ?? "")"
            )
        } else {
            appendLog(
                .system,
                "当前系统未提供 BDAddress，继续使用 \(activeMACAddress ?? "手动地址")"
            )
        }
        appendLog(.system, "已连接 \(displayName(for: peripheral))，开始发现 GATT 服务")
        updatePhase(.discovering, for: peripheral.identifier)
        authenticationStatus = "蓝牙已连接，正在发现认证服务"
        setStage("发现 GATT 服务与特征", timeout: 10)
        peripheral.delegate = self
        peripheral.discoverServices([
            CBUUID(string: YDEbikeProtocol.authenticationService),
            CBUUID(string: YDEbikeProtocol.commandService)
        ])
    }

    func centralManager(
        _ central: CBCentralManager,
        didFailToConnect peripheral: CBPeripheral,
        error: Error?
    ) {
        guard activePeripheral === peripheral else { return }
        connectionFailed = true
        authenticationStatus = "蓝牙连接失败"
        updatePhase(.failed, for: peripheral.identifier)
        reportError(
            "[\(connectionStage)] 连接失败：\(error.map(errorDescription) ?? "请将设备重新上电后重试")"
        )
        activePeripheral = nil
        connectedDeviceID = nil
        resetProtocolState()
    }

    func centralManager(
        _ central: CBCentralManager,
        didDisconnectPeripheral peripheral: CBPeripheral,
        error: Error?
    ) {
        guard activePeripheral === peripheral else { return }
        let disconnectedDuringAuthentication = authenticationStarted && !authenticationCompleted
        let unexpected = !disconnectRequested && !connectionFailed
        updatePhase(connectionFailed || unexpected ? .failed : .discovered, for: peripheral.identifier)
        appendLog(
            error == nil ? .system : .error,
            error == nil
                ? "已断开 \(displayName(for: peripheral))"
                : "连接中断：\(errorDescription(error!))"
        )
        if disconnectedDuringAuthentication {
            appendLog(
                .error,
                "认证完成前断线，最后阶段：\(connectionStage)。请导出日志以区分读取挑战值、订阅通知与写入应答。"
            )
        }
        if unexpected {
            authenticationStatus = "连接已中断，最后阶段：\(connectionStage)"
            reportError("[\(connectionStage)] 连接中断：\(error.map(errorDescription) ?? "车辆关闭了连接，系统未提供原因")")
        } else if disconnectRequested {
            authenticationStatus = "已断开"
        }
        activePeripheral = nil
        connectedDeviceID = nil
        activeMACAddress = nil
        resetProtocolState()
    }
}

extension BLEManager: CBPeripheralDelegate {
    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        guard acceptsCallbacks(from: peripheral) else { return }
        if let error {
            failConnection("发现服务失败：\(errorDescription(error))")
            return
        }

        let services = peripheral.services ?? []
        appendLog(.system, "发现 \(services.count) 个目标服务")
        let found = Set(services.map { $0.uuid.uuidString.uppercased() })
        let required = [YDEbikeProtocol.authenticationService, YDEbikeProtocol.commandService]
        guard required.allSatisfy({ found.contains($0) }) else {
            failConnection("缺少本协议所需服务；实际返回：\(found.sorted().joined(separator: ", "))")
            return
        }
        for service in services {
            appendLog(.system, "服务 \(service.uuid.uuidString)")
            switch service.uuid.uuidString.uppercased() {
            case YDEbikeProtocol.authenticationService:
                peripheral.discoverCharacteristics([
                    CBUUID(string: YDEbikeProtocol.authenticationReadWriteCharacteristic),
                    CBUUID(string: YDEbikeProtocol.authenticationNotifyCharacteristic)
                ], for: service)
            case YDEbikeProtocol.commandService:
                peripheral.discoverCharacteristics([
                    CBUUID(string: YDEbikeProtocol.commandWriteCharacteristic),
                    CBUUID(string: YDEbikeProtocol.commandNotifyCharacteristic)
                ], for: service)
            default:
                continue
            }
        }
    }

    func peripheral(
        _ peripheral: CBPeripheral,
        didDiscoverCharacteristicsFor service: CBService,
        error: Error?
    ) {
        guard acceptsCallbacks(from: peripheral) else { return }
        if let error {
            failConnection("发现特征失败：\(errorDescription(error))")
            return
        }

        for characteristic in service.characteristics ?? [] {
            appendLog(.system, "特征 \(characteristic.uuid.uuidString)，properties=0x\(String(characteristic.properties.rawValue, radix: 16)) \(characteristicProperties(characteristic.properties))")
            switch characteristic.uuid.uuidString.uppercased() {
            case YDEbikeProtocol.authenticationReadWriteCharacteristic:
                authReadWriteCharacteristic = characteristic
            case YDEbikeProtocol.authenticationNotifyCharacteristic:
                authNotifyCharacteristic = characteristic
            case YDEbikeProtocol.commandWriteCharacteristic:
                commandWriteCharacteristic = characteristic
            case YDEbikeProtocol.commandNotifyCharacteristic:
                commandNotifyCharacteristic = characteristic
            default:
                continue
            }
            appendLog(.system, "特征 \(characteristic.uuid.uuidString) 已发现")
        }

        if service.uuid.uuidString.uppercased() == YDEbikeProtocol.authenticationService,
            (authReadWriteCharacteristic == nil || authNotifyCharacteristic == nil)
        {
            failConnection("认证服务缺少 Read/Write 或 Notify 特征。")
            return
        }
        if service.uuid.uuidString.uppercased() == YDEbikeProtocol.commandService {
            guard commandWriteCharacteristic != nil else {
                failConnection("命令服务缺少写入特征。")
                return
            }
        }
        beginAuthenticationIfPossible()
    }

    func peripheral(
        _ peripheral: CBPeripheral,
        didUpdateValueFor characteristic: CBCharacteristic,
        error: Error?
    ) {
        guard acceptsCallbacks(from: peripheral) else { return }
        if let error {
            failConnection("读取 \(characteristic.uuid.uuidString) 失败：\(errorDescription(error))")
            return
        }
        guard let data = characteristic.value else { return }

        let uuid = characteristic.uuid.uuidString.uppercased()
        let isV2Challenge = uuid == YDEbikeProtocol.authenticationReadWriteCharacteristic
            && (try? YDEbikeProtocol.authenticationProfile(challenge: data).flow) == .tokenV2
        let hideData = isV2Challenge
            || (uuid == YDEbikeProtocol.authenticationNotifyCharacteristic && authenticationUsesToken)
        appendLog(
            .received,
            hideData ? "\(characteristic.uuid.uuidString)，\(data.count) 字节（V2 认证内容已隐藏）"
                : characteristic.uuid.uuidString,
            data: hideData ? nil : data
        )
        switch characteristic.uuid.uuidString.uppercased() {
        case YDEbikeProtocol.authenticationReadWriteCharacteristic:
            if authenticationStarted && authenticationReadScheduled && !authenticationCompleted {
                prepareAuthentication(challenge: data)
            }
        case YDEbikeProtocol.authenticationNotifyCharacteristic:
            if authenticationUsesToken {
                receiveV2AuthenticationResult(data)
            } else {
                appendLog(.system, "已收到认证通知；当前旧版流程不把该通知自动判为认证成功")
            }
        case YDEbikeProtocol.commandNotifyCharacteristic:
            if let code = YDEbikeProtocol.commandResponseCode(from: data) {
                appendLog(
                    code == 1 ? .system : .error,
                    code == 1 ? "设备返回：操作成功" : "设备返回：操作失败（状态 \(code)）"
                )
            }
        default:
            break
        }
    }

    func peripheral(
        _ peripheral: CBPeripheral,
        didWriteValueFor characteristic: CBCharacteristic,
        error: Error?
    ) {
        guard acceptsCallbacks(from: peripheral),
            activeWriteRequiresResponse,
            activeWrite?.characteristic === characteristic
        else { return }
        finishActiveWrite(error: error)
    }

    func peripheral(
        _ peripheral: CBPeripheral,
        didUpdateNotificationStateFor characteristic: CBCharacteristic,
        error: Error?
    ) {
        guard acceptsCallbacks(from: peripheral) else { return }
        if let error {
            failConnection("订阅 \(characteristic.uuid.uuidString) 失败：\(errorDescription(error))")
            return
        }
        guard characteristic.isNotifying else {
            failConnection("通知状态回调未启用通知：\(characteristic.uuid.uuidString)")
            return
        }
        appendLog(.system, "通知订阅已确认：\(characteristic.uuid.uuidString)")

        if characteristic.uuid.uuidString.uppercased()
            == YDEbikeProtocol.authenticationNotifyCharacteristic,
            authenticationStarted,
            let challenge = pendingAuthenticationChallenge
        {
            authenticate(challenge: challenge)
        } else if characteristic.uuid.uuidString.uppercased()
            == YDEbikeProtocol.commandNotifyCharacteristic,
            commandNotificationPending
        {
            finishConnectionSetup()
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didReadRSSI RSSI: NSNumber, error: Error?) {
        guard acceptsCallbacks(from: peripheral) else { return }
        guard error == nil else { return }
        if let index = devices.firstIndex(where: { $0.id == peripheral.identifier }) {
            devices[index].rssi = RSSI.intValue
            devices = devices
        }
    }

    func peripheralIsReady(toSendWriteWithoutResponse peripheral: CBPeripheral) {
        guard acceptsCallbacks(from: peripheral) else { return }
        drainWriteQueue()
    }

    private func characteristicProperties(_ properties: CBCharacteristicProperties) -> String {
        let labels: [(CBCharacteristicProperties, String)] = [
            (.read, "Read"), (.write, "Write"),
            (.writeWithoutResponse, "WriteWithoutResponse"),
            (.notify, "Notify"), (.indicate, "Indicate")
        ]
        return labels.filter { properties.contains($0.0) }.map { $0.1 }.joined(separator: "/")
    }
}

