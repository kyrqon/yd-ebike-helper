import SwiftUI

@MainActor
struct YadeaAccountEntry: View {
    @ObservedObject private var account = YadeaAccount.shared
    @State private var showsAccount = false

    var body: some View {
        Button {
            showsAccount = true
        } label: {
            HStack {
                Label("雅迪账号与车辆", systemImage: "person.crop.circle")
                Spacer()
                Text(account.isLoggedIn ? "已登录" : "未登录")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .buttonStyle(.bordered)
        .sheet(isPresented: $showsAccount) {
            YadeaAccountView()
        }
    }
}

@MainActor
struct YadeaAccountView: View {
    @Environment(\.dismiss) private var dismiss
    @ObservedObject private var account = YadeaAccount.shared
    @State private var phone = ""
    @State private var code = ""
    @State private var password = ""
    @State private var loginMethod: LoginMethod = .sms
    @State private var resendSeconds = 0
    @State private var cooldownTask: Task<Void, Never>?
    @State private var isVisible = false

    private enum LoginMethod: String, CaseIterable, Identifiable {
        case sms = "验证码"
        case password = "密码"
        var id: String { rawValue }
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text("V2 认证需要先登录雅迪账号，再选择本人已绑定的车辆。")
                    Text("账号服务：gw.yadeaiot.com.cn")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Text("登录信息和验证码直接提交到雅迪账号服务。")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                if account.isLoggedIn {
                    vehiclesSection
                    Section {
                        Button("退出账号", role: .destructive) {
                            clearSecrets()
                            account.logout()
                        }
                        .disabled(account.isBusy)
                    }
                } else {
                    loginSection
                }

                if account.isBusy || !account.status.isEmpty {
                    Section("状态") {
                        HStack(alignment: .top, spacing: 10) {
                            if account.isBusy {
                                ProgressView()
                                    .controlSize(.small)
                            }
                            if !account.status.isEmpty {
                                Text(account.status)
                                    .textSelection(.enabled)
                            }
                        }
                    }
                }
            }
            .formStyle(.grouped)
            .navigationTitle("雅迪账号")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("完成") {
                        clearSecrets()
                        dismiss()
                    }
                }
            }
            .onAppear {
                isVisible = true
            }
            .onChange(of: loginMethod) { _ in
                clearSecrets()
            }
            .onChange(of: phone) { _ in
                code = ""
            }
            .onChange(of: account.isLoggedIn) { loggedIn in
                if loggedIn {
                    clearSecrets()
                    cooldownTask?.cancel()
                    resendSeconds = 0
                }
            }
            .onDisappear {
                isVisible = false
                clearSecrets()
                cooldownTask?.cancel()
                cooldownTask = nil
                resendSeconds = 0
            }
        }
        #if os(macOS)
        .frame(minWidth: 480, idealWidth: 540, minHeight: 540)
        #endif
    }

    private var loginSection: some View {
        Section("登录") {
            Picker("登录方式", selection: $loginMethod) {
                ForEach(LoginMethod.allCases) { method in
                    Text(method.rawValue).tag(method)
                }
            }
            .pickerStyle(.segmented)
            .disabled(account.isBusy)

            phoneField
                .disabled(account.isBusy)

            if loginMethod == .sms {
                HStack {
                    verificationCodeField
                        .disabled(account.isBusy)
                    Button(resendSeconds > 0 ? "\(resendSeconds) 秒后重发" : "获取验证码") {
                        let mobile = phone.trimmingCharacters(in: .whitespacesAndNewlines)
                        Task {
                            let sent = await account.sendSMS(phone: mobile)
                            if sent && isVisible && !account.isLoggedIn {
                                beginCooldown()
                            }
                        }
                    }
                    .disabled(account.isBusy || resendSeconds > 0 || phone.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
            } else {
                SecureField("密码", text: $password)
                    .disabled(account.isBusy)
            }

            Button("登录并读取绑定车辆") {
                let mobile = phone.trimmingCharacters(in: .whitespacesAndNewlines)
                let enteredCode = code.trimmingCharacters(in: .whitespacesAndNewlines)
                let enteredPassword = password
                let method = loginMethod
                Task {
                    if method == .sms {
                        await account.loginSMS(phone: mobile, code: enteredCode)
                    } else {
                        await account.loginPassword(account: mobile, password: enteredPassword)
                    }
                    clearSecrets()
                }
            }
            .buttonStyle(.borderedProminent)
            .disabled(account.isBusy || phone.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                || (loginMethod == .sms ? code.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty : password.isEmpty))
        }
    }

    private var phoneField: some View {
        TextField("手机号", text: $phone)
            .autocorrectionDisabled()
            #if os(iOS)
            .textInputAutocapitalization(.never)
            .textContentType(.telephoneNumber)
            .keyboardType(.phonePad)
            #endif
    }

    private var verificationCodeField: some View {
        TextField("短信验证码", text: $code)
            .autocorrectionDisabled()
            #if os(iOS)
            .textInputAutocapitalization(.never)
            .textContentType(.oneTimeCode)
            .keyboardType(.numberPad)
            #endif
    }

    private var vehiclesSection: some View {
        Section("绑定车辆") {
            HStack {
                Text("选择需要连接的车辆，并核对蓝牙地址与扫描结果一致。")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer(minLength: 8)
                Button("刷新车辆") {
                    Task {
                        await account.refreshVehicles()
                    }
                }
                .disabled(account.isBusy)
            }
            if account.vehicles.isEmpty {
                Text("还没有读取到绑定车辆，请点击“刷新车辆”。")
                    .foregroundStyle(.secondary)
            } else {
                Picker("认证车辆", selection: $account.selectedVehicleID) {
                    Text("请选择车辆").tag(String?.none)
                    ForEach(account.vehicles) { vehicle in
                        Text(vehicle.name.isEmpty ? "雅迪车辆 \(vehicle.vin.suffix(6))" : vehicle.name)
                            .tag(Optional(vehicle.id))
                    }
                }
                .disabled(account.isBusy)

                if let selected = account.vehicles.first(where: { $0.id == account.selectedVehicleID }) {
                    LabeledContent("蓝牙地址") {
                        Text(selected.macAddress.isEmpty ? "未提供" : selected.macAddress)
                            .font(.callout.monospaced())
                            .textSelection(.enabled)
                    }
                    LabeledContent("车架号末六位") {
                        Text(String(selected.vin.suffix(6)))
                            .font(.callout.monospaced())
                    }
                }
            }
        }
    }

    private func clearSecrets() {
        code = ""
        password = ""
    }

    private func beginCooldown() {
        cooldownTask?.cancel()
        resendSeconds = 60
        cooldownTask = Task { @MainActor in
            while resendSeconds > 0 {
                do {
                    try await Task.sleep(nanoseconds: 1_000_000_000)
                } catch {
                    return
                }
                guard !Task.isCancelled else { return }
                resendSeconds -= 1
            }
            cooldownTask = nil
        }
    }
}
