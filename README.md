# YD E-Bike Helper

<p align="center">
  <img src="Assets/AppIcon.png" width="160" alt="YD E-Bike Helper 图标">
</p>

适用于 macOS 和 iPhone 的雅迪（YADEA）电动车 BLE 调试工具，提供设备发现、账号与车辆管理、蓝牙认证、动力锁定控制和通信日志。

> 本项目为非官方工具，与雅迪科技集团有限公司无隶属或授权关系。请仅连接本人拥有或已获授权的车辆。

## 功能

- 扫描 BLE 设备，查看名称、信号强度、广播与 GATT 信息。
- 从广播识别 MAC 候选，也支持手动输入；连接时保留用户选择的地址。
- 实现旧版认证和 V2 Token 握手。V2 使用本人账号下绑定车辆的授权材料，并检查车端认证结果。
- 通过验证码或密码登录账号，刷新并选择绑定车辆；车辆 MAC 必须与当前蓝牙目标一致。
- 解除或恢复兼容车辆的动力锁定，调整提示音音量，发送自定义 HEX。
- 区分 GATT 写确认、车辆认证结果和状态反馈，动力操作状态匹配时显示一次提示。
- 导出通信日志、保留最近失败记录，并对周期状态通知采样，减少重复日志。

不同车型、控制器和固件的协议可能不同。SecretKey 刷写及未知认证格式尚未实现，遇到这些流程会停止并显示原因。

## 系统要求

- **iPhone**：iOS 17 或更高版本，支持蓝牙。
- **macOS**：macOS 13 或更高版本，支持蓝牙。
- **源码构建**：Xcode 15 或更高版本；Swift Package 使用 Swift 5.10 或更高版本。

车辆 BLE 通信必须在真机上验证，模拟器不能代替实车蓝牙连接。

## 安装到 iPhone

### 使用 Mac 与 Xcode

1. 打开 `YDEbikeHelper.xcodeproj`。
2. 在 Xcode 的 Accounts 中登录 Apple 账户。
3. 用数据线连接 iPhone，解锁并信任电脑。
4. 选择 `YDEbikeHelper-iOS` Target，在 Signing & Capabilities 中设置自己的 Team；如有需要，修改 Bundle Identifier。
5. 选择连接的 iPhone 并运行。
6. 如系统要求，开启 iPhone 的开发者模式并按提示重启；首次启动时允许蓝牙权限。

免费 Apple 账户签名通常有效 7 天，到期后需要重新签名安装。

### 只有 Windows 时

本仓库提供手动工作流 **Build iPhone IPA**：

1. 在 Actions 中选择该工作流，运行需要构建的分支。
2. 构建成功后下载 `yd-ebike-helper-auth-diagnostics-unsigned` 制品并解压。
3. 使用 [Sideloadly](https://sideloadly.io/) 在电脑本地签名并安装 IPA。
4. 按 iPhone 提示完成开发者信任与开发者模式设置。

工作流先运行测试，再生成未签名 IPA 和 SHA-256；CI 不需要 Apple 账号、证书或密码。

## 安装 macOS 版本

可使用仓库发布的 macOS 安装包，或从源码构建：

```bash
swift test
zsh scripts/build-app.sh
```

打包脚本输出 `dist/yd-ebike-helper-macOS.zip`。解压后将 App 移到“应用程序”，首次运行时允许蓝牙权限。

## 使用

1. 打开 App 并刷新扫描，选择目标车辆。
2. 核对设备 MAC。iPhone 的 CoreBluetooth 标识是 UUID，不能替代车辆 MAC；广播候选也需要核对。
3. 如车辆使用 V2 Token，先打开“雅迪账号与车辆”，登录本人账号并选择已绑定车辆。
4. 保持认证写入方式为“自动（兼容）”，点击“连接并认证”。V2 需要有回应写入。
5. 认证完成后再执行车辆支持的操作。操作前让车辆完全停稳。
6. 遇到问题时导出通信日志，并记录界面的 HTTP 或业务错误码。

## 结果提示与日志

- **GATT 写确认**表示蓝牙写请求已被确认，不能单独证明车辆业务操作完成。
- **V2 认证成功**需要写确认和车端成功结果，再完成命令通知订阅。
- **车辆状态已确认**表示已收到与本次动力操作请求一致的合法短状态反馈；它不是带命令序号的执行 ACK，也不是独立测速结果。
- 未收到目标状态反馈时仅提示“指令已发送”，不把未知结果判为失败。
- `0x2A`、`0x2B` 周期状态不再解释为通用操作成功或失败；每类每 15 秒最多保留一个原始样本，并汇总省略条数。
- 最近一次失败记录保留在本机，点击“清空”会同时删除该记录。

## 账号与数据

账号请求仅发送到固定的雅迪 HTTPS 服务域名 `gw.yadeaiot.com.cn`，验证码由用户手动请求。会话保存在本机钥匙串，密码和验证码不持久保存。

获取车辆凭证前会核对当前账号、所选绑定车辆、MAC 和账号角色。退出或变更账号会中止 V2 连接。

V2 挑战值、授权材料、握手密文和认证通知原文不写入日志。日志仍可能包含设备名称和蓝牙地址，公开分享前请检查并遮盖识别信息；不要提交密码、验证码或 Token。

## 构建与验证

```bash
swift test
```

iPhone 不签名编译检查：

```bash
xcodebuild \
  -project YDEbikeHelper.xcodeproj \
  -scheme YDEbikeHelper-iOS \
  -configuration Release \
  -sdk iphoneos \
  -destination 'generic/platform=iOS' \
  CODE_SIGNING_ALLOWED=NO \
  build
```

测试涵盖认证能力识别、加密固定向量、网关编解码、车辆与角色匹配、异步会话失效、状态反馈和日志采样。离线测试通过不代表所有车型或在线服务均已验证。

## 协议参考

部分账号接口和 V2 握手字段参考 [YuRong 的协议分析](https://github.com/ghhccghk/YuRong/tree/0df37d80fa747c1c55de278bfa487e5db71e7af6)，使用原生 Swift 和系统 CommonCrypto 独立实现。这些是社区分析资料，并非厂商公布的完整规格；接口或服务策略变化可能影响兼容性。

请勿在车辆行驶过程中连接或发送控制指令。本工具不提供绕过车辆所有权验证或访问控制的功能。
