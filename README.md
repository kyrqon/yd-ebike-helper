# YD E-Bike Helper

## 此 fork 的账号与认证功能

1.0.4 修正周期车辆状态被误记为“操作成功/失败”的问题：0x2A/0x2B 仅作为状态上报，每类最多每 15 秒保留一个原始样本并汇总省略条数。动力操作取得 GATT 写确认、且随后观察到与请求一致的合法短状态字段后，只显示一次“车辆状态已确认”；这表示状态一致，不是带命令序号的执行 ACK。未获得目标状态反馈时仅提示“指令已发送”。普通写入完成后阶段恢复为“已连接，等待操作”，避免把很久后的蓝牙断线错误标到旧操作上。

1.0.3 增加本人账号登录、绑定车辆选择与 V2 Token 握手。原有动力控制报文没有改写或自动发送。

### 实车反馈

2026-11-01，使用者反馈：1.0.3 已在其雅迪 Q17 Pro Y、iOS 26.6 上完成 V2 认证并成功解除动力锁定。此前该车已读取到 16 字节 RandKey，能力标志为 0x5F。

这是本次测试车辆的使用者反馈，尚未验证其他控制器或固件版本，也没有记录实际最高速度或独立测速结果。

- 手机号验证码或密码由用户在账号页面输入，只提交到固定的雅迪 HTTPS 服务域名 gw.yadeaiot.com.cn。没有自定义网关、Token 粘贴或自动发送验证码功能。
- 会话保存在本机钥匙串，密码和验证码不持久保存。只获取当前账号的绑定车辆；所选车的规范化 MAC 必须与本次蓝牙目标一致，角色或授权材料缺失时停止。
- 先读取 RandKey 并识别认证版本，再等待认证通知订阅确认。V2 流程取得本人车辆的 dkInfo 和账号角色后构造加密应答；必须同时收到 GATT 写确认及车端成功结果，再订阅命令通知并开放操作。退出或变更账号会中止 V2 连接。
- 保留原 14 字节旧版应答。旧版“应答已提交”不等同于车端确认。SecretKey 刷写、未知认证版本和未知长度没有实现，会明确报错并停止；不会尝试绕过授权。
- 手选 MAC 优先，不被扫描候选覆盖。V2 需要 Write Request；旧版写入方式可选择。没有订阅失败继续认证或超时盲目重试的兜底。
- 通信日志可导出，最近一次失败保留在本机，点击“清空”同时删除。V2 挑战值、授权材料、握手密文和认证通知原文均不进入日志，只记录长度、能力标志、阶段和结果码。

算法与接口字段参考 [YuRong 固定版本](https://github.com/ghhccghk/YuRong/tree/0df37d80fa747c1c55de278bfa487e5db71e7af6)，用系统 CommonCrypto 与原生 Swift 独立实现；这些是社区逆向规则，不是厂商公布的规格。官方服务版本、风控或接口变化可能导致登录失败，界面会显示 HTTP 或业务错误码。

### 安装与首次验证

在 Actions 中运行 **Build iPhone IPA**，选择本次修改的分支。工作流先执行 swift test，再编译该提交并输出未签名 IPA 和 SHA-256。Windows 用户可通过 Sideloadly 本地签名安装。

1. 打开“雅迪账号与车辆”，手动登录本人账号。
2. 读取并选择已绑定车辆，核对账号页显示的蓝牙地址与扫描目标一致。
3. 保持“自动（兼容）”，点击“连接并认证”，先不要发送车辆控制命令。
4. V2 必须显示车端认证成功；若失败，导出通信日志，并提供账号页面的 HTTP / 业务错误码。不要分享密码、验证码或 Token。

<p align="center">
  <img src="Assets/AppIcon.png" width="160" alt="YD E-Bike Helper 图标">
</p>

`YD E-Bike Helper` 是一款适用于 macOS 和 iPhone 的雅迪（YADEA）电动车 BLE 蓝牙调试工具，可用于发现设备、建立连接、完成设备认证、管理动力锁定以及查看通信日志。

[软件主页](https://cbdt-jwt.github.io/yd-ebike-helper/) · [下载最新版](https://github.com/CBDT-JWT/yd-ebike-helper/releases/latest)

> 本项目是独立开发的非官方工具，与雅迪科技集团有限公司无隶属或授权关系。请仅连接和调试属于自己或已获得明确授权的设备。

## 主要功能

- 扫描附近名称以 `YD` 开头的 BLE 设备
- 展示设备名称、信号强度、系统标识和广播数据
- 从设备广播信息中识别 MAC 地址，也支持手动输入
- 连接设备并完成认证流程
- 解除或恢复兼容车辆的动力锁定
- 设置提示音音量，并支持发送自定义 HEX 数据
- 查看 GATT 服务、特征及收发日志

## 系统要求

### iPhone

- iOS 17 或更高版本
- 一台安装了 Xcode 15 或更高版本的 Mac
- 普通 Apple 账户即可进行免费真机签名

### Mac

- macOS 13 Ventura 或更高版本
- 支持蓝牙的 Mac
- Apple Silicon 或 Intel 处理器

## 安装到 iPhone

iPhone 版本不需要 TestFlight，可以通过 Xcode 直接安装到自己的手机。

1. 使用 Xcode 打开 `YDEbikeHelper.xcodeproj`。
2. 打开“Xcode → Settings → Accounts”，登录你的 Apple 账户。
3. 用数据线连接 iPhone，在手机上选择“信任此电脑”。
4. 在项目导航中选择 `YDEbikeHelper`，再选择 `YDEbikeHelper-iOS` Target。
5. 打开“Signing & Capabilities”，将 Team 设为你的 `Personal Team`。
6. 如果 Bundle Identifier 出现重复提示，将其修改成只属于你的值，例如 `com.yourname.ydebikehelper`。
7. 在 Xcode 顶部运行设备中选择你的 iPhone，然后点击运行按钮或按 `Command + R`。
8. 如果手机提示需要开发者模式，前往“设置 → 隐私与安全性 → 开发者模式”，开启并按提示重新启动手机。
9. 首次打开 App 时允许使用蓝牙。

免费 `Personal Team` 筿名有效期为 7 天。到期后重新连接 iPhone，并在 Xcode 中再次运行即可续签安装。蓝牙功能必须使用真机测试，iOS 模拟器不能代替车辆 BLE 通信。

## 安装 macOS 版本

从 [Releases](https://github.com/CBDT-JWT/yd-ebike-helper/releases/latest) 下载 `yd-ebike-helper-macOS.zip`。

1. 解压下载的 ZIP 文件。
2. 将 `YD E-Bike Helper.app` 拖入“应用程序”文件夹。
3. 首次启动时允许应用使用蓝牙。
4. 如果 macOS 阻止打开，请前往“系统设置 → 隐私与安全性”，在安全性提示中选择“仍要打开”。

## 使用方法

1. 打开应用并点击“刷新扫描”。
2. 从设备列表中选择目标雅迪电动车。
3. 核对自动识别的 MAC 地址；无法自动识别时可手动填写。
4. 点击连接，等待设备认证和 GATT 服务发现完成。
5. 管理动力锁定、设置提示音音量，或在高级区域发送自定义 HEX 数据。
6. 通过通信日志查看连接、认证、写入和通知结果。

设备 MAC 地址通常会从广播数据中自动识别。不同车型、控制器版本或固件的广播格式可能不同，因此部分设备仍需手动输入。

## 从源码构建

项目使用 SwiftUI、CoreBluetooth 和 Swift Package Manager。协议测试和 macOS 打包命令：

```bash
swift test
zsh scripts/build-app.sh
```

打包完成后会生成：

```text
dist/yd-ebike-helper-macOS.zip
```

iOS 工程可以使用以下命令执行不签名的 ARM64 编译检查：

```bash
xcodebuild \
  -project YDEbikeHelper.xcodeproj \
  -scheme YDEbikeHelper-iOS \
  -sdk iphoneos \
  -destination 'generic/platform=iOS' \
  CODE_SIGNING_ALLOWED=NO \
  build
```

## 注意事项

- 解除动力锁定后，车辆动力状态可能立即发生变化；请确保车辆完全停稳、支架可靠且周围无障碍物。
- 请勿在车辆行驶过程中连接或发送控制指令。
- 不同车型和固件版本的兼容性可能存在差异。
- 本工具不提供绕过车辆安全机制、所有权验证或访问控制的功能。

