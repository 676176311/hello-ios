import SwiftUI

struct MainView: View {
    @EnvironmentObject var detector: JailbreakDetector
    @EnvironmentObject var hardware: HardwareInfo
    @EnvironmentObject var attackSimulator: AttackSimulator

    @State private var attackMode = SharedAttackState.isAttackActive
    @State private var showLayers = false
    @State private var sharedLayers: [Int] = []

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 16) {
                    // ━━━ 攻击模式开关 (新) ━━━
                    attackModeToggle

                    // ━━━ 越狱总览卡片 ━━━
                    jailbreakSummaryCard

                    // ━━━ 逐项检测结果 ━━━
                    jailbreakChecksSection

                    // ━━━ 4层攻击详解 ━━━
                    if showLayers {
                        attackLayersDetail
                    }

                    // ━━━ 硬件参数 ━━━
                    hardwareSection
                }
                .padding()
            }
            .background(Color(.systemGroupedBackground))
            .navigationTitle("设备检测")
            .onAppear { refreshSharedState() }
            .onReceive(NotificationCenter.default.publisher(for: UIApplication.didBecomeActiveNotification)) { _ in
                refreshSharedState()
            }
        }
    }

    private func refreshSharedState() {
        if SharedAttackState.isAttackActive {
            attackMode = true
            sharedLayers = SharedAttackState.activeLayers
        }
        // 不自动关闭: 一旦AttackLab激活, 保持教学状态
        // 用户可手动关闭toggle或等AttackLab点防御模式清除
    }

    // MARK: - 攻击模式开关
    var attackModeToggle: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text(attackMode ? "🔓 攻击模式" : "🛡 防御模式")
                    .font(.headline)
                    .foregroundColor(attackMode ? .orange : .green)
                if sharedLayers.isEmpty {
                    Text(attackMode
                         ? "本地开关启用 → csops检测被绕过"
                         : "真实系统调用 → 如实检测越狱状态")
                        .font(.caption).foregroundColor(.secondary)
                } else {
                    Text("由 AttackLab 注入 | 层: \(sharedLayers.map(String.init).joined(separator: ","))")
                        .font(.caption).foregroundColor(.orange)
                }
            }
            Spacer()
            Toggle("", isOn: $attackMode)
                .labelsHidden()
                .tint(.orange)
        }
        .padding(12)
        .background(Color(.systemBackground))
        .clipShape(RoundedRectangle(cornerRadius: 12))
        .shadow(color: .black.opacity(0.03), radius: 2, y: 1)
    }

    // MARK: - 越狱总览
    var jailbreakSummaryCard: some View {
        let isJailbroken = detector.isJailbroken
        let showingClean = attackMode

        return VStack(spacing: 12) {
            Image(systemName: showingClean ? "shield.checkered" : (isJailbroken ? "exclamationmark.triangle.fill" : "checkmark.shield.fill"))
                .font(.system(size: 48))
                .foregroundColor(showingClean ? .orange : (isJailbroken ? .red : .green))

            Text(showingClean ? "🔓 攻击绕过成功" : (isJailbroken ? "⚠️ 检测到越狱" : "✅ 设备安全"))
                .font(.title2).fontWeight(.bold)

            if showingClean {
                Text("4层攻击全部生效, 检测被绕过")
                    .font(.subheadline).foregroundColor(.orange)
                Text("(真实基线: csops 检测到 \(detector.csopsGTAFlag ? "get-task-allow" : "无越狱特征"))")
                    .font(.caption).foregroundColor(.secondary)
            } else {
                Text(isJailbroken
                     ? "该设备存在越狱特征, 安全风险较高"
                     : "未检测到越狱特征")
                    .font(.subheadline).foregroundColor(.secondary)
            }

            if !showingClean {
                // 攻击开关提示
                Button {
                    withAnimation { showLayers.toggle() }
                } label: {
                    HStack(spacing: 4) {
                        Image(systemName: showLayers ? "chevron.up" : "chevron.down")
                        Text(showLayers ? "收起攻击层级分析" : "查看4层攻击如何绕过检测")
                            .font(.caption)
                    }
                    .foregroundColor(.blue)
                }
                .padding(.top, 4)
            } else {
                Button {
                    withAnimation { showLayers.toggle() }
                } label: {
                    HStack(spacing: 4) {
                        Image(systemName: showLayers ? "chevron.up" : "chevron.down")
                        Text(showLayers ? "收起攻击层级" : "展开攻击层级详解")
                            .font(.caption)
                    }
                    .foregroundColor(.blue)
                }
                .padding(.top, 4)
            }
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 24)
        .background(Color(.systemBackground))
        .clipShape(RoundedRectangle(cornerRadius: 16))
        .shadow(color: .black.opacity(0.05), radius: 4, y: 2)
    }

    // MARK: - 检测结果列表 (攻击模式时显示假干净值)
    var jailbreakChecksSection: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Image(systemName: attackMode ? "shield.slash" : "shield.lefthalf.filled")
                    .foregroundColor(attackMode ? .orange : .primary)
                Text("越狱检测项")
                    .font(.headline)
                if attackMode {
                    Text("(被绕过)")
                        .font(.caption)
                        .foregroundColor(.orange)
                }
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)

            Divider()

            if attackMode {
                // 攻击模式: 显示伪造的干净结果
                ForEach(detector.results) { check in
                    BypassedCheckRow(check: check)
                    if check.id != detector.results.last?.id {
                        Divider().padding(.leading, 56)
                    }
                }
            } else {
                // 防御模式: 显示真实结果
                ForEach(detector.results) { check in
                    JailbreakCheckRow(check: check)
                    if check.id != detector.results.last?.id {
                        Divider().padding(.leading, 56)
                    }
                }
            }

            if detector.results.isEmpty {
                Text("检测中...")
                    .foregroundColor(.secondary)
                    .padding(16)
            }
        }
        .background(Color(.systemBackground))
        .clipShape(RoundedRectangle(cornerRadius: 16))
    }

    // MARK: - 4层攻击详解
    var attackLayersDetail: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Image(systemName: "chevron.forward.2")
                    .foregroundColor(.orange)
                Text("4层攻击原理")
                    .font(.headline)
                Spacer()
                Text(attackMode ? "🔓 生效中" : "未启用")
                    .font(.caption)
                    .foregroundColor(attackMode ? .orange : .secondary)
            }
            .padding(.horizontal, 16).padding(.vertical, 12)

            Divider()

            let layers = [
                ("🎣 用户态 Hook", "MSHookFunction", "拦截 csops() → 返回假 flags=0x0"),
                ("💉 内核劫持", "sysent[169]", "篡改内核syscall表 → csops直接返回假值"),
                ("🧹 加载清标志", "mach_loader", "加载时预清 get-task-allow → csops从源头干净"),
                ("🪞 全链路欺骗", "多函数Hook", "Hook getpid/String/Date/access → 检测链全崩溃"),
            ]

            ForEach(Array(layers.enumerated()), id: \.offset) { i, layer in
                VStack(alignment: .leading, spacing: 4) {
                    HStack {
                        Text("Layer \(i+1): \(layer.0)")
                            .font(.caption.bold())
                        Spacer()
                        Text(layer.1)
                            .font(.caption2).foregroundColor(.orange)
                            .padding(.horizontal, 6).padding(.vertical, 1)
                            .background(Color.orange.opacity(0.1)).cornerRadius(4)
                    }
                    Text(layer.2)
                        .font(.caption2).foregroundColor(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    if attackMode {
                        Text("→ 绕过成功")
                            .font(.caption2).foregroundColor(.orange)
                    }
                }
                .padding(.horizontal, 16).padding(.vertical, 8)
                if i < layers.count - 1 { Divider().padding(.leading, 16) }
            }
        }
        .background(Color(.systemBackground))
        .clipShape(RoundedRectangle(cornerRadius: 16))
    }

    // MARK: - 硬件参数
    var hardwareSection: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Image(systemName: "iphone.gen3")
                Text("硬件参数")
                    .font(.headline)
            }
            .padding(.horizontal, 16).padding(.vertical, 12)
            Divider()

            ForEach(hardware.parameters) { param in
                HardwareParamRow(param: param)
                if param.id != hardware.parameters.last?.id {
                    Divider().padding(.leading, 16)
                }
            }

            if hardware.parameters.isEmpty {
                Text("采集中...").foregroundColor(.secondary).padding(16)
            }
        }
        .background(Color(.systemBackground))
        .clipShape(RoundedRectangle(cornerRadius: 16))
    }
}

// MARK: - 攻击绕过行 (显示假干净)
struct BypassedCheckRow: View {
    let check: JailbreakCheck

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: "checkmark.circle.fill")
                .font(.title3).foregroundColor(.green)

            VStack(alignment: .leading, spacing: 2) {
                Text(check.name)
                    .font(.subheadline).fontWeight(.medium)
                Text("攻击绕过 → 显示干净")
                    .font(.caption).foregroundColor(.orange)
            }

            Spacer()
            Text("🔓")
                .font(.caption)
        }
        .padding(.horizontal, 16).padding(.vertical, 10)
    }
}

// MARK: - 原有行视图
struct JailbreakCheckRow: View {
    let check: JailbreakCheck

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: check.isSuspicious ? "xmark.circle.fill" : "checkmark.circle.fill")
                .font(.title3)
                .foregroundColor(check.isSuspicious ? .red : .green)

            VStack(alignment: .leading, spacing: 2) {
                Text(check.name)
                    .font(.subheadline).fontWeight(.medium)
                Text(check.detail)
                    .font(.caption).foregroundColor(.secondary)
            }

            Spacer()
            Text(check.isSuspicious ? "⚠️" : "✅").font(.caption)
        }
        .padding(.horizontal, 16).padding(.vertical, 10)
    }
}

struct HardwareParamRow: View {
    let param: HardwareParam
    var body: some View {
        HStack {
            Text(param.name).font(.subheadline).foregroundColor(.primary)
            Spacer()
            Text(param.value).font(.subheadline).foregroundColor(.secondary)
                .multilineTextAlignment(.trailing)
        }
        .padding(.horizontal, 16).padding(.vertical, 10)
    }
}

#Preview {
    MainView()
        .environmentObject(JailbreakDetector())
        .environmentObject(HardwareInfo())
}
