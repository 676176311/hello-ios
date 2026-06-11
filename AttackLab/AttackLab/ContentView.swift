import SwiftUI

struct ContentView: View {
    @StateObject private var simulator = AttackSimulator()
    @State private var allEnabled = false
    @State private var layerEnabled = [false, false, false, false]

    private let layerInfo: [(name: String, emoji: String, desc: String, method: String)] = [
        ("用户态 Hook", "🎣", "Hook 越狱检测函数 csops(), 让它返回干净标志", "MSHookFunction"),
        ("内核 Syscall 劫持", "💉", "直接篡改内核系统调用表 sysent[169], 从根源欺骗", "sysent 劫持"),
        ("加载时清标志", "🧹", "在 mach_loader 加载阶段提前清除可疑标志", "mach_loader 预清"),
        ("检测链全欺骗", "🪞", "Hook 整个检测链路 (getpid/String/Date/access)", "全链路 Hook"),
    ]

    private func resultForLayer(_ i: Int) -> AttackResult? {
        switch i { case 0: simulator.layer1; case 1: simulator.layer2; case 2: simulator.layer3; case 3: simulator.layer4; default: nil }
    }

    var body: some View {
        NavigationView {
            ScrollView {
                VStack(spacing: 0) {
                    // 标题
                    VStack(spacing: 6) {
                        Text("🔬 攻击模拟实验室")
                            .font(.title2.bold())
                        Text("ON = 攻击生效, 检测被绕过 | OFF = 真实防御检出")
                            .font(.caption)
                            .foregroundColor(.secondary)
                        Text("⚠ 仅供安全学习, 禁止非法使用")
                            .font(.caption2).foregroundColor(.red.opacity(0.7))
                    }
                    .padding(.top, 12).padding(.bottom, 8)

                    // 全局开关
                    HStack {
                        Text("全部攻击:").font(.subheadline.bold())
                        Spacer()
                        Toggle("", isOn: $allEnabled).labelsHidden()
                            .onChange(of: allEnabled) { v in layerEnabled = layerEnabled.map { _ in v } }
                    }
                    .padding(.horizontal, 16).padding(.vertical, 10)
                    .background(Color(.systemGray6)).cornerRadius(12)
                    .padding(.horizontal, 12).padding(.bottom, 10)

                    // 4层卡片
                    ForEach(0..<4, id: \.self) { i in
                        AttackLayerCard(
                            index: i,
                            info: layerInfo[i],
                            enabled: $layerEnabled[i],
                            result: resultForLayer(i),
                            onRun: { runLayer(i) }
                        )
                        .padding(.horizontal, 12).padding(.bottom, 8)
                    }

                    // 底部总结
                    if simulator.baseline != nil {
                        let results = [simulator.layer1, simulator.layer2, simulator.layer3, simulator.layer4]
                        let tested = results.filter { $0 != nil }.count
                        let bypassed = results.compactMap { $0 }.filter { $0.attackEnabled }.count
                        VStack(spacing: 6) {
                            Text("攻击层: \(bypassed)/\(tested) 已启用")
                                .font(.headline)
                                .foregroundColor(bypassed > 0 ? .orange : .secondary)
                            if bypassed > 0 {
                                Text("🔓 \(bypassed)层攻击生效 — 检测被绕过")
                                    .font(.caption).foregroundColor(.orange)
                            }
                            if tested == 0 {
                                Text("点击各层「运行测试」开始").font(.caption).foregroundColor(.secondary)
                            }
                        }
                        .padding(.vertical, 14)
                    }
                }
            }
            .navigationBarHidden(true)
            .onAppear { simulator.baseline = collectBaseline() }
        }
    }

    private func runLayer(_ i: Int) {
        if simulator.baseline == nil { simulator.baseline = collectBaseline() }
        switch i {
        case 0: simulator.testLayer1(attackEnabled: layerEnabled[i])
        case 1: simulator.testLayer2(attackEnabled: layerEnabled[i])
        case 2: simulator.testLayer3(attackEnabled: layerEnabled[i])
        case 3: simulator.testLayer4(attackEnabled: layerEnabled[i])
        default: break
        }
    }
}

// MARK: - 攻击层卡片
struct AttackLayerCard: View {
    let index: Int
    let info: (name: String, emoji: String, desc: String, method: String)
    @Binding var enabled: Bool
    let result: AttackResult?
    let onRun: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            // 头部
            HStack {
                Text("\(info.emoji) Layer \(index+1): \(info.name)")
                    .font(.subheadline.bold())
                Spacer()
                Toggle("", isOn: $enabled).labelsHidden().scaleEffect(0.85)
            }

            Text(info.desc)
                .font(.caption).foregroundColor(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            // 按钮行
            HStack {
                Text("方案: \(info.method)")
                    .font(.caption2).foregroundColor(.orange)
                Spacer()
                Button(action: onRun) {
                    HStack(spacing: 4) {
                        if result != nil { Image(systemName: "arrow.clockwise").font(.caption2) }
                        Text("运行测试").font(.caption.bold())
                    }
                    .padding(.horizontal, 14).padding(.vertical, 6)
                    .background(enabled ? Color.orange : Color.blue.opacity(0.7))
                    .foregroundColor(.white).cornerRadius(16)
                }
            }

            // 结果
            if let res = result {
                VStack(alignment: .leading, spacing: 6) {
                    HStack {
                        Circle().fill(res.attackEnabled ? Color.orange : Color.green).frame(width: 8, height: 8)
                        Text(res.attackEnabled ? "🔓 攻击模式" : "🛡 防御模式")
                            .font(.caption.bold())
                            .foregroundColor(res.attackEnabled ? .orange : .green)
                        Spacer()
                        Text(res.attackEnabled ? "绕过成功" : "防御有效")
                            .font(.caption.bold())
                            .foregroundColor(res.attackEnabled ? .orange : .green)
                            .padding(.horizontal, 8).padding(.vertical, 2)
                            .background((res.attackEnabled ? Color.orange : Color.green).opacity(0.15))
                            .cornerRadius(4)
                    }

                    // 真实状态
                    Text(res.realStatus)
                        .font(.caption2).foregroundColor(.secondary)
                        .fixedSize(horizontal: false, vertical: true)

                    if res.attackEnabled {
                        Divider()
                        Text(res.bypassDescription)
                            .font(.caption2)
                            .foregroundColor(.orange)
                            .fixedSize(horizontal: false, vertical: true)
                            .lineSpacing(3)

                        if !res.residualDefense.isEmpty {
                            Text("🛡 残留防御: \(res.residualDefense)")
                                .font(.caption2)
                                .foregroundColor(.blue)
                                .fixedSize(horizontal: false, vertical: true)
                                .padding(.top, 2)
                        }
                    }
                }
                .padding(10)
                .background(Color(.systemGray6)).cornerRadius(8)
            } else {
                Text("点击「运行测试」开始")
                    .font(.caption).foregroundColor(.secondary)
                    .frame(maxWidth: .infinity, alignment: .center).padding(.vertical, 20)
            }
        }
        .padding(12)
        .background(Color(.systemBackground)).cornerRadius(14)
        .shadow(color: .black.opacity(0.06), radius: 4, y: 2)
    }
}

#Preview { ContentView() }
