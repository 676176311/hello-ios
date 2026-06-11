import SwiftUI

struct ContentView: View {
    @StateObject private var simulator = AttackSimulator()
    @State private var allEnabled = false
    @State private var layerEnabled = [false, false, false, false]

    private let layerInfo: [(name: String, emoji: String, desc: String, method: String)] = [
        ("用户态 Hook", "🎣", "攻击者用 MSHookFunction 拦截 csops(), 让它返回干净标志", "MSHookFunction(csops)"),
        ("内核 Syscall 劫持", "💉", "checkra1n 级内核漏洞, 直接修改 sysent[169] csops 入口", "sysent[169] 伪造"),
        ("加载时清标志", "🧹", "在 mach_loader 阶段提前清掉 get-task-allow 等可疑标志", "mach_loader 预清"),
        ("检测链欺骗", "🪞", "Hook getpid/MemoryLayout/String 等底层函数, 全链路欺骗", "多函数 Hook"),
    ]

    private func resultForLayer(_ i: Int) -> LayerResult? {
        switch i {
        case 0: return simulator.layer1
        case 1: return simulator.layer2
        case 2: return simulator.layer3
        case 3: return simulator.layer4
        default: return nil
        }
    }

    var body: some View {
        NavigationView {
            ScrollView {
                VStack(spacing: 0) {
                    // 顶部标题
                    VStack(spacing: 8) {
                        Text("🔬 越狱攻击模拟实验室")
                            .font(.title2.bold())
                        Text("每个攻击层可独立开关，观察防御检测的变化")
                            .font(.caption)
                            .foregroundColor(.secondary)
                        Text("⚠ 本App仅供安全学习研究，禁止非法使用")
                            .font(.caption2)
                            .foregroundColor(.red.opacity(0.7))
                    }
                    .padding(.top, 16)
                    .padding(.bottom, 12)

                    // 全局开关
                    HStack {
                        Text("全部攻击层:")
                            .font(.subheadline.bold())
                        Spacer()
                        Toggle("", isOn: $allEnabled)
                            .labelsHidden()
                            .onChange(of: allEnabled) { newVal in
                                layerEnabled = layerEnabled.map { _ in newVal }
                            }
                    }
                    .padding(.horizontal, 16)
                    .padding(.vertical, 10)
                    .background(Color(.systemGray6))
                    .cornerRadius(12)
                    .padding(.horizontal, 12)
                    .padding(.bottom, 12)

                    // 4层攻击卡片
                    ForEach(0..<4, id: \.self) { i in
                        LayerCard(
                            index: i,
                            info: layerInfo[i],
                            enabled: $layerEnabled[i],
                            result: resultForLayer(i),
                            onRun: { runLayer(i) }
                        )
                        .padding(.horizontal, 12)
                        .padding(.bottom, 10)
                    }

                    // 底部总结
                    if simulator.baseline != nil {
                        VStack(spacing: 6) {
                            let results = [simulator.layer1, simulator.layer2, simulator.layer3, simulator.layer4]
                            let tested = results.filter { $0 != nil }.count
                            let detected = results.compactMap { $0 }.filter { $0.detected }.count
                            Text("检出: \(detected)/\(tested) 层")
                                .font(.headline)
                                .foregroundColor(detected > 0 ? .red : .green)
                            if detected > 0 {
                                Text("⚠️ 模拟攻击被防御检出 — 攻击无法隐藏痕迹")
                                    .font(.caption)
                                    .foregroundColor(.red)
                            } else if tested > 0 {
                                Text("✅ 所有层防御正常")
                                    .font(.caption)
                                    .foregroundColor(.green)
                            } else {
                                Text("点击各层「运行测试」开始")
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                            }
                        }
                        .padding(.vertical, 16)
                    }
                }
            }
            .navigationBarHidden(true)
            .onAppear {
                simulator.baseline = collectBaseline()
            }
        }
    }

    private func runLayer(_ i: Int) {
        if simulator.baseline == nil {
            simulator.baseline = collectBaseline()
        }
        switch i {
        case 0: simulator.testLayer1(attackEnabled: layerEnabled[i])
        case 1: simulator.testLayer2(attackEnabled: layerEnabled[i])
        case 2: simulator.testLayer3(attackEnabled: layerEnabled[i])
        case 3: simulator.testLayer4(attackEnabled: layerEnabled[i])
        default: break
        }
    }
}

// MARK: - 单层攻击卡片
struct LayerCard: View {
    let index: Int
    let info: (name: String, emoji: String, desc: String, method: String)
    @Binding var enabled: Bool
    let result: LayerResult?
    let onRun: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            // 头部
            HStack {
                Text("\(info.emoji) Layer \(index+1): \(info.name)")
                    .font(.subheadline.bold())
                Spacer()
                Toggle("", isOn: $enabled)
                    .labelsHidden()
                    .scaleEffect(0.85)
            }

            // 攻击描述
            Text(info.desc)
                .font(.caption)
                .foregroundColor(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            HStack {
                Text("攻击: \(info.method)")
                    .font(.caption2)
                    .foregroundColor(.orange)
                Spacer()
                Button(action: onRun) {
                    HStack(spacing: 4) {
                        if result != nil {
                            Image(systemName: "arrow.clockwise")
                                .font(.caption2)
                        }
                        Text("运行测试")
                            .font(.caption.bold())
                    }
                    .padding(.horizontal, 14)
                    .padding(.vertical, 6)
                    .background(enabled ? Color.red.opacity(0.8) : Color.blue.opacity(0.7))
                    .foregroundColor(.white)
                    .cornerRadius(16)
                }
            }

            // 结果区域
            if let res = result {
                VStack(alignment: .leading, spacing: 6) {
                    // 模式指示
                    HStack {
                        Circle()
                            .fill(res.attackEnabled ? Color.red : Color.green)
                            .frame(width: 8, height: 8)
                        Text(res.attackEnabled ? "🔴 攻击模拟: ON" : "🟢 正常模式")
                            .font(.caption.bold())
                            .foregroundColor(res.attackEnabled ? .red : .green)
                        Spacer()
                        Text(res.detected ? "⚠️ 检出" : "✓ 正常")
                            .font(.caption.bold())
                            .foregroundColor(res.detected ? .red : .green)
                            .padding(.horizontal, 8)
                            .padding(.vertical, 2)
                            .background(res.detected ? Color.red.opacity(0.15) : Color.green.opacity(0.15))
                            .cornerRadius(4)
                    }

                    // 详情
                    Text(res.attackEnabled ? "\(res.safeDetail)\n\n\(res.attackDetail)" : res.safeDetail)
                        .font(.caption2)
                        .foregroundColor(res.attackEnabled ? (res.detected ? .red : .orange) : .secondary)
                        .fixedSize(horizontal: false, vertical: true)
                        .lineSpacing(4)
                }
                .padding(10)
                .background(Color(.systemGray6))
                .cornerRadius(8)
            } else {
                Text("点击「运行测试」开始")
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .frame(maxWidth: .infinity, alignment: .center)
                    .padding(.vertical, 20)
            }
        }
        .padding(12)
        .background(Color(.systemBackground))
        .cornerRadius(14)
        .shadow(color: .black.opacity(0.06), radius: 4, y: 2)
    }
}

#Preview {
    ContentView()
}
