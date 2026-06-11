import SwiftUI

struct ContentView: View {
    @StateObject private var simulator = AttackSimulator()
    @State private var allEnabled = false
    @State private var layerEnabled = [false, false, false, false]

    private let layerInfo = [
        (name: "用户态 Hook", emoji: "🎣", desc: "攻击者用 MSHookFunction 拦截 csops(), 让它返回干净标志", method: "MSHookFunction(csops)"),
        (name: "内核 Syscall 劫持", emoji: "💉", desc: "checkra1n 等级的内核漏洞, 直接修改 sysent[169] csops 入口", method: "sysent[169] 伪造"),
        (name: "加载时清标志", emoji: "🧹", desc: "在 mach_loader 阶段提前清掉 get-task-allow 等可疑标志", method: "mach_loader 预清"),
        (name: "检测链欺骗", emoji: "🪞", desc: "Hook getpid/MemoryLayout/String等底层函数, 破坏检测链路", method: "多函数 Hook"),
    ]

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
                            result: simulator.layerResults[i],
                            onRun: { simulator.layerResults[i] = simulator.layerResults[i] }
                        ) {
                            runLayer(i)
                        }
                        .padding(.horizontal, 12)
                        .padding(.bottom, 10)
                    }

                    // 底部总结
                    VStack(spacing: 6) {
                        let detected = simulator.layerResults.filter { $0.detected }.count
                        let tested = simulator.layerResults.filter { $0.layer > 0 }.count
                        Text("检出: \(detected)/\(tested) 层")
                            .font(.headline)
                            .foregroundColor(detected > 0 ? .red : .green)
                        if detected > 0 {
                            Text("⚠️ 设备存在越狱或攻击痕迹")
                                .font(.caption)
                                .foregroundColor(.red)
                        } else if tested > 0 {
                            Text("✅ 未检测到攻击痕迹")
                                .font(.caption)
                                .foregroundColor(.green)
                        }
                    }
                    .padding(.vertical, 16)
                }
            }
            .navigationBarHidden(true)
        }
    }

    private func runLayer(_ i: Int) {
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
    let result: LayerResult
    let onRun: () -> Void
    let runAction: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            // 头部：名称 + 开关
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
                Button(action: runAction) {
                    HStack(spacing: 4) {
                        if result.layer > 0 && result.attackEnabled == enabled {
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
            if result.layer > 0 {
                VStack(alignment: .leading, spacing: 4) {
                    HStack {
                        Circle()
                            .fill(result.attackEnabled ? Color.red : Color.green)
                            .frame(width: 8, height: 8)
                        Text(result.attackEnabled ? "🔴 攻击模拟: ON" : "🟢 正常模式")
                            .font(.caption.bold())
                            .foregroundColor(result.attackEnabled ? .red : .green)
                        Spacer()
                        if result.detected {
                            Text("⚠️ 检出")
                                .font(.caption.bold())
                                .foregroundColor(.red)
                                .padding(.horizontal, 8)
                                .padding(.vertical, 2)
                                .background(Color.red.opacity(0.15))
                                .cornerRadius(4)
                        } else {
                            Text("✓ 正常")
                                .font(.caption)
                                .foregroundColor(.green)
                                .padding(.horizontal, 8)
                                .padding(.vertical, 2)
                                .background(Color.green.opacity(0.15))
                                .cornerRadius(4)
                        }
                    }

                    Text("基线: \(result.baseline)")
                        .font(.caption2)
                        .foregroundColor(.secondary)

                    if result.attackEnabled || result.detected {
                        Text("结果: \(result.attackDetail)")
                            .font(.caption2)
                            .foregroundColor(result.detected ? .red : .orange)
                            .fixedSize(horizontal: false, vertical: true)
                    }
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
