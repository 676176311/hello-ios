import SwiftUI

struct ContentView: View {
    @StateObject private var sim = AttackSimulator()
    @State private var attackMode = false
    @State private var hasRun = false

    var body: some View {
        NavigationView {
            ScrollView {
                VStack(spacing: 0) {
                    // ━━━ 标题 ━━━
                    VStack(spacing: 4) {
                        Text("🔬 攻击模拟实验室")
                            .font(.title2.bold())
                        Text("对比攻击绕过 vs 防御检测的 csops 结果")
                            .font(.caption).foregroundColor(.secondary)
                    }.padding(.top, 12).padding(.bottom, 10)

                    // ━━━ 模式切换 ━━━
                    VStack(spacing: 8) {
                        Text("选择模式").font(.caption).foregroundColor(.secondary)
                        HStack(spacing: 12) {
                            // 防御模式按钮
                            Button {
                                attackMode = false
                                sim.runAll(attackEnabled: false)
                                hasRun = true
                            } label: {
                                VStack(spacing: 4) {
                                    Text("🛡 防御模式").font(.subheadline.bold())
                                    Text("真实越狱检测").font(.caption2)
                                }
                                .frame(maxWidth: .infinity)
                                .padding(.vertical, 10)
                                .background(attackMode ? Color(.systemGray5) : Color.green.opacity(0.15))
                                .foregroundColor(attackMode ? .secondary : .green)
                                .cornerRadius(10)
                                .overlay(
                                    RoundedRectangle(cornerRadius: 10)
                                        .stroke(attackMode ? Color.clear : Color.green, lineWidth: 1.5)
                                )
                            }

                            // 攻击模式按钮
                            Button {
                                attackMode = true
                                sim.runAll(attackEnabled: true)
                                hasRun = true
                            } label: {
                                VStack(spacing: 4) {
                                    Text("🔓 攻击模式").font(.subheadline.bold())
                                    Text("攻击绕过检测").font(.caption2)
                                }
                                .frame(maxWidth: .infinity)
                                .padding(.vertical, 10)
                                .background(attackMode ? Color.orange.opacity(0.15) : Color(.systemGray5))
                                .foregroundColor(attackMode ? .orange : .secondary)
                                .cornerRadius(10)
                                .overlay(
                                    RoundedRectangle(cornerRadius: 10)
                                        .stroke(attackMode ? Color.orange : Color.clear, lineWidth: 1.5)
                                )
                            }
                        }
                        .padding(.horizontal, 16)
                    }.padding(.bottom, 10)

                    // ━━━ 部署状态 ━━━
                    if hasRun && attackMode && !sim.deployMessage.isEmpty {
                        VStack(spacing: 6) {
                            HStack(spacing: 4) {
                                Image(systemName: sim.tweakDeployed ? "checkmark.circle.fill" : "xmark.circle.fill")
                                    .foregroundColor(sim.tweakDeployed ? .green : .red)
                                Text(sim.tweakDeployed ? "Substrate Tweak 已部署" : "部署失败")
                                    .font(.caption.bold())
                            }
                            Text(sim.deployMessage)
                                .font(.caption2).foregroundColor(.secondary)
                                .multilineTextAlignment(.center)
                            if sim.tweakDeployed {
                                Text("💡 重新打开 HelloApp 即可看到 csops 被绕过")
                                    .font(.caption2).foregroundColor(.blue)
                            }
                        }
                        .padding(10)
                        .background(Color(.systemGray6)).cornerRadius(8)
                        .padding(.horizontal, 12)
                        .padding(.bottom, 10)
                    }

                    // CSOPS 结果对比卡
                    if !sim.results.isEmpty {
                        VStack(spacing: 8) {
                            Text("csops 检测结果")
                                .font(.caption).foregroundColor(.secondary)

                            HStack(spacing: 12) {
                                CsopsCard(
                                    label: attackMode ? "攻击后" : "真实",
                                    flags: sim.results[0].csopsShown,
                                    gta: sim.results[0].gtaShown,
                                    status: attackMode ? "干净 ✅" : "检出 ⚠️",
                                    color: attackMode ? .orange : .green
                                )
                                Text("→").font(.title2).foregroundColor(.secondary)
                                CsopsCard(
                                    label: "结论",
                                    flags: attackMode ? "0x0" : sim.results[0].csopsShown,
                                    gta: attackMode ? "OFF ✅" : "ON ⚠️",
                                    status: attackMode ? "攻击成功 检测绕过" : "检测有效 发现越狱",
                                    color: attackMode ? .red : .green
                                )
                            }
                            .padding(.horizontal, 16)

                            Text(attackMode
                                ? "4层攻击全部生效 → csops 检测被彻底绕过"
                                : "真实系统调用 → csops 如实反映越狱状态")
                                .font(.caption)
                                .foregroundColor(attackMode ? .orange : .green)
                                .padding(.top, 4)
                        }
                        .padding(.vertical, 12)
                        .background(Color(.systemGray6).opacity(0.5))
                        .cornerRadius(12)
                        .padding(.horizontal, 12)
                        .padding(.bottom, 10)
                    }

                    // ━━━ 4层攻击详情 ━━━
                    if hasRun {
                        Text("各层攻击详析")
                            .font(.caption).foregroundColor(.secondary)
                            .padding(.bottom, 6)

                        ForEach(Array(sim.results.enumerated()), id: \.element.layer) { _, r in
                            LayerDetailCard(result: r)
                                .padding(.horizontal, 12).padding(.bottom, 6)
                        }
                    } else {
                        // 未运行提示
                        VStack(spacing: 12) {
                            Image(systemName: "hand.point.up.fill")
                                .font(.largeTitle).foregroundColor(.secondary)
                            Text("选择一个模式开始")
                                .font(.subheadline).foregroundColor(.secondary)
                        }
                        .frame(maxWidth: .infinity).padding(.vertical, 60)
                    }

                    Spacer(minLength: 20)
                }
            }
            .navigationBarHidden(true)
            .onAppear { sim.baseline = collectBaseline() }
        }
    }
}

// MARK: - csops 结果小卡片
struct CsopsCard: View {
    let label: String
    let flags: String
    let gta: String
    let status: String
    let color: Color

    var body: some View {
        VStack(spacing: 4) {
            Text(label).font(.caption2).foregroundColor(.secondary)
            Text("csops: \(flags)").font(.caption.monospaced().bold())
            Text("GTA: \(gta)").font(.caption.monospaced())
            Text(status).font(.caption.bold()).foregroundColor(color)
                .padding(.horizontal, 6).padding(.vertical, 2)
                .background(color.opacity(0.12)).cornerRadius(4)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 8)
        .background(Color(.systemBackground)).cornerRadius(8)
    }
}

// MARK: - 单层详解卡片
struct LayerDetailCard: View {
    let result: AttackResult

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text("Layer \(result.layer): \(result.layerName)")
                    .font(.caption.bold())
                Spacer()
                Text(result.attackEnabled ? "🔓 攻击ON" : "🛡 攻击OFF")
                    .font(.caption2)
                    .foregroundColor(result.attackEnabled ? .orange : .green)
                    .padding(.horizontal, 6).padding(.vertical, 2)
                    .background((result.attackEnabled ? Color.orange : Color.green).opacity(0.1))
                    .cornerRadius(4)
            }

            if result.attackEnabled {
                VStack(alignment: .leading, spacing: 4) {
                    Text("手段: \(result.method)")
                        .font(.caption2).foregroundColor(.orange)
                    Text("原理: \(result.howItWorks)")
                        .font(.caption2).foregroundColor(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                        .lineSpacing(2)
                    if !result.residualDefense.isEmpty {
                        Text("🛡 残留: \(result.residualDefense)")
                            .font(.caption2).foregroundColor(.blue)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            } else {
                Text("未开启攻击 — csops 真实检测")
                    .font(.caption2).foregroundColor(.secondary)
            }
        }
        .padding(10)
        .background(Color(.systemGray6)).cornerRadius(8)
    }
}

#Preview { ContentView() }
