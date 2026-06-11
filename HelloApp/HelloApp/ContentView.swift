import SwiftUI

struct MainView: View {
    @EnvironmentObject var detector: JailbreakDetector
    @EnvironmentObject var hardware: HardwareInfo
    @EnvironmentObject var attackSimulator: AttackSimulator

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 16) {
                    // 越狱总览卡片
                    jailbreakSummaryCard

                    // 逐项检测结果
                    jailbreakChecksSection

                    // 攻击模拟防御测试
                    attackSimulationSection

                    // 硬件参数
                    hardwareSection
                }
                .padding()
            }
            .background(Color(.systemGroupedBackground))
            .navigationTitle("设备检测")
        }
    }

    // MARK: - 越狱总览
    var jailbreakSummaryCard: some View {
        let isJailbroken = detector.isJailbroken
        return VStack(spacing: 12) {
            Image(systemName: isJailbroken ? "exclamationmark.triangle.fill" : "checkmark.shield.fill")
                .font(.system(size: 48))
                .foregroundColor(isJailbroken ? .red : .green)

            Text(isJailbroken ? "⚠️ 检测到越狱" : "✅ 设备安全")
                .font(.title2)
                .fontWeight(.bold)

            Text(isJailbroken
                 ? "该设备存在越狱特征，安全风险较高"
                 : "未检测到越狱特征")
                .font(.subheadline)
                .foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 24)
        .background(Color(.systemBackground))
        .clipShape(RoundedRectangle(cornerRadius: 16))
        .shadow(color: .black.opacity(0.05), radius: 4, y: 2)
    }

    // MARK: - 逐项检测列表
    var jailbreakChecksSection: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Image(systemName: "shield.lefthalf.filled")
                Text("越狱检测项")
                    .font(.headline)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)

            Divider()

            ForEach(detector.results) { check in
                JailbreakCheckRow(check: check)
                if check.id != detector.results.last?.id {
                    Divider().padding(.leading, 56)
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

    // MARK: - 攻击模拟防御测试
    var attackSimulationSection: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Image(systemName: "shield.righthalf.filled")
                    .foregroundColor(attackSimulator.isCompromised ? .red : .green)
                Text("防御自检 (4层攻击模拟)")
                    .font(.headline)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)

            Divider()

            ForEach(attackSimulator.results) { result in
                SimulationRow(result: result)
                if result.id != attackSimulator.results.last?.id {
                    Divider().padding(.leading, 56)
                }
            }

            if attackSimulator.results.isEmpty {
                Text("点击下方按钮运行攻击模拟...")
                    .foregroundColor(.secondary)
                    .padding(16)
            }

            Button(action: { attackSimulator.runAllSimulations() }) {
                HStack {
                    Image(systemName: "play.fill")
                    Text("运行 4 层攻击模拟")
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 12)
                .background(Color.blue)
                .foregroundColor(.white)
                .clipShape(RoundedRectangle(cornerRadius: 10))
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
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
            .padding(.horizontal, 16)
            .padding(.vertical, 12)

            Divider()

            ForEach(hardware.parameters) { param in
                HardwareParamRow(param: param)
                if param.id != hardware.parameters.last?.id {
                    Divider().padding(.leading, 16)
                }
            }

            if hardware.parameters.isEmpty {
                Text("采集中...")
                    .foregroundColor(.secondary)
                    .padding(16)
            }
        }
        .background(Color(.systemBackground))
        .clipShape(RoundedRectangle(cornerRadius: 16))
    }
}

// MARK: - 越狱检测行
struct JailbreakCheckRow: View {
    let check: JailbreakCheck

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: check.isSuspicious ? "xmark.circle.fill" : "checkmark.circle.fill")
                .font(.title3)
                .foregroundColor(check.isSuspicious ? .red : .green)

            VStack(alignment: .leading, spacing: 2) {
                Text(check.name)
                    .font(.subheadline)
                    .fontWeight(.medium)
                Text(check.detail)
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            Spacer()

            Text(check.isSuspicious ? "⚠️" : "✅")
                .font(.caption)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
    }
}

// MARK: - 硬件参数行
struct HardwareParamRow: View {
    let param: HardwareParam

    var body: some View {
        HStack {
            Text(param.name)
                .font(.subheadline)
                .foregroundColor(.primary)

            Spacer()

            Text(param.value)
                .font(.subheadline)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.trailing)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
    }
}

// MARK: - 攻击模拟行
struct SimulationRow: View {
    let result: SimulationResult

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: result.detected ? "shield.slash.fill" : "shield.checkered")
                .font(.title3)
                .foregroundColor(result.detected ? .red : .green)

            VStack(alignment: .leading, spacing: 2) {
                HStack {
                    Text("Layer \(result.layer): \(result.layerName)")
                        .font(.subheadline)
                        .fontWeight(.medium)
                    Spacer()
                    Text(result.detected ? "🚨 检出" : "✅ 防住")
                        .font(.caption)
                        .fontWeight(.semibold)
                        .foregroundColor(result.detected ? .red : .green)
                }
                Text(result.detail)
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            Spacer()
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
    }
}

#Preview {
    MainView()
        .environmentObject(JailbreakDetector())
        .environmentObject(HardwareInfo())
}
