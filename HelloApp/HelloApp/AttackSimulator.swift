import Foundation
import Darwin
import UIKit

// 注意: iOS 不允许第三方应用使用 dlopen/dlsym，本文件不包含任何 dlsym 调用
// 所有检测在普通 iOS 上安全运行，越狱设备上通过交叉验证检出

// csops 声明（与 JailbreakDetector 共享，同模块可见）
// @_silgen_name 已在 JailbreakDetector.swift 中声明

// MARK: - 攻击模拟结果
struct SimulationResult: Identifiable {
    let id = UUID()
    let layer: Int
    let layerName: String
    let attackMethod: String
    let detected: Bool
    let detail: String
}

// MARK: - 攻击模拟器
class AttackSimulator: ObservableObject {
    @Published var results: [SimulationResult] = []
    @Published var isCompromised = false

    func runAllSimulations() {
        results = []

        results.append(simulateLayer1_UserlandHook())
        results.append(simulateLayer2_KernelHook())
        results.append(simulateLayer3_LoadTimeFlags())
        results.append(simulateLayer4_ChainSpoofing())

        isCompromised = results.contains { $0.detected }
    }

    // ═══════════════════════════════════════════
    // Layer 1: 用户态 Hook 检测
    // 攻击: MSHookFunction(csops, fake, ...)
    // 防御: 失败即异常 — 正常iOS上csops不会失败
    // ═══════════════════════════════════════════
    private func simulateLayer1_UserlandHook() -> SimulationResult {
        var flags: UInt32 = 0
        let ret = csops(getpid(), 0, &flags, MemoryLayout<UInt32>.size)

        if ret != 0 {
            // csops 调用失败 — 正常iOS不会发生
            return SimulationResult(layer: 1, layerName: "用户态Hook",
                attackMethod: "MSHookFunction(csops)", detected: true,
                detail: "🚨 csops 返回 \(ret)（errno=\(errno)）→ 调用被拦截或系统异常")
        }

        // csops 成功，检查标志位
        if flags & 0x04 != 0 {  // get-task-allow
            return SimulationResult(layer: 1, layerName: "用户态Hook",
                attackMethod: "MSHook改写标志位", detected: false,
                detail: "ℹ️ get-task-allow 已开启 — 非AppStore签名特征\ncsops flags=0x\(String(flags, radix: 16))")
        }

        return SimulationResult(layer: 1, layerName: "用户态Hook",
            attackMethod: "MSHookFunction(csops)", detected: false,
            detail: "✅ csops 正常返回，标志位正常\ncsops flags=0x\(String(flags, radix: 16))")
    }

    // ═══════════════════════════════════════════
    // Layer 2: 内核 Syscall 表劫持
    // 攻击: checkra1n/palera1n 修改内核 sysent[169]
    // 防御: 交叉验证 — csops 说正常但文件系统异常 → 矛盾
    // ═══════════════════════════════════════════
    private func simulateLayer2_KernelHook() -> SimulationResult {
        var flags: UInt32 = 0
        let csopsOK = (csops(getpid(), 0, &flags, MemoryLayout<UInt32>.size) == 0)

        let suspiciousPaths = [
            "/var/jb",
            "/var/libexec",
            "/Library/MobileSubstrate",
            "/usr/lib/TweakInject",
            "/Applications/Cydia.app",
            "/Applications/Sileo.app",
            "/usr/bin/ssh"
        ]
        var foundPaths: [String] = []
        for path in suspiciousPaths {
            if access(path, F_OK) == 0 {
                foundPaths.append(path)
            }
        }

        let csopsClean = csopsOK && (flags & 0x04) == 0

        if csopsClean && !foundPaths.isEmpty {
            return SimulationResult(layer: 2, layerName: "内核劫持",
                attackMethod: "sysent[169] 伪造", detected: true,
                detail: "🚨 csops 说正常但文件系统发现: \(foundPaths.joined(separator: ", "))\n→ 交叉验证失败：csops结果不可信")
        }

        if !csopsOK {
            return SimulationResult(layer: 2, layerName: "内核劫持",
                attackMethod: "sysent[169] 伪造", detected: true,
                detail: "🚨 csops 调用失败 — 可能被内核层拦截")
        }

        return SimulationResult(layer: 2, layerName: "内核劫持",
            attackMethod: "sysent[169] 伪造", detected: false,
            detail: "✅ 交叉验证一致\ncsops flags=0x\(String(flags, radix: 16)), 文件系统未发现越狱路径")
    }

    // ═══════════════════════════════════════════
    // Layer 3: 进程加载时预清标志
    // 攻击: mach_loader 阶段清掉 get-task-allow
    // 防御: 检查 Mach 异常端口 + URL Schemes（不依赖 csops）
    // ═══════════════════════════════════════════
    private func simulateLayer3_LoadTimeFlags() -> SimulationResult {
        var signalsFound: [String] = []

        // 检查 Mach 异常端口（即使csops标志被清，端口依然在）
        let masks: [exception_mask_t] = [0x1FFE]
        for mask in masks {
            var ports = [mach_port_t](repeating: 0, count: 32)
            var exMasks = [exception_mask_t](repeating: 0, count: 32)
            var behaviors = [exception_behavior_t](repeating: 0, count: 32)
            var flavors = [thread_state_flavor_t](repeating: 0, count: 32)
            var count: mach_msg_type_number_t = 32

            let kr = task_get_exception_ports(
                mach_task_self_, mask,
                &exMasks, &count,
                &ports, &behaviors, &flavors
            )
            if kr == KERN_SUCCESS && count > 0 {
                signalsFound.append("Mach异常端口: \(count)个")
                break
            }
        }

        // 检查 URL Schemes（越狱商店特有的 scheme）
        let schemes = ["cydia://", "sileo://", "zbra://", "undecimus://"]
        for scheme in schemes {
            if let url = URL(string: scheme), UIApplication.shared.canOpenURL(url) {
                signalsFound.append("可疑URL Scheme: \(scheme)")
            }
        }

        if !signalsFound.isEmpty {
            return SimulationResult(layer: 3, layerName: "加载时清标志",
                attackMethod: "mach_loader 伪造", detected: true,
                detail: "🚨 端口/Scheme异常:\n\(signalsFound.joined(separator: "\n"))\n→ csops标志可能被清，但其他维度检出")
        }

        return SimulationResult(layer: 3, layerName: "加载时清标志",
            attackMethod: "mach_loader 伪造", detected: false,
            detail: "✅ 异常端口与URL Schemes均正常")
    }

    // ═══════════════════════════════════════════
    // Layer 4: 检测链欺骗
    // 攻击: Hook getpid / MemoryLayout / String格式化
    // 防御: 自完整性校验（不依赖 dlsym）
    // ═══════════════════════════════════════════
    private func simulateLayer4_ChainSpoofing() -> SimulationResult {
        var details: [String] = []

        // 1. getpid 一致性
        let pid1 = getpid()
        let pid2 = getpid()
        if pid1 != pid2 || pid1 <= 0 {
            return SimulationResult(layer: 4, layerName: "检测链欺骗",
                attackMethod: "Hook getpid", detected: true,
                detail: "🚨 getpid() 返回不一致: \(pid1) vs \(pid2)")
        }
        details.append("getpid 一致: \(pid1)")

        // 2. MemoryLayout 完整性
        let u32size = MemoryLayout<UInt32>.size
        if u32size != 4 {
            return SimulationResult(layer: 4, layerName: "检测链欺骗",
                attackMethod: "Hook MemoryLayout", detected: true,
                detail: "🚨 MemoryLayout<UInt32>.size = \(u32size) (应为 4)")
        }

        // 3. String 格式化完整性
        let testStr = String(format: "%d", 12345)
        if testStr != "12345" {
            return SimulationResult(layer: 4, layerName: "检测链欺骗",
                attackMethod: "Hook String格式化", detected: true,
                detail: "🚨 String(format:) 返回异常: '\(testStr)'")
        }

        // 4. 文件操作完整性（access 调用返回合理值）
        let homeAccess = access(NSHomeDirectory(), F_OK)
        if homeAccess != 0 {
            return SimulationResult(layer: 4, layerName: "检测链欺骗",
                attackMethod: "Hook access", detected: true,
                detail: "🚨 access(NSHomeDirectory()) 返回 \(homeAccess) → 文件系统调用被拦截")
        }

        // 5. 时间单调性检查
        let t1 = Date().timeIntervalSince1970
        let t2 = Date().timeIntervalSince1970
        if t2 < t1 {
            return SimulationResult(layer: 4, layerName: "检测链欺骗",
                attackMethod: "Hook Date", detected: true,
                detail: "🚨 时间倒退: t1=\(t1) t2=\(t2) → Date() 被篡改")
        }

        return SimulationResult(layer: 4, layerName: "检测链欺骗",
            attackMethod: "综合hook攻击", detected: false,
            detail: "✅ 检测链完整性通过\n\(details.joined(separator: "\n"))")
    }
}
