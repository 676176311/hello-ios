import Foundation
import Darwin
import UIKit

// csops 声明（iOS 可用的代码签名检测 API）
@_silgen_name("csops")
func csops(_ pid: pid_t, _ ops: UInt32, _ useraddr: UnsafeMutableRawPointer?, _ usersize: Int) -> Int32

// MARK: - 单层攻击测试结果
struct LayerResult: Identifiable {
    let id = UUID()
    let layer: Int
    let layerName: String
    let attackMethod: String
    let attackEnabled: Bool   // 是否开启了模拟攻击
    let detected: Bool        // 防御是否检测到异常
    let baseline: String      // 正常基线值
    let attackDetail: String  // 攻击下的变化
}

// MARK: - 攻击模拟器（纯逻辑，无UI）
class AttackSimulator: ObservableObject {
    @Published var layerResults: [LayerResult] = [LayerResult](
        repeating: LayerResult(layer: 0, layerName: "", attackMethod: "", attackEnabled: false, detected: false, baseline: "", attackDetail: ""),
        count: 4
    )

    // ━━━ Layer 1: 用户态 Hook ━━━
    func testLayer1(attackEnabled: Bool) {
        var flags: UInt32 = 0
        let ret = csops(getpid(), 0, &flags, MemoryLayout<UInt32>.size)

        if attackEnabled {
            // 模拟: 攻击者 Hook 了 csops，返回假的干净标志
            // 检查点: csops 调用结果 + 文件系统交叉验证
            let suspiciousPaths = [
                "/Applications/Cydia.app",
                "/var/jb",
                "/Library/MobileSubstrate"
            ]
            var found: [String] = []
            for path in suspiciousPaths {
                if access(path, F_OK) == 0 { found.append(path) }
            }

            let csopsClean = (ret == 0 && (flags & 0x04) == 0)
            let detail: String
            if csopsClean && !found.isEmpty {
                detail = "csops说干净但文件系统发现 \(found.joined(separator: ",")) → 检测到Hook"
                layerResults[0] = LayerResult(layer: 1, layerName: "用户态Hook", attackMethod: "MSHook csops", attackEnabled: true, detected: true, baseline: "csops正常", attackDetail: detail)
            } else if ret != 0 {
                detail = "csops失败(ret=\(ret)) → csops被拦截"
                layerResults[0] = LayerResult(layer: 1, layerName: "用户态Hook", attackMethod: "MSHook csops", attackEnabled: true, detected: true, baseline: "csops正常", attackDetail: detail)
            } else {
                let flagStr = "0x\(String(flags, radix: 16))"
                detail = "csops=\(flagStr) get-task-allow=\((flags&0x04)!=0 ? "ON" : "OFF")"
                layerResults[0] = LayerResult(layer: 1, layerName: "用户态Hook", attackMethod: "MSHook csops", attackEnabled: true, detected: false, baseline: "csops正常", attackDetail: detail)
            }
        } else {
            let flagStr = "0x\(String(flags, radix: 16))"
            layerResults[0] = LayerResult(layer: 1, layerName: "用户态Hook", attackMethod: "MSHook csops", attackEnabled: false, detected: false, baseline: "csops=\(flagStr) 正常", attackDetail: "攻击未启用")
        }
    }

    // ━━━ Layer 2: 内核 Syscall 表劫持 ━━━
    func testLayer2(attackEnabled: Bool) {
        var flags: UInt32 = 0
        let csopsOK = (csops(getpid(), 0, &flags, MemoryLayout<UInt32>.size) == 0)
        let flagStr = "0x\(String(flags, radix: 16))"

        if attackEnabled {
            // 模拟: 内核 sysent[169] 被篡改，csops返回假结果
            // 检查点: 文件系统交叉验证
            let paths = [
                "/var/jb", "/usr/bin/ssh", "/usr/lib/TweakInject",
                "/Applications/Cydia.app", "/bin/bash"
            ]
            var found: [String] = []
            for p in paths {
                if access(p, F_OK) == 0 { found.append(p) }
            }
            let csopsClean = csopsOK && (flags & 0x04) == 0

            if csopsClean && !found.isEmpty {
                layerResults[1] = LayerResult(layer: 2, layerName: "内核劫持", attackMethod: "sysent[169]伪造", attackEnabled: true, detected: true, baseline: "csops=\(flagStr) 正常", attackDetail: "文件系统发现: \(found.joined(separator: ",")) → 交叉验证失败")
            } else if !csopsOK {
                layerResults[1] = LayerResult(layer: 2, layerName: "内核劫持", attackMethod: "sysent[169]伪造", attackEnabled: true, detected: true, baseline: "csops正常", attackDetail: "csops调用失败 → 内核层异常")
            } else {
                layerResults[1] = LayerResult(layer: 2, layerName: "内核劫持", attackMethod: "sysent[169]伪造", attackEnabled: true, detected: false, baseline: "csops=\(flagStr) 正常", attackDetail: "交叉验证一致，未检测到劫持")
            }
        } else {
            layerResults[1] = LayerResult(layer: 2, layerName: "内核劫持", attackMethod: "sysent[169]伪造", attackEnabled: false, detected: false, baseline: "csops=\(flagStr) 正常", attackDetail: "攻击未启用")
        }
    }

    // ━━━ Layer 3: Mach 加载时清标志 ━━━
    func testLayer3(attackEnabled: Bool) {
        var signals: [String] = []

        if attackEnabled {
            // 模拟: mach_loader 阶段清除了 csops 的 get-task-allow 标志
            // 检查点: 异常端口 + URL Schemes（不依赖 csops）
            let mask: exception_mask_t = 0x1FFE
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
                signals.append("异常端口: \(count)个")
            } else {
                signals.append("异常端口: 无")
            }

            // URL Schemes
            let schemes = ["cydia://", "sileo://", "zbra://"]
            for s in schemes {
                if let url = URL(string: s), UIApplication.shared.canOpenURL(url) {
                    signals.append("Scheme: \(s)")
                }
            }

            let detected = signals.contains { $0.contains("端口") && !$0.contains("无") } || signals.contains { $0.contains("Scheme") }
            if detected {
                layerResults[2] = LayerResult(layer: 3, layerName: "加载时清标志", attackMethod: "mach_loader伪造", attackEnabled: true, detected: true, baseline: "csops正常(可能被清)", attackDetail: signals.joined(separator: ", "))
            } else {
                layerResults[2] = LayerResult(layer: 3, layerName: "加载时清标志", attackMethod: "mach_loader伪造", attackEnabled: true, detected: false, baseline: "csops正常", attackDetail: "端口+Scheme均正常")
            }
        } else {
            layerResults[2] = LayerResult(layer: 3, layerName: "加载时清标志", attackMethod: "mach_loader伪造", attackEnabled: false, detected: false, baseline: "csops正常", attackDetail: "攻击未启用")
        }
    }

    // ━━━ Layer 4: 检测链欺骗 ━━━
    func testLayer4(attackEnabled: Bool) {
        var checks: [String] = []
        var failed = false

        // getpid 一致性
        let p1 = getpid(), p2 = getpid()
        if p1 != p2 || p1 <= 0 {
            checks.append("getpid异常: \(p1)≠\(p2)")
            failed = true
        } else {
            checks.append("getpid=\(p1) ✓")
        }

        // MemoryLayout
        if MemoryLayout<UInt32>.size != 4 {
            checks.append("MemoryLayout异常")
            failed = true
        } else {
            checks.append("MemoryLayout<UInt32>=4 ✓")
        }

        // String格式化
        if String(format: "%d", 12345) != "12345" {
            checks.append("String格式化异常")
            failed = true
        } else {
            checks.append("String(format:) ✓")
        }

        // 时间单调
        let t1 = Date().timeIntervalSince1970
        let t2 = Date().timeIntervalSince1970
        if t2 < t1 {
            checks.append("时间倒退!")
            failed = true
        } else {
            checks.append("时间单调 ✓")
        }

        // access正常
        if access(NSHomeDirectory(), F_OK) != 0 {
            checks.append("access异常")
            failed = true
        } else {
            checks.append("access() ✓")
        }

        if attackEnabled {
            // 模拟环境下，检测到任何异常都是有效检出
            if failed {
                layerResults[3] = LayerResult(layer: 4, layerName: "检测链欺骗", attackMethod: "多函数Hook", attackEnabled: true, detected: true, baseline: "检测链完整", attackDetail: "异常: \(checks.filter{$0.contains("异常")||$0.contains("≠")||$0.contains("倒退")}.joined(separator: "; "))")
            } else {
                layerResults[3] = LayerResult(layer: 4, layerName: "检测链欺骗", attackMethod: "多函数Hook", attackEnabled: true, detected: false, baseline: "检测链完整", attackDetail: "5项检查全通过: \(checks.joined(separator: ", "))")
            }
        } else {
            layerResults[3] = LayerResult(layer: 4, layerName: "检测链欺骗", attackMethod: "多函数Hook", attackEnabled: false, detected: false, baseline: "检测链完整: \(checks.joined(separator: ", "))", attackDetail: "攻击未启用")
        }
    }
}
