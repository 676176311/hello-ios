import Foundation
import Darwin
import UIKit

@_silgen_name("csops")
func csops(_ pid: pid_t, _ ops: UInt32, _ useraddr: UnsafeMutableRawPointer?, _ usersize: Int) -> Int32

// MARK: - 真实基线
struct BaselineSnapshot {
    let csopsFlags: UInt32
    let csopsRet: Int32
    let excPortCount: UInt32
    let excPortKR: Int32
    let pidConsistent: Bool
    let memLayoutOK: Bool
    let stringFormatOK: Bool
    let timeMonotonic: Bool
    let homeAccessOK: Bool
    let jbSchemes: [String]
}

func collectBaseline() -> BaselineSnapshot {
    var flags: UInt32 = 0
    let ret = csops(getpid(), 0, &flags, MemoryLayout<UInt32>.size)

    var portCnt: UInt32 = 0
    let mask: exception_mask_t = 0x1FFE
    var ports = [mach_port_t](repeating: 0, count: 32)
    var exMasks = [exception_mask_t](repeating: 0, count: 32)
    var behaviors = [exception_behavior_t](repeating: 0, count: 32)
    var flavors = [thread_state_flavor_t](repeating: 0, count: 32)
    var cnt: mach_msg_type_number_t = 32
    let kr = task_get_exception_ports(mach_task_self_, mask, &exMasks, &cnt, &ports, &behaviors, &flavors)
    if kr == KERN_SUCCESS { portCnt = cnt }

    let p1 = getpid(), p2 = getpid()
    let pidOK = p1 == p2 && p1 > 0
    let memOK = MemoryLayout<UInt32>.size == 4
    let strOK = String(format: "%d", 12345) == "12345"
    let t1 = Date().timeIntervalSince1970, t2 = Date().timeIntervalSince1970
    let timeOK = t2 >= t1
    let homeOK = access(NSHomeDirectory(), F_OK) == 0

    var schemes: [String] = []
    for s in ["cydia://", "sileo://", "zbra://"] {
        if let url = URL(string: s), UIApplication.shared.canOpenURL(url) { schemes.append(s) }
    }

    return BaselineSnapshot(
        csopsFlags: flags, csopsRet: ret,
        excPortCount: portCnt, excPortKR: kr,
        pidConsistent: pidOK, memLayoutOK: memOK,
        stringFormatOK: strOK, timeMonotonic: timeOK,
        homeAccessOK: homeOK, jbSchemes: schemes
    )
}

// MARK: - 结果结构

/// 攻击层结果
/// `detected`: 是否检出越狱
/// - 攻击OFF时 detected=true → 防御正常检出
/// - 攻击ON时 detected=false → 攻击成功绕过
struct AttackResult {
    let layer: Int
    let layerName: String
    let attackMethod: String
    let attackEnabled: Bool

    /// 攻击OFF时的真实检测结果
    let realStatus: String

    /// 攻击ON时的伪造结果说明
    let bypassDescription: String

    /// 防御方还能做什么（即使本层被绕过）
    let residualDefense: String
}

// MARK: - 模拟器
class AttackSimulator: ObservableObject {
    @Published var layer1: AttackResult?
    @Published var layer2: AttackResult?
    @Published var layer3: AttackResult?
    @Published var layer4: AttackResult?
    @Published var baseline: BaselineSnapshot?

    // ━━━ Layer 1: 用户态 Hook csops ━━━
    func testLayer1(attackEnabled: Bool) {
        let bl = baseline!
        let csopsOK = bl.csopsRet == 0
        let rawFlagStr = csopsOK ? "0x\(String(bl.csopsFlags, radix: 16))" : "调用失败"
        let hasGTA = csopsOK && ((bl.csopsFlags & 0x04) != 0)
        let realDetected = csopsOK && hasGTA

        if attackEnabled {
            layer1 = AttackResult(
                layer: 1,
                layerName: "用户态 Hook",
                attackMethod: "MSHookFunction(csops)",
                attackEnabled: true,
                realStatus: "真实系统: csops=\(rawFlagStr) → get-task-allow=\(hasGTA ? "ON" : "OFF")",
                bypassDescription: """
                【攻击生效】用 MSHookFunction 拦截 csops()
                csops 现在返回 flags=0x0 → get-task-allow=OFF
                注入进程的 dylib 在 csops 调用前篡改了返回值
                检测方看到的: 签名干净, 无越狱痕迹
                """,
                residualDefense: "文件系统交叉验证 (检查 /Applications/Cydia.app 等路径)"
            )
        } else {
            layer1 = AttackResult(
                layer: 1,
                layerName: "用户态 Hook",
                attackMethod: "MSHookFunction(csops)",
                attackEnabled: false,
                realStatus: "真实系统: csops=\(rawFlagStr)\n→ get-task-allow=\(hasGTA ? "ON ⚠️ 检出越狱" : "OFF ✅ 正常")",
                bypassDescription: "攻击未启用",
                residualDefense: ""
            )
        }
    }

    // ━━━ Layer 2: 内核 syscall 表劫持 ━━━
    func testLayer2(attackEnabled: Bool) {
        let bl = baseline!
        let csopsOK = bl.csopsRet == 0
        let rawFlagStr = csopsOK ? "0x\(String(bl.csopsFlags, radix: 16))" : "调用失败"
        let hasGTA = csopsOK && ((bl.csopsFlags & 0x04) != 0)

        if attackEnabled {
            layer2 = AttackResult(
                layer: 2,
                layerName: "内核 Syscall 劫持",
                attackMethod: "sysent[169] 伪造",
                attackEnabled: true,
                realStatus: "真实系统: csops=\(rawFlagStr) → get-task-allow=\(hasGTA ? "ON" : "OFF")",
                bypassDescription: """
                【攻击生效】修改内核 sysent[169] 表项 (csops 系统调用入口)
                内核直接返回伪造的代码签名标志 → 所有用户态调用均被欺骗
                比 Layer1 更彻底: Hook 在用户态, Syscall劫持在内核态
                任何通过 csops 的检测全部失效
                """,
                residualDefense: "直接遍历 proc 结构 (需要 root), 异常端口检测"
            )
        } else {
            layer2 = AttackResult(
                layer: 2,
                layerName: "内核 Syscall 劫持",
                attackMethod: "sysent[169] 伪造",
                attackEnabled: false,
                realStatus: "真实系统: csops=\(rawFlagStr)\n→ get-task-allow=\(hasGTA ? "ON ⚠️ 检出越狱" : "OFF ✅ 正常")",
                bypassDescription: "攻击未启用",
                residualDefense: ""
            )
        }
    }

    // ━━━ Layer 3: Mach Loader 预清标志 ━━━
    func testLayer3(attackEnabled: Bool) {
        let bl = baseline!
        let portDesc = bl.excPortCount > 0 ? "发现 \(bl.excPortCount) 个异常端口" : "无异常端口"
        let schemeDesc = bl.jbSchemes.isEmpty ? "无越狱Scheme" : bl.jbSchemes.joined(separator: ", ")
        let csopsOK = bl.csopsRet == 0
        let hasGTA = csopsOK && ((bl.csopsFlags & 0x04) != 0)
        let rawFlagStr = csopsOK ? "0x\(String(bl.csopsFlags, radix: 16))" : "调用失败"

        if attackEnabled {
            layer3 = AttackResult(
                layer: 3,
                layerName: "加载时清标志",
                attackMethod: "mach_loader 预清",
                attackEnabled: true,
                realStatus: "真实系统: csops=\(rawFlagStr)",
                bypassDescription: """
                【攻击生效】在 mach_loader 加载 App 二进制时
                提前清除 csops 中的 get-task-allow 等可疑标志
                代码还没开始执行, 标志已经被清空了
                csops 检测方看到的: 完全干净的签名标志
                这是最隐蔽的绕过方式之一
                """,
                residualDefense: "Mach 异常端口 (task_get_exception_ports), URL Schemes, 进程列表"
            )
        } else {
            layer3 = AttackResult(
                layer: 3,
                layerName: "加载时清标志",
                attackMethod: "mach_loader 预清",
                attackEnabled: false,
                realStatus: "真实系统: csops=\(rawFlagStr)\n→ get-task-allow=\(hasGTA ? "ON ⚠️ 检出越狱" : "OFF ✅ 正常")\n异常端口: \(portDesc)\nURL Schemes: \(schemeDesc)",
                bypassDescription: "攻击未启用",
                residualDefense: ""
            )
        }
    }

    // ━━━ Layer 4: 检测链全欺骗 ━━━
    func testLayer4(attackEnabled: Bool) {
        let bl = baseline!
        let csopsOK = bl.csopsRet == 0
        let hasGTA = csopsOK && ((bl.csopsFlags & 0x04) != 0)
        let rawFlagStr = csopsOK ? "0x\(String(bl.csopsFlags, radix: 16))" : "调用失败"

        var checks: [String] = []
        if bl.pidConsistent { checks.append("getpid ✓") } else { checks.append("getpid ✗") }
        if bl.memLayoutOK { checks.append("MemoryLayout ✓") } else { checks.append("MemoryLayout ✗") }
        if bl.stringFormatOK { checks.append("String(format:) ✓") } else { checks.append("String(format:) ✗") }
        if bl.timeMonotonic { checks.append("时间 ✓") } else { checks.append("时间倒退 ✗") }
        if bl.homeAccessOK { checks.append("access ✓") } else { checks.append("access ✗") }

        if attackEnabled {
            layer4 = AttackResult(
                layer: 4,
                layerName: "检测链全欺骗",
                attackMethod: "多函数 Hook",
                attackEnabled: true,
                realStatus: "真实系统: csops=\(rawFlagStr)\n自检: \(checks.joined(separator: ", "))",
                bypassDescription: """
                【攻击生效】Hook 整个检测链路:
                - getpid() → 返回伪造PID
                - MemoryLayout → 返回正常值
                - String(format:) → 格式化正常
                - Date() → 时间正常
                - access() → 文件不存在
                所有检测手段全部欺骗, 防御方无从下手
                这是最全面的攻击: 攻击者控制了整个检测链
                """,
                residualDefense: "硬件特征 (不可伪造), 内核断点检测, 代码完整性校验"
            )
        } else {
            layer4 = AttackResult(
                layer: 4,
                layerName: "检测链全欺骗",
                attackMethod: "多函数 Hook",
                attackEnabled: false,
                realStatus: "真实系统: csops=\(rawFlagStr)\n→ get-task-allow=\(hasGTA ? "ON ⚠️ 检出" : "OFF ✅ 正常")\n自检: \(checks.joined(separator: ", "))",
                bypassDescription: "攻击未启用",
                residualDefense: ""
            )
        }
    }
}
