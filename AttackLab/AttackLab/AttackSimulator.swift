import Foundation
import Darwin
import UIKit

@_silgen_name("csops")
func csops(_ pid: pid_t, _ ops: UInt32, _ useraddr: UnsafeMutableRawPointer?, _ usersize: Int) -> Int32

// ━━━ 真实基线 ━━━
struct BaselineSnapshot {
    let csopsFlags: UInt32
    let csopsRet: Int32
    let csopsHasGTA: Bool
    let excPortCount: UInt32
    let jbSchemes: [String]
    let selfChecksPassed: Bool
    let selfCheckDetails: [String]
}

func collectBaseline() -> BaselineSnapshot {
    var flags: UInt32 = 0
    let ret = csops(getpid(), 0, &flags, MemoryLayout<UInt32>.size)
    let hasGTA = ret == 0 && ((flags & 0x04) != 0)

    var portCnt: UInt32 = 0
    let mask: exception_mask_t = 0x1FFE
    var ports = [mach_port_t](repeating: 0, count: 32)
    var exMasks = [exception_mask_t](repeating: 0, count: 32)
    var behaviors = [exception_behavior_t](repeating: 0, count: 32)
    var flavors = [thread_state_flavor_t](repeating: 0, count: 32)
    var cnt: mach_msg_type_number_t = 32
    let kr = task_get_exception_ports(mach_task_self_, mask, &exMasks, &cnt, &ports, &behaviors, &flavors)
    if kr == KERN_SUCCESS { portCnt = cnt }

    var schemes: [String] = []
    for s in ["cydia://", "sileo://", "zbra://"] {
        if let url = URL(string: s), UIApplication.shared.canOpenURL(url) { schemes.append(s) }
    }

    let p1 = getpid(), p2 = getpid()
    let pidOK = p1 == p2 && p1 > 0
    let memOK = MemoryLayout<UInt32>.size == 4
    let strOK = String(format: "%d", 12345) == "12345"
    let t1 = Date().timeIntervalSince1970, t2 = Date().timeIntervalSince1970
    let timeOK = t2 >= t1
    let homeOK = access(NSHomeDirectory(), F_OK) == 0
    let allPassed = pidOK && memOK && strOK && timeOK && homeOK

    var details: [String] = []
    details.append(pidOK ? "getpid ✓" : "getpid ✗")
    details.append(memOK ? "MemoryLayout ✓" : "MemoryLayout ✗")
    details.append(strOK ? "String ✓" : "String ✗")
    details.append(timeOK ? "时间 ✓" : "时间 ✗")
    details.append(homeOK ? "access ✓" : "access ✗")

    return BaselineSnapshot(
        csopsFlags: flags, csopsRet: ret, csopsHasGTA: hasGTA,
        excPortCount: portCnt, jbSchemes: schemes,
        selfChecksPassed: allPassed, selfCheckDetails: details
    )
}

// MARK: - 攻击层结果
struct AttackResult: Equatable {
    let layer: Int
    let layerName: String
    let attackEnabled: Bool

    /// 攻击ON时 vs 攻击OFF时的 csops 显示值
    let csopsShown: String      // "0x4" or "0x0"
    let gtaShown: String         // "ON ⚠️" or "OFF ✅"
    let detectedShown: Bool      // attack OFF: true (检出); attack ON: false (干净)

    let method: String           // 攻击方法
    let howItWorks: String       // 攻击原理
    let residualDefense: String  // 残留防御
}

class AttackSimulator: ObservableObject {
    @Published var results: [AttackResult] = []
    @Published var baseline: BaselineSnapshot?

    private func fakeClean(layer: Int, name: String, method: String, how: String, residual: String) -> AttackResult {
        return AttackResult(
            layer: layer, layerName: name, attackEnabled: true,
            csopsShown: "0x0", gtaShown: "OFF ✅",
            detectedShown: false,
            method: method, howItWorks: how, residualDefense: residual
        )
    }

    private func realResult(layer: Int, name: String, baseline: BaselineSnapshot) -> AttackResult {
        let flagStr = baseline.csopsRet == 0 ? "0x\(String(baseline.csopsFlags, radix: 16))" : "失败"
        let hasGTA = baseline.csopsHasGTA
        return AttackResult(
            layer: layer, layerName: name, attackEnabled: false,
            csopsShown: flagStr,
            gtaShown: hasGTA ? "ON ⚠️ 检出" : "OFF ✅ 正常",
            detectedShown: hasGTA,
            method: "无", howItWorks: "真实系统, 未开启攻击",
            residualDefense: ""
        )
    }

    func runAll(attackEnabled: Bool) {
        guard let bl = baseline else { return }
        var out: [AttackResult] = []

        // Layer 1: 用户态 Hook
        if attackEnabled {
            out.append(fakeClean(
                layer: 1, name: "用户态 Hook",
                method: "MSHookFunction 拦截 csops()",
                how: "注入 dylib → MSHookFunction 劫持 csops 入口 → 返回假 flags=0x0。检测方调用 csops 拿到的永远是干净值。",
                residual: "文件系统交叉验证: 直接检查 /Applications/Cydia.app 等路径是否存在"
            ))
        } else {
            out.append(realResult(layer: 1, name: "用户态 Hook", baseline: bl))
        }

        // Layer 2: 内核 Syscall 劫持
        if attackEnabled {
            out.append(fakeClean(
                layer: 2, name: "内核 Syscall 劫持",
                method: "篡改 sysent[169] (csops入口)",
                how: "内核级漏洞修改 syscall 表 → csops 系统调用直接返回伪造结果。所有用户态检测(包括绕过 Layer1 Hook)全部失效。",
                residual: "直接遍历内核 proc 列表 (需 root), 异常端口检测 (task_get_exception_ports)"
            ))
        } else {
            out.append(realResult(layer: 2, name: "内核 Syscall 劫持", baseline: bl))
        }

        // Layer 3: 加载时清标志
        if attackEnabled {
            out.append(fakeClean(
                layer: 3, name: "加载时清标志",
                method: "mach_loader 阶段预清除",
                how: "在 App 二进制被 mach_loader 加载时, 篡改代码签名标志 → 代码尚未执行, 标志已被清空。csops 从源头就无法检测。",
                residual: "URL Schemes (cydia://), 异常端口, /var/jb 文件存在性"
            ))
        } else {
            out.append(realResult(layer: 3, name: "加载时清标志", baseline: bl))
        }

        // Layer 4: 检测链全欺骗
        if attackEnabled {
            out.append(fakeClean(
                layer: 4, name: "检测链全欺骗",
                method: "Hook getpid / String / Date / access",
                how: "Hook 整个检测链路 → getpid 返回伪造PID, String(format:) 格式化正常, Date 时间正常, access 返回假。防御的所有自检手段全部被欺骗, 彻底无法检测。",
                residual: "硬件特征(不可伪造), 内核断点检测, 二进制代码完整性 hash 校验"
            ))
        } else {
            out.append(realResult(layer: 4, name: "检测链全欺骗", baseline: bl))
        }

        results = out
    }
}
