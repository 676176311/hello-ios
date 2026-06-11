import Foundation
import Darwin
import UIKit

// csops 声明（iOS 可用的代码签名检测 API）
@_silgen_name("csops")
func csops(_ pid: pid_t, _ ops: UInt32, _ useraddr: UnsafeMutableRawPointer?, _ usersize: Int) -> Int32

// ━━━ 通用基线采集 ━━━
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
    let strOK = (String(format: "%d", 12345) == "12345")
    let t1 = Date().timeIntervalSince1970
    let t2 = Date().timeIntervalSince1970
    let timeOK = t2 >= t1
    let homeOK = access(NSHomeDirectory(), F_OK) == 0

    var schemes: [String] = []
    for s in ["cydia://", "sileo://", "zbra://"] {
        if let url = URL(string: s), UIApplication.shared.canOpenURL(url) {
            schemes.append(s)
        }
    }

    return BaselineSnapshot(
        csopsFlags: flags, csopsRet: ret,
        excPortCount: portCnt, excPortKR: kr,
        pidConsistent: pidOK, memLayoutOK: memOK,
        stringFormatOK: strOK, timeMonotonic: timeOK,
        homeAccessOK: homeOK, jbSchemes: schemes
    )
}

// MARK: - 单层攻击测试结果
struct LayerResult {
    let layer: Int
    let layerName: String
    let attackMethod: String
    let attackEnabled: Bool
    let detected: Bool
    let safeDetail: String    // 正常基线详情
    let attackDetail: String  // 攻击模拟详情
}

// MARK: - 攻击模拟器
class AttackSimulator: ObservableObject {
    @Published var layer1: LayerResult?
    @Published var layer2: LayerResult?
    @Published var layer3: LayerResult?
    @Published var layer4: LayerResult?
    @Published var baseline: BaselineSnapshot?

    // ━━━ Layer 1: 用户态 Hook ━━━
    func testLayer1(attackEnabled: Bool) {
        let bl = baseline!
        let flagStr = bl.csopsRet == 0 ? "0x\(String(bl.csopsFlags, radix: 16))" : "调用失败"
        let csopsOK = bl.csopsRet == 0
        let hasGTA = csopsOK && (bl.csopsFlags & 0x04) != 0

        if attackEnabled {
            // 模拟: 攻击者用 MSHookFunction 拦截了 csops, 让它返回干净标志（假装没有 get-task-allow）
            // 但防御通过文件系统交叉验证发现了越狱痕迹
            let fakePaths = ["/Applications/Cydia.app", "/Library/MobileSubstrate/MobileSubstrate.dylib"]
            layer1 = LayerResult(
                layer: 1, layerName: "用户态Hook",
                attackMethod: "MSHookFunction(csops)",
                attackEnabled: true, detected: true,
                safeDetail: "真实csops=\(flagStr) get-task-allow=\(hasGTA ? "ON" : "OFF")",
                attackDetail: """
                【攻击】Hook了csops, 让它返回 flags=0x0 (伪装干净)
                【防御】文件交叉验证发现: \(fakePaths.joined(separator: ", "))
                【结论】csops说干净但Cydia存在 → 击穿了Hook伪装
                """
            )
        } else {
            layer1 = LayerResult(
                layer: 1, layerName: "用户态Hook",
                attackMethod: "MSHookFunction(csops)",
                attackEnabled: false, detected: false,
                safeDetail: "真实csops=\(flagStr) get-task-allow=\(hasGTA ? "ON (开发签名正常)" : "OFF")",
                attackDetail: "攻击未启用, 系统运行正常"
            )
        }
    }

    // ━━━ Layer 2: 内核 Syscall 表劫持 ━━━
    func testLayer2(attackEnabled: Bool) {
        let bl = baseline!
        let flagStr = bl.csopsRet == 0 ? "0x\(String(bl.csopsFlags, radix: 16))" : "调用失败"
        let csopsOK = bl.csopsRet == 0
        let hasGTA = csopsOK && (bl.csopsFlags & 0x04) != 0

        if attackEnabled {
            // 模拟: checkra1n 级内核漏洞, 直接改 sysent[169] (csops 入口)
            // csops 返回完全伪造的值, 但文件系统无法隐藏
            let fakePaths = ["/var/jb", "/usr/bin/ssh", "/bin/bash"]
            layer2 = LayerResult(
                layer: 2, layerName: "内核Syscall劫持",
                attackMethod: "sysent[169]伪造",
                attackEnabled: true, detected: true,
                safeDetail: "真实csops=\(flagStr) get-task-allow=\(hasGTA ? "ON" : "OFF")",
                attackDetail: """
                【攻击】内核级漏洞篡改sysent[169], csops直接返回虚假结果
                【防御】绕过csops, 直接检查文件系统:
                发现: \(fakePaths.joined(separator: ", "))
                【结论】内核级也可通过IO交叉验证检出
                """
            )
        } else {
            layer2 = LayerResult(
                layer: 2, layerName: "内核Syscall劫持",
                attackMethod: "sysent[169]伪造",
                attackEnabled: false, detected: false,
                safeDetail: "真实csops=\(flagStr) get-task-allow=\(hasGTA ? "ON (开发签名正常)" : "OFF")",
                attackDetail: "攻击未启用, 内核层正常"
            )
        }
    }

    // ━━━ Layer 3: Mach 加载时清标志 ━━━
    func testLayer3(attackEnabled: Bool) {
        let bl = baseline!
        let portDesc = bl.excPortCount > 0 ? "\(bl.excPortCount)个端口" : "无异常端口"
        let schemeDesc = bl.jbSchemes.isEmpty ? "无越狱Scheme" : bl.jbSchemes.joined(separator: ",")

        if attackEnabled {
            // 模拟: mach_loader 阶段清掉了 csops 标志
            // 但异常端口和 URL Schemes 暴露了真相
            layer3 = LayerResult(
                layer: 3, layerName: "加载时清标志",
                attackMethod: "mach_loader预清csops",
                attackEnabled: true, detected: true,
                safeDetail: "异常端口: \(portDesc), URL Schemes: \(schemeDesc)",
                attackDetail: """
                【攻击】在mach_loader阶段提前清除了get-task-allow标志
                【防御】不依赖csops, 改用:
                - 异常端口检测: 发现 debugserver 注册了异常端口
                - URL Schemes: 发现 cydia:// 可响应
                【结论】csops可被绕过, 但端口和Scheme无法隐藏
                """
            )
        } else {
            layer3 = LayerResult(
                layer: 3, layerName: "加载时清标志",
                attackMethod: "mach_loader预清csops",
                attackEnabled: false, detected: false,
                safeDetail: "异常端口: \(portDesc), URL Schemes: \(schemeDesc)",
                attackDetail: "攻击未启用, Mach层正常"
            )
        }
    }

    // ━━━ Layer 4: 检测链欺骗 ━━━
    func testLayer4(attackEnabled: Bool) {
        let bl = baseline!
        var checks: [String] = []
        if bl.pidConsistent { checks.append("getpid ✓") } else { checks.append("getpid ✗") }
        if bl.memLayoutOK { checks.append("MemoryLayout ✓") } else { checks.append("MemoryLayout ✗") }
        if bl.stringFormatOK { checks.append("String(format:) ✓") } else { checks.append("String(format:) ✗") }
        if bl.timeMonotonic { checks.append("时间单调 ✓") } else { checks.append("时间倒退 ✗") }
        if bl.homeAccessOK { checks.append("access() ✓") } else { checks.append("access() ✗") }

        if attackEnabled {
            // 模拟: 攻击者 Hook 了多个底层函数来欺骗检测链
            layer4 = LayerResult(
                layer: 4, layerName: "检测链欺骗",
                attackMethod: "多函数Hook",
                attackEnabled: true, detected: true,
                safeDetail: "5项检查: \(checks.joined(separator: ", "))",
                attackDetail: """
                【攻击】Hook getpid/MemoryLayout/String/Date/access 破坏检测链
                【防御】多重自检:
                - getpid()连续调用发现不一致
                - MemoryLayout<UInt32>.size异常
                - String(format:)格式化异常
                【结论】攻击者要Hook全链路, 任一遗漏即暴露
                """
            )
        } else {
            layer4 = LayerResult(
                layer: 4, layerName: "检测链欺骗",
                attackMethod: "多函数Hook",
                attackEnabled: false, detected: false,
                safeDetail: "5项检查: \(checks.joined(separator: ", "))",
                attackDetail: "攻击未启用, 检测链完整"
            )
        }
    }
}
