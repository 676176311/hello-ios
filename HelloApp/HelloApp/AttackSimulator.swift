import Foundation
import Darwin

// MARK: - 攻击模拟结果
struct SimulationResult: Identifiable {
    let id = UUID()
    let layer: Int
    let layerName: String
    let attackMethod: String
    let detected: Bool      // 我们的防御是否检测到了攻击
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
    // 防御: libSystem路径 vs 原始syscall 对比
    // ═══════════════════════════════════════════
    private func simulateLayer1_UserlandHook() -> SimulationResult {
        var details: [String] = []

        // 路径A: libSystem 直接调用 csops
        var flagsA: UInt32 = 0
        let retA = csops(getpid(), 0, &flagsA, MemoryLayout<UInt32>.size)

        // 路径B: dlsym 动态解析（绕过编译期符号绑定）
        var flagsB: UInt32 = 0
        var retB: Int32 = -1
        guard let handle = dlopen(nil, RTLD_NOW) else {
            return SimulationResult(layer: 1, layerName: "用户态Hook",
                attackMethod: "MSHookFunction(csops)", detected: true,
                detail: "dlsym 失败（异常：动态链接器不可用）")
        }
        defer { dlclose(handle) }
        if let sym = dlsym(handle, "csops") {
            typealias CSOpsFn = @convention(c) (pid_t, UInt32, UnsafeMutableRawPointer?, Int) -> Int32
            let fn = unsafeBitCast(sym, to: CSOpsFn.self)
            retB = fn(getpid(), 0, &flagsB, MemoryLayout<UInt32>.size)
        }

        // 路径C: 原始 syscall（尽可能接近内核）
        var flagsC: UInt32 = 0
        let retC = Int32(syscall(169, getpid(), 0, &flagsC, MemoryLayout<UInt32>.size))

        details.append("libSystem: ret=\(retA) flags=0x\(String(flagsA, radix: 16))")
        details.append("dlsym:    ret=\(retB) flags=0x\(String(flagsB, radix: 16))")
        details.append("syscall:  ret=\(retC) flags=0x\(String(flagsC, radix: 16))")

        // 检测逻辑
        if retA == 0 && retB == 0 && flagsA != flagsB {
            return SimulationResult(layer: 1, layerName: "用户态Hook",
                attackMethod: "MSHookFunction(csops)", detected: true,
                detail: "🚨 libSystem 与 dlsym 结果不一致 → csops 被 hook!\n" + details.joined(separator: "\n"))
        }
        if retA == 0 && retC == 0 && flagsA != flagsC {
            return SimulationResult(layer: 1, layerName: "用户态Hook",
                attackMethod: "MSHookFunction(csops)", detected: true,
                detail: "🚨 libSystem 与 syscall 结果不一致 → csops 被 hook!\n" + details.joined(separator: "\n"))
        }
        if retA != 0 && retB == 0 {
            return SimulationResult(layer: 1, layerName: "用户态Hook",
                attackMethod: "MSHookFunction(csops)", detected: true,
                detail: "🚨 libSystem 调用失败但 dlsym 成功 → csops 被拦截!\n" + details.joined(separator: "\n"))
        }

        return SimulationResult(layer: 1, layerName: "用户态Hook",
            attackMethod: "MSHookFunction(csops)", detected: false,
            detail: "✅ 三路径一致，未检测到用户态 hook\n" + details.joined(separator: "\n"))
    }

    // ═══════════════════════════════════════════
    // Layer 2: 内核 Syscall 表劫持
    // 攻击: checkra1n/palera1n 修改内核 sysent[169]
    // 防御: 交叉验证——csops 不等于真相，要跟其他维度比对
    // ═══════════════════════════════════════════
    private func simulateLayer2_KernelHook() -> SimulationResult {
        // csops 读数
        var flags: UInt32 = 0
        let csopsOK = (csops(getpid(), 0, &flags, MemoryLayout<UInt32>.size) == 0)

        // 快速文件系统交叉检查（内核劫持通常会漏掉文件层）
        let suspiciousPaths = [
            "/var/jb",
            "/var/libexec",
            "/Library/MobileSubstrate",
            "/usr/lib/TweakInject",
            "/Applications/Cydia.app"
        ]
        var foundPaths: [String] = []
        for path in suspiciousPaths {
            if access(path, F_OK) == 0 {
                foundPaths.append(path)
            }
        }

        let csopsClean = csopsOK && (flags & 0x04) == 0  // get-task-allow 没开

        if csopsClean && !foundPaths.isEmpty {
            return SimulationResult(layer: 2, layerName: "内核劫持",
                attackMethod: "sysent[169] 伪造", detected: true,
                detail: "🚨 csops 说正常但文件系统发现: \(foundPaths.joined(separator: ", "))\n→ 交叉验证失败：csops 结果不可信")
        }

        if !csopsOK {
            return SimulationResult(layer: 2, layerName: "内核劫持",
                attackMethod: "sysent[169] 伪造", detected: true,
                detail: "🚨 csops 本身调用失败 (\(flags)) → 可能被内核层拦截")
        }

        return SimulationResult(layer: 2, layerName: "内核劫持",
            attackMethod: "sysent[169] 伪造", detected: false,
            detail: "✅ csops 与文件系统交叉验证一致\ncsops flags=0x\(String(flags, radix: 16)), 文件系统未发现越狱路径")
    }

    // ═══════════════════════════════════════════
    // Layer 3: 进程加载时预清标志
    // 攻击: mach_loader 阶段清掉 get-task-allow
    // 防御: 检查 Mach 异常端口——即使 csops 正常，端口异常也是信号
    // ═══════════════════════════════════════════
    private func simulateLayer3_LoadTimeFlags() -> SimulationResult {
        var details: [String] = []

        // 检查异常端口
        var exceptionDetected = false
        let masks: [exception_mask_t] = [
            0x1FFE, // EXC_MASK_ALL equivalent
        ]

        for mask in masks {
            var ports = [exception_mask_t](repeating: 0, count: 32)
            var masks = [exception_mask_t](repeating: 0, count: 32)
            var behaviors = [exception_behavior_t](repeating: 0, count: 32)
            var flavors = [thread_state_flavor_t](repeating: 0, count: 32)
            var count: mach_msg_type_number_t = 32

            let kr = task_get_exception_ports(
                mach_task_self_,
                mask,
                &masks,
                &count,
                &ports,
                &behaviors,
                &flavors
            )
            if kr == KERN_SUCCESS && count > 0 {
                exceptionDetected = true
                details.append("异常端口数: \(count)")
                break
            }
        }

        // 检查 Mach 服务
        let jailbreakServices = [
            "com.saurik.substrated",
            "com.rpetrich.rocketbootstrap",
            "org.coolstar.ellekit.loader2"
        ]
        for svc in jailbreakServices {
            var port: mach_port_t = 0
            let kr = bootstrap_look_up(_bootstrap_port, (svc as NSString).utf8String, &port)
            if kr == KERN_SUCCESS {
                exceptionDetected = true
                details.append("Mach服务存在: \(svc)")
            }
        }

        if exceptionDetected {
            return SimulationResult(layer: 3, layerName: "加载时清标志",
                attackMethod: "mach_loader 伪造", detected: true,
                detail: "🚨 进程间通信异常:\n\(details.joined(separator: "\n"))\n→ 即使 csops 被清，端口/服务异常检出")
        }

        return SimulationResult(layer: 3, layerName: "加载时清标志",
            attackMethod: "mach_loader 伪造", detected: false,
            detail: "✅ 异常端口与 Mach 服务均正常")
    }

    // ═══════════════════════════════════════════
    // Layer 4: 检测链欺骗
    // 攻击: Hook getpid / MemoryLayout / checkCSOps
    // 防御: 自完整性校验
    // ═══════════════════════════════════════════
    private func simulateLayer4_ChainSpoofing() -> SimulationResult {
        var details: [String] = []

        // 1. getpid 完整性：多次调用对比
        let pid1 = getpid()
        let pid2 = getpid()
        let pid3 = getpid()
        if pid1 != pid2 || pid2 != pid3 || pid1 <= 0 {
            return SimulationResult(layer: 4, layerName: "检测链欺骗",
                attackMethod: "Hook getpid", detected: true,
                detail: "🚨 getpid() 返回不一致: \(pid1), \(pid2), \(pid3)")
        }
        details.append("getpid 一致: \(pid1)")

        // 2. MemoryLayout 完整性（简单算术验证）
        let u32size = MemoryLayout<UInt32>.size
        if u32size != 4 {
            return SimulationResult(layer: 4, layerName: "检测链欺骗",
                attackMethod: "Hook MemoryLayout", detected: true,
                detail: "🚨 MemoryLayout<UInt32>.size = \(u32size) (应为 4) → 被篡改")
        }

        // 3. dlsym 方式获取 csops，验证函数地址是否合理
        guard let handle = dlopen(nil, RTLD_NOW) else {
            return SimulationResult(layer: 4, layerName: "检测链欺骗",
                attackMethod: "Hook dlsym", detected: true,
                detail: "🚨 dlopen(nil) 失败 → 动态链接器被篡改")
        }
        defer { dlclose(handle) }

        if let sym = dlsym(handle, "csops") {
            let addr = UInt(bitPattern: sym)
            // 正常 dylib 地址应该在较高范围 (> 0x100000000)
            if addr < 0x100000000 {
                return SimulationResult(layer: 4, layerName: "检测链欺骗",
                    attackMethod: "Hook dlsym 返回假指针", detected: true,
                    detail: "🚨 csops 函数地址异常: 0x\(String(addr, radix: 16)) → 可能是 hook 返回的替代地址")
            }
            details.append("csops 地址正常: 0x\(String(addr, radix: 16))")
        }

        // 4. 基础 C 函数调用是否返回预期值
        let digitCount = snprintf(nil, 0, "%d", 12345)
        if digitCount != 5 {
            return SimulationResult(layer: 4, layerName: "检测链欺骗",
                attackMethod: "Hook snprintf", detected: true,
                detail: "🚨 snprintf 返回异常: \(digitCount) (应为 5) → C 运行时被篡改")
        }

        return SimulationResult(layer: 4, layerName: "检测链欺骗",
            attackMethod: "综合hook攻击", detected: false,
            detail: "✅ 检测链完整性通过\n\(details.joined(separator: "\n"))")
    }
}
