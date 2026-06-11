import Foundation
import UIKit
import Darwin

// MARK: - 结果模型
struct JailbreakCheck: Identifiable {
    let id = UUID()
    let name: String
    let isSuspicious: Bool
    let detail: String
}

// MARK: - csops 申明
@_silgen_name("csops")
func csops(_ pid: pid_t, _ ops: UInt32, _ useraddr: UnsafeMutableRawPointer?, _ usersize: Int) -> Int32

// bootstrap_port 全局变量（Xcode 16 Swift 无法直接访问，用 @_silgen_name 桥接）
@_silgen_name("bootstrap_port")
var _bootstrap_port: mach_port_t

// MARK: - bootstrap_look_up 申明
@_silgen_name("bootstrap_look_up")
func bootstrap_look_up(_ bp: mach_port_t, _ service_name: UnsafePointer<CChar>, _ sp: UnsafeMutablePointer<mach_port_t>) -> kern_return_t

// MARK: - ═════════════ 越狱检测主类 ═════════════
class JailbreakDetector: ObservableObject {
    @Published var results: [JailbreakCheck] = []
    @Published var isJailbroken: Bool = false

    func runAllChecks() {
        var checks: [JailbreakCheck] = []

        // ━━━━━━━━━ 一、文件系统检测 ━━━━━━━━━
        // ── 1. 传统 rootful 越狱路径 ──
        let classicPaths = [
            "/Applications/Cydia.app",
            "/Applications/Sileo.app",
            "/Applications/Zebra.app",
            "/Applications/Installer.app",
            "/Applications/blackra1n.app",
            "/Applications/FakeCarrier.app",
            "/Applications/Icy.app",
            "/Applications/IntelliScreen.app",
            "/Applications/MxTube.app",
            "/Applications/RockApp.app",
            "/Applications/WinterBoard.app",
            "/private/var/lib/apt",
            "/private/var/lib/cydia",
            "/private/var/lib/dpkg",
            "/private/var/mobile/Library/SBSettings/Themes",
            "/private/var/tmp/cydia.log",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
            "/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
            "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
            "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
            "/private/var/stash",
            "/private/var/log/syslog",
            "/private/etc/ssh/sshd_config",
            "/usr/sbin/sshd",
            "/usr/bin/sshd",
            "/etc/apt",
            "/etc/ssh/sshd_config",
            "/usr/libexec/ssh-keysign",
            "/bin/bash",
            "/bin/sh",
            "/usr/libexec/sftp-server",
        ]
        let foundClassic = classicPaths.filter { access($0, F_OK) == 0 }
        checks.append(JailbreakCheck(
            name: "传统 rootful 路径",
            isSuspicious: !foundClassic.isEmpty,
            detail: foundClassic.isEmpty ? "未发现" : "发现 \(foundClassic.count) 个: \(foundClassic.prefix(3).joined(separator: ", "))"
        ))

        // ── 2. Rootless 越狱路径 (/var/jb/) ──
        var rootlessPaths: [String] = []
        rootlessPaths.append("/var/jb")

        let jbSubDirs = [
            "Applications", "bin", "bzip2", "cache", "dpkg", "etc",
            "gzip", "lib", "Lib", "libexec", "Library", "newuser",
            "sbin", "sh", "share", "ssh", "usr", "profile",
            "master.passwd", "suid_profile"
        ]
        for sub in jbSubDirs {
            rootlessPaths.append("/var/jb/\(sub)")
        }

        // /var/jb 下的应用
        let jbApps = ["Cydia.app", "Sileo.app", "Zebra.app", "Filza.app", "NewTerm.app"]
        for app in jbApps {
            rootlessPaths.append("/var/jb/Applications/\(app)")
        }

        // /var/jb 下常见的包管理器
        let jbMgrPaths = [
            "/var/jb/usr/bin/apt",
            "/var/jb/usr/bin/dpkg",
            "/var/jb/usr/bin/sshd",
            "/var/jb/Library/MobileSubstrate",
            "/var/jb/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/var/jb/var/mobile/Library/Sileo",
            "/var/jb/var/mobile/Library/Application Support/xyz.willy.Zebra",
            "/var/jb/var/mobile/Library/Preferences/com.tigisoftware.Filza.plist",
            "/var/jb/var/mobile/.eksafemode",
            "/var/jb/var/lib/apt",
            "/var/jb/var/lib/dpkg",
            "/var/jb/var/lib/cydia",
            "/var/jb/var/lib/undecimus",
            "/var/jb/var/log/apt",
            "/var/jb/var/log/dpkg",
            "/var/jb/var/lib/filza",
            "/var/jb/etc/apt",
        ]
        rootlessPaths += jbMgrPaths

        let foundRootless = rootlessPaths.filter { access($0, F_OK) == 0 }
        checks.append(JailbreakCheck(
            name: "Rootless 越狱 (/var/jb)",
            isSuspicious: !foundRootless.isEmpty,
            detail: foundRootless.isEmpty ? "未发现" : "发现 \(foundRootless.count) 个: \(foundRootless.prefix(3).joined(separator: ", "))"
        ))

        // ── 3. 传统 rootful /var/ 下可疑文件 ──
        let varFiles = [
            "apt", "bin", "bzip2", "cache", "dpkg", "etc", "gzip",
            "lib", "Lib", "libexec", "Library", "LIY", "Liy",
            "newuser", "profile", "sbin", "sh", "share", "ssh",
            "sudo_logsrvd.conf", "suid_profile", "sy", "usr",
            "zlogin", "zlogout", "zprofile", "zshenv", "zshrc",
            "master.passwd"
        ]
        let foundVarFiles = varFiles.filter { access("/var/\($0)", F_OK) == 0 }
        checks.append(JailbreakCheck(
            name: "Rootful /var/ 文件",
            isSuspicious: !foundVarFiles.isEmpty,
            detail: foundVarFiles.isEmpty ? "未发现" : "发现 \(foundVarFiles.count) 个: \(foundVarFiles.prefix(3).joined(separator: ", "))"
        ))

        // ── 4. Xina 越狱专用 ──
        let xinaPaths = [
            "/var/containers/Bundle/dylib",
            "/var/containers/Bundle/xina",
            "/var/mobile/Library/Preferences/com.xina.blacklist.plist",
        ]
        let foundXina = xinaPaths.filter { access($0, F_OK) == 0 }
        checks.append(JailbreakCheck(
            name: "Xina 越狱",
            isSuspicious: !foundXina.isEmpty,
            detail: foundXina.isEmpty ? "未发现" : "发现 Xina 文件: \(foundXina.joined(separator: ", "))"
        ))

        // ── 5. KernBypass ──
        let kernBypass = access("/private/var/MobileSoftwareUpdate/mnt1/dev/null", F_OK) == 0
        checks.append(JailbreakCheck(
            name: "KernBypass",
            isSuspicious: kernBypass,
            detail: kernBypass ? "KernBypass 已安装" : "未发现"
        ))

        // ── 6. Fugu15 / Fugu15 Max ──
        let fuguPaths: [(String, String)] = [
            ("/private/preboot/jb", "Fugu15 引导"),
            ("/usr/lib/systemhook.dylib", "Fugu15 Max systemhook"),
            ("/usr/lib/sandbox.plist", "Fugu15 Max sandbox"),
            ("/var/log/launchdhook.log", "Fugu15 Max 日志"),
        ]
        var fuguFound: [String] = []
        for (path, desc) in fuguPaths {
            if access(path, F_OK) == 0 { fuguFound.append(desc) }
        }
        checks.append(JailbreakCheck(
            name: "Fugu15 系列",
            isSuspicious: !fuguFound.isEmpty,
            detail: fuguFound.isEmpty ? "未发现" : "发现: \(fuguFound.joined(separator: ", "))"
        ))

        // ── 7. Bootstrap / 包管理器痕迹 ──
        let bootstrapChecks: [(String, String)] = [
            ("/var/log/apt", "apt 日志(rootful)"),
            ("/var/log/apt", "apt 日志(rootful)"),
            ("/var/lib/dpkg", "dpkg(rootful)"),
            ("/var/lib", "var/lib(rootful)"),
            ("/var/lib/apt", "apt(rootful)"),
            ("/var/lib/cydia", "Cydia(rootful)"),
            ("/var/lib/undecimus", "unc0ver"),
            ("/var/mobile/Library/Sileo", "Sileo 数据"),
            ("/var/mobile/.eksafemode", "ellekit 安全模式"),
            ("/private/var/mobile/.ekenablelogging", "ellekit 日志"),
            ("/private/var/mobile/log.txt", "ellekit 日志文件"),
            ("/var/mobile/Library/Application Support/xyz.willy.Zebra", "Zebra 数据"),
        ]
        var bootFound: [String] = []
        for (path, desc) in bootstrapChecks {
            if access(path, F_OK) == 0 { bootFound.append(desc) }
        }
        checks.append(JailbreakCheck(
            name: "包管理器/Bootstrap 痕迹",
            isSuspicious: !bootFound.isEmpty,
            detail: bootFound.isEmpty ? "未发现" : "发现: \(bootFound.joined(separator: ", "))"
        ))

        // ── 8. TrollStore / Filza 检测 ──
        let trollPaths: [(String, String)] = [
            ("/var/lib/filza", "TrollStore Filza"),
            ("/var/mobile/Library/Filza", "Filza 用户数据"),
            ("/var/mobile/Library/Preferences/com.tigisoftware.Filza.plist", "Filza 配置"),
        ]
        var trollFound: [String] = []
        for (path, desc) in trollPaths {
            if access(path, F_OK) == 0 { trollFound.append(desc) }
        }
        checks.append(JailbreakCheck(
            name: "TrollStore / Filza",
            isSuspicious: !trollFound.isEmpty,
            detail: trollFound.isEmpty ? "未发现" : "发现: \(trollFound.joined(separator: ", "))"
        ))

        // ── 9. palera1n / checkra1n preboot ──
        let prebootResult = checkPrebootJB()
        checks.append(JailbreakCheck(
            name: "Preboot 越狱 (palera1n等)",
            isSuspicious: prebootResult.0,
            detail: prebootResult.1
        ))


        // ━━━━━━━━━ 二、系统级检测 ━━━━━━━━━
        // ── 10. chroot 检测 ──
        let chrootResult = checkChroot()
        checks.append(JailbreakCheck(
            name: "chroot 检测",
            isSuspicious: chrootResult,
            detail: chrootResult ? "根挂载点异常 → 可能 chroot" : "根挂载点正常"
        ))

        // ── 11. fork() 检测 ──
        let forkResult = checkFork()
        checks.append(JailbreakCheck(
            name: "fork() 调用",
            isSuspicious: forkResult,
            detail: forkResult ? "fork() 成功 → 沙盒被突破" : "fork() 被限制 → 正常沙盒"
        ))

        // ── 13. 沙盒写入检测 ──
        let sandboxResult = checkSandboxWrite()
        checks.append(JailbreakCheck(
            name: "沙盒保护",
            isSuspicious: sandboxResult,
            detail: sandboxResult ? "可写入 /private → 沙盒被突破" : "写入被拒绝 → 沙盒正常"
        ))

        // ── 14. 环境变量 ──
        let envResult = checkEnvironment()
        checks.append(JailbreakCheck(
            name: "环境变量",
            isSuspicious: envResult,
            detail: envResult ? "发现 DYLD_INSERT_LIBRARIES 等可疑变量" : "环境变量正常"
        ))

        // ── 15. 符号链接 ──
        let symlinkResult = checkSymlinks()
        checks.append(JailbreakCheck(
            name: "符号链接",
            isSuspicious: symlinkResult,
            detail: symlinkResult ? "发现可疑符号链接" : "未发现可疑符号链接"
        ))

        // ── 16. /var/jb 符号链接（含持久化记忆） ──
        let varjbResult = checkVarJBLink()
        checks.append(JailbreakCheck(
            name: "/var/jb 链接检测",
            isSuspicious: varjbResult.0,
            detail: varjbResult.1
        ))


        // ━━━━━━━━━ 三、运行时/进程检测 ━━━━━━━━━
        // ── 17. csops 代码签名标志 ──
        let csopsResult = checkCSOps()
        checks.append(JailbreakCheck(
            name: "代码签名标志 (csops)",
            isSuspicious: csopsResult.0,
            detail: csopsResult.1
        ))

        // ── 18. 异常端口 ──
        let excResult = checkExceptionPorts()
        checks.append(JailbreakCheck(
            name: "异常端口",
            isSuspicious: excResult.0,
            detail: excResult.1
        ))

        // ── 19. 越狱 Mach 服务 ──
        let machResult = checkMachServices()
        checks.append(JailbreakCheck(
            name: "越狱 Mach 服务",
            isSuspicious: machResult.0,
            detail: machResult.1
        ))

        // ── 20. VM Region 注入检测 ──
        let vmResult = checkVMRegion()
        checks.append(JailbreakCheck(
            name: "VM 注入检测",
            isSuspicious: vmResult.0,
            detail: vmResult.1
        ))


        // ━━━━━━━━━ 四、应用层检测 ━━━━━━━━━
        // ── 21. URL Schemes ──
        let schemeResult = checkURLSchemes()
        checks.append(JailbreakCheck(
            name: "URL Schemes",
            isSuspicious: schemeResult.0,
            detail: schemeResult.1
        ))

        // ── 22. 已安装越狱应用 (Bundle ID) ──
        let appResult = checkInstalledJBApps()
        checks.append(JailbreakCheck(
            name: "已安装越狱应用",
            isSuspicious: appResult.0,
            detail: appResult.1
        ))

        results = checks
        isJailbroken = checks.contains(where: { $0.isSuspicious })
    }

    // ━━━━━━━━━━ 检测方法实现 ━━━━━━━━━━

    // MARK: - Preboot 越狱
    private func checkPrebootJB() -> (Bool, String) {
        var s = statfs()
        guard statfs("/", &s) == 0 else { return (false, "无法读取根文件系统") }

        let mntFrom = withUnsafePointer(to: &s.f_mntfromname) {
            $0.withMemoryRebound(to: CChar.self, capacity: Int(MFSNAMELEN)) {
                String(cString: $0)
            }
        }

        // 解析 preboot 哈希
        let prefix = "com.apple.os.update-"
        guard mntFrom.hasPrefix(prefix),
              let atSign = mntFrom.firstIndex(of: "@") else {
            // 没有 snapshot → 可能是真正的 rootful 越狱
            return (!mntFrom.contains("@"), mntFrom.contains("@") ? "快照正常" : "无快照挂载 → rootful 越狱")
        }

        let hashPart = String(mntFrom[mntFrom.index(mntFrom.startIndex, offsetBy: prefix.count)..<atSign])

        // 检查 /private/preboot/<hash>/procursus
        let procursusPath = "/private/preboot/\(hashPart)/procursus"
        if access(procursusPath, F_OK) == 0 {
            return (true, "preboot 中发现 procursus 引导")
        }

        // jb 目录
        let jbPrebootPath = "/private/preboot/\(hashPart)/jb"
        if let linkTarget = readlinkStr(jbPrebootPath) {
            return (true, "preboot jb 链接 → \(linkTarget)")
        }
        if access(jbPrebootPath, F_OK) == 0 {
            return (true, "preboot jb 目录存在")
        }

        // 检查 preboot 分区是否可写 (仅 iOS 15 及以下才有意义)
        if access("/private/preboot/jb", F_OK) == 0 {
            return (true, "/private/preboot/jb 存在")
        }

        return (false, "preboot 干净")
    }

    private func readlinkStr(_ path: String) -> String? {
        var buf = [CChar](repeating: 0, count: Int(PATH_MAX))
        let len = readlink(path, &buf, buf.count)
        guard len > 0 else { return nil }
        return String(cString: buf)
    }

    // MARK: - chroot 检测
    private func checkChroot() -> Bool {
        var s = statfs()
        guard statfs("/", &s) == 0 else { return false }
        let mnt = withUnsafePointer(to: &s.f_mntonname) {
            $0.withMemoryRebound(to: CChar.self, capacity: Int(MFSNAMELEN)) {
                String(cString: $0)
            }
        }
        return mnt != "/"
    }

    // MARK: - fork() (bypass Xcode 16)
    private func checkFork() -> Bool {
        guard let handle = dlopen(nil, RTLD_NOW) else { return false }
        defer { dlclose(handle) }
        guard let sym = dlsym(handle, "fork") else { return false }
        typealias ForkFn = @convention(c) () -> Int32
        let fn = unsafeBitCast(sym, to: ForkFn.self)
        let pid = fn()
        if pid >= 0 {
            if pid == 0 {
                _exit(0)
            } else {
                var status: Int32 = 0
                waitpid(pid, &status, 0)
            }
            return true
        }
        return false
    }

    // MARK: - 沙盒写入
    private func checkSandboxWrite() -> Bool {
        let testPath = "/private/jb_test_\(UUID().uuidString)"
        let data = "test".data(using: .utf8)!
        let result = FileManager.default.createFile(atPath: testPath, contents: data)
        if result {
            try? FileManager.default.removeItem(atPath: testPath)
            return true
        }
        return false
    }

    // MARK: - 环境变量
    private func checkEnvironment() -> Bool {
        let keys = ["DYLD_INSERT_LIBRARIES", "DYLD_FORCE_FLAT_NAMESPACE",
                     "DYLD_SHARED_REGION", "DYLD_SHARED_CACHE_DIR"]
        for key in keys {
            if getenv(key) != nil { return true }
        }
        return false
    }

    // MARK: - 符号链接
    private func checkSymlinks() -> Bool {
        let paths = [
            "/var/lib/undecimus/apt",
            "/Applications",
            "/Library/Ringtones",
            "/Library/Wallpaper",
            "/usr/arm-apple-darwin9",
            "/usr/include",
            "/usr/libexec",
        ]
        for path in paths {
            var st = stat()
            if lstat(path, &st) == 0 {
                if (st.st_mode & S_IFMT) == S_IFLNK { return true }
            }
        }
        return false
    }

    // MARK: - /var/jb 链接 + 持久化记忆
    private func checkVarJBLink() -> (Bool, String) {
        if let target = readlinkStr("/var/jb") {
            UserDefaults.standard.set(target, forKey: "_var_jb_link")
            return (true, "/var/jb → \(target)")
        }

        // 之前记录过但链接被临时删了
        if let saved = UserDefaults.standard.string(forKey: "_var_jb_link") {
            if access(saved, F_OK) == 0 {
                return (true, "/var/jb 已删除但目标仍可访问: \(saved)")
            }
        }
        return (false, "未发现")
    }

    // MARK: - csops 代码签名标志
    private func checkCSOps() -> (Bool, String) {
        var flags: UInt32 = 0
        let ret = csops(getpid(), 0, &flags, MemoryLayout<UInt32>.size)
        guard ret == 0 else { return (false, "csops 调用失败") }

        var issues: [String] = []
        if flags & 0x00000004 != 0 { issues.append("get-task-allow") }
        if flags & 0x04000000 != 0 { issues.append("非标准平台二进制") }
        if flags & 0x00000008 != 0 { issues.append("非标准安装器") }
        if (flags & 0x00000300) == 0 { issues.append("JIT-allow") }
        if flags & 0x00004000 != 0 { issues.append("异常权限") }

        if issues.isEmpty {
            return (false, "签名标志正常")
        }
        return (true, "发现: \(issues.joined(separator: ", "))")
    }

    // MARK: - 异常端口
    private func checkExceptionPorts() -> (Bool, String) {
        var masks = [exception_mask_t](repeating: 0, count: 14) // EXC_TYPES_COUNT = 14
        var ports = [mach_port_t](repeating: 0, count: 14)
        var behaviors = [exception_behavior_t](repeating: 0, count: 14)
        var flavors = [thread_state_flavor_t](repeating: 0, count: 14)
        var count: mach_msg_type_number_t = 0

        let kr = task_get_exception_ports(
            mach_task_self_,
            0x1FFE, // EXC_MASK_ALL
            &masks,
            &count,
            &ports,
            &behaviors,
            &flavors
        )

        guard kr == KERN_SUCCESS, count > 0 else { return (false, "无法获取异常端口") }

        // 正常情况 count=1, port=0, behavior=0, flavor=0
        var issues: [String] = []
        if count != 1 { issues.append("异常端口数: \(count)") }
        for i in 0..<Int(count) {
            if ports[i] != 0 || behaviors[i] != 0 || flavors[i] != 0 {
                issues.append("端口[\(i)]: port=\(ports[i]) beh=\(behaviors[i]) flav=\(flavors[i])")
            }
        }

        if issues.isEmpty {
            return (false, "异常端口正常")
        }
        return (true, issues.joined(separator: "; "))
    }

    // MARK: - 越狱 Mach 服务
    private func checkMachServices() -> (Bool, String) {
        let services: [(String, String)] = [
            ("cy:com.saurik.substrated", "checkra1n Substrate"),
            ("org.coolstar.jailbreakd", "CoolStar jailbreakd"),
            ("jailbreakd", "Xina jailbreakd"),
            ("cy:com.opa334.jailbreakd", "Dopamine jailbreakd"),
            ("lh:com.opa334.jailbreakd", "Dopamine jailbreakd (lh)"),
        ]

        var found: [String] = []
        for (name, desc) in services {
            var port: mach_port_t = 0
            let kr = name.withCString { cstr in
                bootstrap_look_up(_bootstrap_port, cstr, &port)
            }
            if kr == KERN_SUCCESS || kr == 1102 {
                found.append(desc)
            }
        }

        if found.isEmpty {
            return (false, "未发现越狱 Mach 服务")
        }
        return (true, "发现: \(found.joined(separator: ", "))")
    }

    // MARK: - VM Region 注入检测
    private func checkVMRegion() -> (Bool, String) {
        var address: vm_address_t = 0
        var size: vm_size_t = 0
        var rawInfo = [Int32](repeating: 0, count: 20)
        var infoCnt = mach_msg_type_number_t(20)
        var objectName: mach_port_t = 0

        let kr = vm_region_64(
            mach_task_self_,
            &address,
            &size,
            9, // VM_REGION_BASIC_INFO_64
            &rawInfo,
            &infoCnt,
            &objectName
        )

        guard kr == KERN_SUCCESS else { return (false, "vm_region 调用失败") }

        let protection = rawInfo[0]
        if protection != 1 && protection != 5 { // VM_PROT_READ=1, VM_PROT_READ|VM_PROT_EXECUTE=5
            return (true, "VM 区域保护异常: 0x\(String(protection, radix: 16))")
        }

        return (false, "VM 区域正常")
    }

    // MARK: - URL Schemes
    private func checkURLSchemes() -> (Bool, String) {
        let schemes = [
            "cydia", "sileo", "zbra", "installer",
            "apt-repo", "filza", "undecimus"
        ]
        var found: [String] = []
        for scheme in schemes {
            if let url = URL(string: "\(scheme)://"),
               UIApplication.shared.canOpenURL(url) {
                found.append(scheme)
            }
        }
        if found.isEmpty {
            return (false, "无可疑 URL Scheme")
        }
        return (true, "可打开: \(found.joined(separator: ", "))")
    }

    // MARK: - 已安装越狱应用 (LSApplicationWorkspace 私有 API)
    private func checkInstalledJBApps() -> (Bool, String) {
        let jbBundleIDs = [
            "com.xina.jailbreak",
            "com.opa334.Dopamine",
            "com.tigisoftware.Filza",
            "org.coolstar.SileoStore",
            "ws.hbang.Terminal",
            "xyz.willy.Zebra",
            "shshd",
        ]

        guard let workspaceClass = NSClassFromString("LSApplicationWorkspace") as? NSObject.Type else {
            return (false, "无法访问 LSApplicationWorkspace")
        }

        guard let workspace = workspaceClass.perform(NSSelectorFromString("defaultWorkspace"))?.takeUnretainedValue() as? NSObject else {
            return (false, "无法获取 defaultWorkspace")
        }

        guard let allApps = workspace.perform(NSSelectorFromString("allInstalledApplications"))?.takeUnretainedValue() as? [AnyObject] else {
            return (false, "无法获取已安装应用列表")
        }

        var found: [String] = []
        for app in allApps {
            if let bundleID = app.perform(NSSelectorFromString("applicationIdentifier"))?.takeUnretainedValue() as? String {
                if jbBundleIDs.contains(bundleID) {
                    found.append(bundleID)
                }
            }
        }

        if found.isEmpty {
            return (false, "未发现越狱应用")
        }
        return (true, "发现: \(found.joined(separator: ", "))")
    }
}
