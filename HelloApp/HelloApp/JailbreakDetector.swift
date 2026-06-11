import Foundation
import UIKit

// MARK: - 检测结果模型
struct JailbreakCheck: Identifiable {
    let id = UUID()
    let name: String
    let isSuspicious: Bool
    let detail: String
}

// MARK: - 越狱检测器
class JailbreakDetector: ObservableObject {
    @Published var results: [JailbreakCheck] = []
    @Published var isJailbroken: Bool = false

    func runAllChecks() {
        var checks: [JailbreakCheck] = []

        // ── 1. 常见越狱应用路径 ──
        let jbAppPaths = [
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
        ]
        let foundApps = jbAppPaths.filter { FileManager.default.fileExists(atPath: $0) }
        checks.append(JailbreakCheck(
            name: "越狱应用",
            isSuspicious: !foundApps.isEmpty,
            detail: foundApps.isEmpty ? "未发现已知越狱应用" : "发现: \(foundApps.count) 个"
        ))

        // ── 2. 可疑文件/路径 ──
        let suspiciousPaths = [
            "/bin/bash",
            "/bin/sh",
            "/usr/sbin/sshd",
            "/usr/bin/sshd",
            "/etc/apt",
            "/etc/ssh/sshd_config",
            "/private/var/tmp/cydia.log",
            "/usr/libexec/ssh-keysign",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
            "/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
            "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
            "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
            "/private/var/stash",
            "/private/var/log/syslog",
            "/private/etc/ssh/sshd_config",
        ]
        let foundPaths = suspiciousPaths.filter { FileManager.default.fileExists(atPath: $0) }
        checks.append(JailbreakCheck(
            name: "可疑文件",
            isSuspicious: !foundPaths.isEmpty,
            detail: foundPaths.isEmpty ? "未发现可疑文件" : "发现 \(foundPaths.count) 个可疑路径"
        ))

        // ── 3. fork() 检测 ──
        let forkResult = checkFork()
        checks.append(JailbreakCheck(
            name: "fork() 调用",
            isSuspicious: forkResult,
            detail: forkResult ? "fork() 调用成功 → 可能已越狱" : "fork() 被限制 → 正常沙盒"
        ))

        // ── 4. 沙盒写入检测 ──
        let sandboxResult = checkSandboxWrite()
        checks.append(JailbreakCheck(
            name: "沙盒保护",
            isSuspicious: sandboxResult,
            detail: sandboxResult ? "可写入 /private → 沙盒被突破" : "写入被拒绝 → 沙盒正常"
        ))

        // ── 5. URL Scheme 检测 ──
        let schemeResult = checkURLSchemes()
        checks.append(JailbreakCheck(
            name: "URL Schemes",
            isSuspicious: schemeResult.0,
            detail: schemeResult.1
        ))

        // ── 6. 环境变量检测 ──
        let envResult = checkEnvironment()
        checks.append(JailbreakCheck(
            name: "环境变量",
            isSuspicious: envResult,
            detail: envResult ? "发现可疑环境变量" : "环境变量正常"
        ))

        // ── 7. 符号链接检测 ──
        let symlinkResult = checkSymlinks()
        checks.append(JailbreakCheck(
            name: "符号链接",
            isSuspicious: symlinkResult,
            detail: symlinkResult ? "发现可疑符号链接" : "未发现可疑符号链接"
        ))

        results = checks
        isJailbroken = checks.contains(where: { $0.isSuspicious })
    }

    // MARK: - fork() 检测（绕过 Xcode 16 的 fork() 封禁）
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
        let testPath = "/private/jailbreak_test_\(UUID().uuidString)"
        let result = FileManager.default.createFile(atPath: testPath, contents: "test".data(using: .utf8))
        if result {
            try? FileManager.default.removeItem(atPath: testPath)
            return true
        }
        return false
    }

    // MARK: - URL Scheme
    private func checkURLSchemes() -> (Bool, String) {
        let schemes = ["cydia://", "sileo://", "zebra://", "installer://"]
        var detectable: [String] = []

        for scheme in schemes {
            if let url = URL(string: scheme),
               UIApplication.shared.canOpenURL(url) {
                detectable.append(scheme)
            }
        }

        if detectable.isEmpty {
            return (false, "无可疑 URL Scheme 响应")
        } else {
            return (true, "可打开: \(detectable.joined(separator: ", "))")
        }
    }

    // MARK: - 环境变量
    private func checkEnvironment() -> Bool {
        let suspiciousEnv = ["DYLD_INSERT_LIBRARIES", "DYLD_FORCE_FLAT_NAMESPACE"]
        for key in suspiciousEnv {
            if getenv(key) != nil {
                return true
            }
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
                if (st.st_mode & S_IFMT) == S_IFLNK {
                    return true
                }
            }
        }
        return false
    }
}
