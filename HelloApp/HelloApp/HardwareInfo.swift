import Foundation
import UIKit

// MARK: - 硬件参数模型
struct HardwareParam: Identifiable {
    let id = UUID()
    let name: String
    let value: String
}

// MARK: - 硬件信息采集器
class HardwareInfo: ObservableObject {
    @Published var parameters: [HardwareParam] = []

    func gatherInfo() {
        var params: [HardwareParam] = []

        // ── 设备标识 ──
        let modelCode = sysctlString("hw.machine") ?? "unknown"
        params.append(HardwareParam(name: "机型代号", value: modelCode))
        params.append(HardwareParam(name: "市场名称", value: mapDeviceModel(modelCode)))
        params.append(HardwareParam(name: "设备名称", value: UIDevice.current.name))
        params.append(HardwareParam(name: "型号", value: UIDevice.current.model))
        params.append(HardwareParam(name: "本地化型号", value: UIDevice.current.localizedModel))

        if let uid = UIDevice.current.identifierForVendor {
            params.append(HardwareParam(name: "IDFV", value: uid.uuidString))
        }

        // ── 系统信息 ──
        params.append(HardwareParam(name: "iOS 版本", value: UIDevice.current.systemVersion))
        params.append(HardwareParam(name: "系统名称", value: UIDevice.current.systemName))
        if let build = sysctlString("kern.osversion") {
            params.append(HardwareParam(name: "Build", value: build))
        }

        // ── CPU ──
        let arch = sysctlString("hw.machine")?
            .components(separatedBy: CharacterSet(charactersIn: "0123456789,")).first ?? "unknown"
        params.append(HardwareParam(name: "CPU 架构", value: arch))

        if let ncpu = sysctlInt("hw.ncpu") {
            params.append(HardwareParam(name: "CPU 核心数", value: "\(ncpu)"))
        }
        if let activecpu = sysctlInt("hw.activecpu") {
            params.append(HardwareParam(name: "活跃核心数", value: "\(activecpu)"))
        }
        if let cpuFreq = sysctlInt64("hw.cpufrequency"), cpuFreq > 0 {
            params.append(HardwareParam(name: "CPU 主频", value: String(format: "%.1f MHz", Double(cpuFreq) / 1_000_000.0)))
        }
        if let cpuFreqMax = sysctlInt64("hw.cpufrequency_max"), cpuFreqMax > 0 {
            params.append(HardwareParam(name: "CPU 最大主频", value: String(format: "%.1f MHz", Double(cpuFreqMax) / 1_000_000.0)))
        }
        if let cacheLine = sysctlInt("hw.cachelinesize") {
            params.append(HardwareParam(name: "CPU 缓存行", value: "\(cacheLine) Bytes"))
        }
        if let l1dcache = sysctlInt("hw.l1dcachesize") {
            params.append(HardwareParam(name: "L1 数据缓存", value: formatBytes(l1dcache)))
        }
        if let l1icache = sysctlInt("hw.l1icachesize") {
            params.append(HardwareParam(name: "L1 指令缓存", value: formatBytes(l1icache)))
        }
        if let l2cache = sysctlInt("hw.l2cachesize") {
            params.append(HardwareParam(name: "L2 缓存", value: formatBytes(l2cache)))
        }

        // ── 物理内存 ──
        if let memsize = sysctlInt64("hw.memsize") {
            params.append(HardwareParam(name: "物理内存", value: formatBytes(Int(memsize))))
        }

        // 可用内存：用 phys_footprint 近似
        if let memUsed = sysctlUInt64("kern.memorystatus_phys_footprint") {
            params.append(HardwareParam(name: "App 占用内存", value: formatBytes(Int(memUsed))))
        }

        // ── 内存分页 ──
        if let pagesize = sysctlInt("hw.pagesize") {
            params.append(HardwareParam(name: "页大小", value: "\(pagesize) Bytes"))
        }

        // ── 屏幕 ──
        let screen = UIScreen.main
        let bounds = screen.bounds
        let scale = screen.scale
        let nativeBounds = screen.nativeBounds
        params.append(HardwareParam(name: "逻辑分辨率", value: "\(Int(bounds.width))×\(Int(bounds.height))"))
        params.append(HardwareParam(name: "物理分辨率", value: "\(Int(nativeBounds.width))×\(Int(nativeBounds.height))"))
        params.append(HardwareParam(name: "像素密度", value: "@\(Int(scale))x"))
        params.append(HardwareParam(name: "亮度", value: String(format: "%.0f%%", screen.brightness * 100)))

        // ── 存储 ──
        let (totalSpace, freeSpace) = getStorageInfo()
        params.append(HardwareParam(name: "总存储", value: formatBytes(totalSpace)))
        params.append(HardwareParam(name: "可用存储", value: formatBytes(freeSpace)))

        // ── 电池 ──
        UIDevice.current.isBatteryMonitoringEnabled = true
        let batteryLevel = UIDevice.current.batteryLevel
        if batteryLevel >= 0 {
            params.append(HardwareParam(name: "电量", value: String(format: "%.0f%%", batteryLevel * 100)))
        } else {
            params.append(HardwareParam(name: "电量", value: "未知"))
        }
        let batteryStateText: String = {
            switch UIDevice.current.batteryState {
            case .unknown: return "未知"
            case .unplugged: return "未充电"
            case .charging: return "充电中"
            case .full: return "已充满"
            @unknown default: return "未知"
            }
        }()
        params.append(HardwareParam(name: "充电状态", value: batteryStateText))

        // ── 系统运行时间 ──
        let uptime = ProcessInfo.processInfo.systemUptime
        params.append(HardwareParam(name: "系统运行时间", value: formatUptime(uptime)))

        // ── 启动时间 ──
        let bootTime = Date(timeIntervalSinceNow: -uptime)
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        params.append(HardwareParam(name: "启动时间", value: formatter.string(from: bootTime)))

        // ── 进程信息 ──
        let processInfo = ProcessInfo.processInfo
        params.append(HardwareParam(name: "逻辑核心数", value: "\(processInfo.processorCount)"))
        params.append(HardwareParam(name: "活跃核心数", value: "\(processInfo.activeProcessorCount)"))
        params.append(HardwareParam(name: "当前 App PID", value: "\(processInfo.processIdentifier)"))

        // ── 热状态 ──
        let thermalText: String = {
            switch processInfo.thermalState {
            case .nominal: return "正常"
            case .fair: return "稍热"
            case .serious: return "过热"
            case .critical: return "严重过热"
            @unknown default: return "未知"
            }
        }()
        params.append(HardwareParam(name: "热状态", value: thermalText))

        // ── 系统内核 ──
        var uts = utsname()
        uname(&uts)
        let kernelVersion = withUnsafePointer(to: &uts.version) {
            $0.withMemoryRebound(to: CChar.self, capacity: Int(_SYS_NAMELEN)) {
                String(cString: $0)
            }
        }
        params.append(HardwareParam(name: "内核版本", value: kernelVersion))

        let kernelType = withUnsafePointer(to: &uts.sysname) {
            $0.withMemoryRebound(to: CChar.self, capacity: Int(_SYS_NAMELEN)) {
                String(cString: $0)
            }
        }
        params.append(HardwareParam(name: "内核类型", value: kernelType))

        let hostname = withUnsafePointer(to: &uts.nodename) {
            $0.withMemoryRebound(to: CChar.self, capacity: Int(_SYS_NAMELEN)) {
                String(cString: $0)
            }
        }
        params.append(HardwareParam(name: "主机名", value: hostname))

        // ── 系统启动时间 (kern.boottime) ──
        if let boottimeSec = sysctlBootTime() {
            let bootDate = Date(timeIntervalSince1970: TimeInterval(boottimeSec))
            params.append(HardwareParam(name: "内核启动时间", value: formatter.string(from: bootDate)))
        }

        // ── 物理内存页信息 ──
        if let memSize = sysctlInt64("hw.memsize"),
           let pageSize = sysctlInt("hw.pagesize") {
            let totalPages = memSize / Int64(pageSize)
            params.append(HardwareParam(name: "总内存页", value: "\(totalPages)"))
        }

        // ── 语言/地区 ──
        params.append(HardwareParam(name: "系统语言", value: Locale.preferredLanguages.first ?? "unknown"))
        params.append(HardwareParam(name: "地区", value: Locale.current.regionCode ?? "unknown"))

        // ── 时区 ──
        let tz = TimeZone.current
        params.append(HardwareParam(name: "时区", value: "\(tz.identifier) (UTC\(tz.abbreviation() ?? ""))"))

        parameters = params
    }

    // MARK: - sysctl 辅助方法
    private func sysctlString(_ name: String) -> String? {
        var size: Int = 0
        guard sysctlbyname(name, nil, &size, nil, 0) == 0 else { return nil }
        var result = [CChar](repeating: 0, count: size)
        guard sysctlbyname(name, &result, &size, nil, 0) == 0 else { return nil }
        return String(cString: result)
    }

    private func sysctlInt(_ name: String) -> Int? {
        var value: Int = 0
        var size = MemoryLayout<Int>.size
        guard sysctlbyname(name, &value, &size, nil, 0) == 0 else { return nil }
        return value
    }

    private func sysctlInt64(_ name: String) -> Int64? {
        var value: Int64 = 0
        var size = MemoryLayout<Int64>.size
        guard sysctlbyname(name, &value, &size, nil, 0) == 0 else { return nil }
        return value
    }

    private func sysctlUInt64(_ name: String) -> UInt64? {
        var value: UInt64 = 0
        var size = MemoryLayout<UInt64>.size
        guard sysctlbyname(name, &value, &size, nil, 0) == 0 else { return nil }
        return value
    }

    private func sysctlBootTime() -> Int64? {
        var tv = timeval()
        var size = MemoryLayout<timeval>.size
        var mib: [Int32] = [CTL_KERN, KERN_BOOTTIME]
        guard sysctl(&mib, UInt32(mib.count), &tv, &size, nil, 0) == 0 else { return nil }
        return tv.tv_sec
    }

    // MARK: - 存储信息
    private func getStorageInfo() -> (total: Int, free: Int) {
        guard let attrs = try? FileManager.default.attributesOfFileSystem(forPath: NSHomeDirectory()) else {
            return (0, 0)
        }
        let total = attrs[.systemSize] as? Int ?? 0
        let free = attrs[.systemFreeSize] as? Int ?? 0
        return (total, free)
    }

    // MARK: - 格式化辅助
    private func formatBytes(_ bytes: Int) -> String {
        if bytes < 0 { return "unknown" }
        let formatter = ByteCountFormatter()
        formatter.countStyle = .binary
        return formatter.string(fromByteCount: Int64(bytes))
    }

    private func formatUptime(_ seconds: TimeInterval) -> String {
        let days = Int(seconds) / 86400
        let hours = (Int(seconds) % 86400) / 3600
        let minutes = (Int(seconds) % 3600) / 60
        if days > 0 {
            return "\(days)天 \(hours)时 \(minutes)分"
        }
        return "\(hours)时 \(minutes)分"
    }

    // MARK: - 设备型号映射
    private func mapDeviceModel(_ code: String) -> String {
        let mapping: [String: String] = [
            "iPhone8,1": "iPhone 6s", "iPhone8,2": "iPhone 6s Plus",
            "iPhone8,4": "iPhone SE (第1代)",
            "iPhone9,1": "iPhone 7", "iPhone9,2": "iPhone 7 Plus",
            "iPhone9,3": "iPhone 7", "iPhone9,4": "iPhone 7 Plus",
            "iPhone10,1": "iPhone 8", "iPhone10,2": "iPhone 8 Plus",
            "iPhone10,3": "iPhone X", "iPhone10,4": "iPhone 8",
            "iPhone10,5": "iPhone 8 Plus", "iPhone10,6": "iPhone X",
            "iPhone11,2": "iPhone XS", "iPhone11,4": "iPhone XS Max",
            "iPhone11,6": "iPhone XS Max", "iPhone11,8": "iPhone XR",
            "iPhone12,1": "iPhone 11", "iPhone12,3": "iPhone 11 Pro",
            "iPhone12,5": "iPhone 11 Pro Max", "iPhone12,8": "iPhone SE (第2代)",
            "iPhone13,1": "iPhone 12 mini", "iPhone13,2": "iPhone 12",
            "iPhone13,3": "iPhone 12 Pro", "iPhone13,4": "iPhone 12 Pro Max",
            "iPhone14,2": "iPhone 13 Pro", "iPhone14,3": "iPhone 13 Pro Max",
            "iPhone14,4": "iPhone 13 mini", "iPhone14,5": "iPhone 13",
            "iPhone14,6": "iPhone SE (第3代)", "iPhone14,7": "iPhone 14",
            "iPhone14,8": "iPhone 14 Plus",
            "iPhone15,2": "iPhone 14 Pro", "iPhone15,3": "iPhone 14 Pro Max",
            "iPhone15,4": "iPhone 15", "iPhone15,5": "iPhone 15 Plus",
            "iPhone16,1": "iPhone 15 Pro", "iPhone16,2": "iPhone 15 Pro Max",
            "iPhone17,1": "iPhone 16 Pro", "iPhone17,2": "iPhone 16 Pro Max",
            "iPhone17,3": "iPhone 16", "iPhone17,4": "iPhone 16 Plus",
            "iPhone17,5": "iPhone 16e",
            "iPhone18,1": "iPhone 17 Pro", "iPhone18,2": "iPhone 17 Pro Max",
            "iPhone18,3": "iPhone 17", "iPhone18,4": "iPhone Air",
        ]
        return mapping[code] ?? code
    }
}
