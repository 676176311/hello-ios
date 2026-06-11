import Foundation

/// 跨 App 共享状态：AttackLab 写入 → HelloApp 读取
/// 用于模拟真实攻击场景：攻击者植入后门 → 防御App检测被欺骗
class SharedAttackState {
    private static let fileName = ".attacklab_state"
    private static var statePath: String { "/tmp/\(fileName)" }

    /// 全局攻击是否激活
    static var isAttackActive: Bool {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: statePath)),
              let dict = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let active = dict["active"] as? Bool else { return false }
        return active
    }

    /// 获取激活的层 (用于展示)
    static var activeLayers: [Int] {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: statePath)),
              let dict = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let layers = dict["layers"] as? [Int] else { return [] }
        return layers
    }

    /// 获取写入时间
    static var timestamp: Double? {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: statePath)),
              let dict = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
        return dict["timestamp"] as? Double
    }

    /// AttackLab: 激活攻击(写入系统状态)
    static func activate(layers: [Int]) {
        let dict: [String: Any] = [
            "active": true,
            "layers": layers,
            "timestamp": Date().timeIntervalSince1970
        ]
        if let data = try? JSONSerialization.data(withJSONObject: dict) {
            try? data.write(to: URL(fileURLWithPath: statePath))
        }
    }

    /// AttackLab: 关闭攻击(清除系统状态)
    static func deactivate() {
        try? FileManager.default.removeItem(atPath: statePath)
    }
}
