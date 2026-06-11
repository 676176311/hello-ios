import SwiftUI

@main
struct HelloApp: App {
    @StateObject private var detector = JailbreakDetector()
    @StateObject private var hardware = HardwareInfo()
    @StateObject private var attackSimulator = AttackSimulator()

    var body: some Scene {
        WindowGroup {
            MainView()
                .environmentObject(detector)
                .environmentObject(hardware)
                .environmentObject(attackSimulator)
                .onAppear {
                    detector.runAllChecks()
                    hardware.gatherInfo()
                }
        }
    }
}
