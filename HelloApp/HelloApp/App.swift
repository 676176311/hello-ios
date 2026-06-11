import SwiftUI

@main
struct HelloApp: App {
    @StateObject private var detector = JailbreakDetector()
    @StateObject private var hardware = HardwareInfo()

    var body: some Scene {
        WindowGroup {
            MainView()
                .environmentObject(detector)
                .environmentObject(hardware)
                .onAppear {
                    detector.runAllChecks()
                    hardware.gatherInfo()
                }
        }
    }
}
