// swift-tools-version:5.9
import PackageDescription

// Foca.app, the menu-bar app (design §8.7). FocaKit holds what can be tested
// without a screen; scripts/build-darwin.sh puts the Foca executable into a
// signed bundle with Info.plist.
let package = Package(
    name: "Foca",
    platforms: [.macOS(.v13)],
    targets: [
        .target(name: "FocaKit", path: "Sources/FocaKit"),
        .executableTarget(
            name: "Foca",
            dependencies: ["FocaKit"],
            path: "Sources/Foca",
            linkerSettings: [
                .linkedFramework("AppKit"),
                .linkedFramework("SwiftUI"),
                .linkedFramework("UserNotifications"),
            ]
        ),
        .testTarget(name: "FocaKitTests", dependencies: ["FocaKit"], path: "Tests/FocaKitTests"),
    ]
)
