// swift-tools-version:5.9
import Foundation
import PackageDescription

// Info.plist is embedded in the binary (__TEXT,__info_plist), so macOS can
// name the helper "foca" in the Touch ID dialog rather than "foca-darwin".
let infoPlist = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("Info.plist").path

let package = Package(
    name: "foca-darwin",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(
            name: "foca-darwin",
            path: "Sources/foca-darwin",
            linkerSettings: [
                .linkedFramework("AppKit"),
                .linkedFramework("IOKit"),
                .linkedFramework("LocalAuthentication"),
                .linkedFramework("Security"),
                .unsafeFlags(["-Xlinker", "-sectcreate", "-Xlinker", "__TEXT", "-Xlinker", "__info_plist", "-Xlinker", infoPlist]),
            ]
        ),
    ]
)
