// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "ScopeScanCore",
    platforms: [
        .iOS(.v17),
        .macOS(.v14)
    ],
    products: [
        .library(name: "ScopeScanCore", targets: ["ScopeScanCore"])
    ],
    targets: [
        .target(name: "ScopeScanCore"),
        .testTarget(name: "ScopeScanCoreTests", dependencies: ["ScopeScanCore"])
    ]
)
