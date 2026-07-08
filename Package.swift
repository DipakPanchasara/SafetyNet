// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "SafetyNet",
    platforms: [.iOS(.v14)],
    products: [
        .library(name: "SafetyNet", targets: ["SafetyNet"])
    ],
    targets: [
        .target(
            name: "SafetyNetObjC",
            path: "Sources/SafetyNetObjC",
            publicHeadersPath: "include"
        ),
        .target(
            name: "SafetyNet",
            dependencies: ["SafetyNetObjC"],
            path: "Sources/SafetyNet"
        ),
        .testTarget(
            name: "SafetyNetTests",
            dependencies: ["SafetyNet"],
            path: "Tests/SafetyNetTests"
        )
    ]
)
