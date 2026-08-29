// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "DigitalMembershipCore",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "DigitalMembershipCore", targets: ["DigitalMembershipCore"])
    ],
    targets: [
        .target(
            name: "DigitalMembershipCore",
            path: "DigitalMembershipScanner/Membership"
        ),
        .testTarget(
            name: "DigitalMembershipCoreTests",
            dependencies: ["DigitalMembershipCore"],
            path: "DigitalMembershipCoreTests"
        )
    ]
)
