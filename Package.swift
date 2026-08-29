// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "DigitalMembershipCore",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "DigitalMembershipCore", targets: ["DigitalMembershipCore"])
    ],
    dependencies: [
        .package(path: "Vendor/BlstPackage"),
        .package(path: "Vendor/XZEmbeddedPackage")
    ],
    targets: [
        .target(
            name: "DigitalMembershipCore",
            dependencies: [
                .product(name: "CBlst", package: "BlstPackage"),
                .product(name: "CXZ", package: "XZEmbeddedPackage")
            ],
            path: "DigitalMembershipScanner/Membership"
        ),
        .testTarget(
            name: "DigitalMembershipCoreTests",
            dependencies: ["DigitalMembershipCore"],
            path: "DigitalMembershipCoreTests"
        )
    ]
)
