// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "XZEmbedded",
    platforms: [
        .iOS(.v17),
        .macOS(.v14),
    ],
    products: [
        .library(name: "CXZ", targets: ["CXZ"])
    ],
    targets: [
        .target(
            name: "CXZ",
            path: "Sources/CXZ",
            publicHeadersPath: "include",
            cSettings: [
                .define("XZ_USE_CRC64"),
                .define("XZ_DEC_SINGLE"),
                .headerSearchPath("src"),
            ]
        )
    ]
)
