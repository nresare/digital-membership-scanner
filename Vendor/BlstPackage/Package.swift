// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "Blst",
    platforms: [
        .iOS(.v17),
        .macOS(.v14),
    ],
    products: [
        .library(name: "CBlst", targets: ["CBlst"])
    ],
    targets: [
        .target(
            name: "CBlst",
            path: "Sources/CBlst",
            sources: [
                "build/assembly.S",
                "src/server.c",
            ],
            publicHeadersPath: "include",
            cSettings: [
                .unsafeFlags(["-fno-builtin"]),
                .define("__BLST_PORTABLE__", .when(platforms: [.iOS, .macOS])),
            ]
        )
    ]
)
