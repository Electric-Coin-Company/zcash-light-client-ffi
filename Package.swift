// swift-tools-version:5.5

import PackageDescription

let package = Package(
    name: "zcash-light-client-ffi",
    products: [
        .library(
            name: "libzcashlc",
            targets: ["libzcashlc"]
        ),
    ],
    dependencies: [

    ],
    targets: [
        .binaryTarget(
            name: "libzcashlc",
            path: "releases/XCFramework/libzcashlc.xcframework"
        )
    ]
)
