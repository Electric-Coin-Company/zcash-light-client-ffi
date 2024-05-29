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
            url: "https://github.com/pacu/zcash-light-client-ffi/releases/download/0.0.0/libzcashlc.xcframework.zip",
            checksum: "5bc1fac907698f45d5cfce3bbca421f1c3e35ae64401a16fc5b561b7502e6876"
        )
    ]
)
