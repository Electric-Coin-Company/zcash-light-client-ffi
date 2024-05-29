# zcash-light-client-ffi

This project is designed for two things:

1. Provide language bindings for the zcash rust library, in the `rust` directory.  
2. Packaging for common dependency managers within those language eco systems.

Currently implemented is building for apple platforms as an `xcframework` and for distribution via Swift Package Manager.


## importing the package
Add the package as a dependency
````Swift
dependencies: [
  .package(url: "https://github.com/zcash-hackworks/zcash-light-client-ffi", from: "0.1.2")
  // other dependencies
]
````

and reference it as product in the target that it will be used

````Swift
targets: [
        .target(
            name: "MyTarget",
            dependencies: [
                .product(name: "libzcashlc", package: "zcash-light-client-ffi")
            ],
````

## Building

### Pre-requisites

Most of the building is done with the rust compiler, and depending on the target will need different toolchains. To install these you will need to install [`rustup`](https://rustup.rs). Once this is installed, the rest of the dependencies can be installed by running `make install`.

### XCFramework

Currently the only build product that is supported. This can be built with `make xcframework` and the result will be in `releases/XCFramework/libzcashlc.xcframework`.

Depending on what state the intermediate build products might be in, you may first want to do `make clean` to do a clean build.


## Releasing

### Swift Package Manager

#### Using CI

1. Tag the desired commit with the new release version, (following semantic versioning).
2. Push the tag to the remote repository.
3. check that the github action has finished properly

#### manually
1. tag the commit to the remote repository
2. run `make xcframework`
3. get the xcframework.zip located inside products and get the sha256 using `shasum -a 256 products/libzcashlc.xcframework.zip | cut -d ' ' -f 1`
4. don't commit the binaries to github!!!
5. create a new Github release using the website or the Github CLI
6. make sure to include the `libzcashlc.xcframework.zip` file and the checksum in the release notes

## License

Licensed under MIT license ([LICENSE](LICENSE) or http://opensource.org/licenses/MIT).

Downstream code forks should note that 'libzcashlc' (and thus XCFramework)
depends on the 'orchard' crate, which is licensed under the [Bootstrap Open
Source License](https://github.com/zcash/orchard/blob/main/LICENSE-BOSL).  A
license exception is provided allowing some derived works that are linked or
combined with the 'orchard' crate to be copied or distributed under the original
licenses (in this case MIT), provided that the included portions of the
'orchard' code remain subject to BOSL.  See
https://github.com/zcash/orchard/blob/main/COPYING for details of which derived
works can make use of this exception.
