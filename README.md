# zcash-light-client-ffi

This project is designed for two things:

1. Provide language bindings for the zcash rust library, in the `rust` directory.  
2. Packaging for common dependency managers within those language eco systems.

Currently implemented is building for apple platforms as an `xcframework` and for distribution via Swift Package Manager and CocoaPods.


## Building

### Pre-requisites

Most of the building is done with the rust compiler, and depending on the target will need different toolchains. To install these you will need to install [`rustup`](https://rustup.rs). Once this is installed, the rest of the dependencies can be installed by running `make install`.

### XCFramework

Currently the only build product that is supported. This can be built with `make xcframework` and the result will be in `releases/XCFramework/libzcashlc.xcframework`.

Depending on what state the intermediate build products might be in, you may first want to do `make clean` to do a clean build.


## Releasing

### Swift Package Manager

1. Build the framework as described above.
2. Commit the result.
3. Tag this commit with the new release version, (following semantic versioning).
4. Push the commit and tag to the remote repository.

### CocoaPods

1. All of the steps from the `Swift Package Manager` release process above.
2. Update `s.version` in `libzcashlc.podspec` to the new release version.
3. (assuming you have the `pod` command) `pod trunk push libzcashlc.podspec`


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
