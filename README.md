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

