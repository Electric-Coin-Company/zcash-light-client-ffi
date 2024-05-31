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

**pre-requisites**: you need to be a repo maintainer


1. as a *maintainer* pull the the latest changes from main.
2. branch to a new release. Example: to create release 0.0.1
create a new branch called `release-0.0.1` using `git checkout -b release-0.0.1`
3. update the rust/Cargo.toml file with the new SemVer number matching the
release format. if it's already updated and you will need to generate another
file changte, that's why you can update the VERSION.txt file.
4. push your changes to the remote branch and open a pull request.
5. The `release.yml` workflow should be executed. this will build
the project and create a github release with the version number provided
in the branch name, containing the artifacts and generated release notes 
by making a diff of the commits from the latest tag to this one.

#### manually
**pre-requisite:** update the version numbers on rust/Cargo.toml and VERSION.txt with the SemVer version that you will use. 
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
