extern crate cbindgen;

use std::{env, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=wrapper.c");
    println!("cargo:rerun-if-changed=wrapper.h");

    let bindings = bindgen::builder()
        .header("wrapper.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .allowlist_function("os_log_.*")
        .allowlist_function("os_release")
        .allowlist_function("os_signpost_.*")
        .generate()
        .expect("should be able to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("should be able to write bindings");

    cc::Build::new().file("wrapper.c").compile("wrapper");

    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    if let Ok(b) = cbindgen::Builder::new()
        .with_crate(crate_dir)
        .with_language(cbindgen::Language::C)
        .generate()
    {
        b.write_to_file("target/Headers/zcashlc.h");
    }
}
