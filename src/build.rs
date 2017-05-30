extern crate bindgen;

use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rustc-link-lib=secur32");

    let bindings = bindgen::Builder::default()
        .no_unstable_rust()
        .header("src/wrapper.h")
        .whitelisted_function("AcquireCredentialsHandle")
        .whitelisted_function("InitializeSecurityContext")
        .whitelisted_function("CompleteAuthToken")
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings.write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings");
}