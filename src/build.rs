extern crate bindgen;

use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:libdir=C:\\Program Files (x86)\\Windows Kits\\10\\Lib\\10.0.15063.0\\um\\x64\\Secur32.lib");
    println!("cargo:rustc-link-search=C:\\Program Files (x86)\\Windows Kits\\10\\Lib\\10.0.15063.0\\um\\x64");
    println!("cargo:rustc-link-lib=Secur32");

    // let bindings = bindgen::Builder::default()
    //     .no_unstable_rust()
    //     .header("src/wrapper.h")
    //     .whitelisted_function("AcquireCredentialsHandle|InitializeSecurityContext|CompleteAuthToken")
    //     .generate()
    //     .expect("Unable to generate bindings");

    //let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    // bindings.write_to_file("bindings.rs")
    //     .expect("Unable to write bindings");
    //bindings.write_to_file(out_path.join("bindings.rs"))
        //.expect("Couldn't write bindings");
}