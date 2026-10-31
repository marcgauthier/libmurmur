use std::path::PathBuf;

fn main() {
    let root = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap())
        .join("../..");
    println!("cargo:rustc-link-search=native={}", root.display());
    println!("cargo:rustc-link-lib=static=murmur");
    for lib in ["stdc++", "pthread", "dl", "m"] {
        println!("cargo:rustc-link-lib=dylib={lib}");
    }
    println!("cargo:rerun-if-changed={}", root.join("libmurmur.a").display());
}
