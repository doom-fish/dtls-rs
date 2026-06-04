//! Build script for `dtls-rs`.
//!
//! The crate itself contains no Swift or C sources — all platform crypto is
//! reached through the sibling `cryptokit-rs` and `security-rs` crates, whose
//! own build scripts emit the necessary `framework=` link directives. We still
//! declare the system frameworks we touch through the local `seckey` FFI shim
//! so the final link succeeds even when only this crate's FFI path is used.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rustc-link-lib=framework=Security");
    println!("cargo:rustc-link-lib=framework=CoreFoundation");
}
