/// uniffi-bindgen binary.
///
/// Invoke with:
///   cargo run --bin uniffi-bindgen -- generate \
///     --library target/debug/libtrueseal_noise.dylib \
///     --language swift --out-dir /tmp/swift-bindings
///
/// See: https://mozilla.github.io/uniffi-rs/tutorial/foreign_language_bindings.html
fn main() {
    uniffi::uniffi_bindgen_main()
}
