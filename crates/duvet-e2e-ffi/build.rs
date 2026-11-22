// `secret_service`: the platforms where the keyring is the Secret Service (Linux and the BSDs),
// which may have none, so the key falls back to a file.
fn main() {
    println!("cargo::rustc-check-cfg=cfg(secret_service)");
    let family = std::env::var("CARGO_CFG_TARGET_FAMILY").unwrap_or_default();
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if family.split(',').any(|family| family == "unix")
        && !matches!(os.as_str(), "macos" | "ios" | "android")
    {
        println!("cargo::rustc-cfg=secret_service");
    }
}
