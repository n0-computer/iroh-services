fn main() {
    built::write_built_file().expect("Failed to acquire build-time information");

    // Setup cfg aliases
    cfg_aliases::cfg_aliases! {
        // Convenience aliases
        wasm_browser: { all(target_family = "wasm", target_os = "unknown") },
    }

    // Make the TARGET env variable available at compile time
    println!(
        "cargo:rustc-env=TARGET={}",
        std::env::var("TARGET").unwrap()
    );
}
