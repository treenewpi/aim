fn main() {
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let plist = manifest.join("src/bin/linux-run.plist");
    println!("cargo:rerun-if-changed={}", plist.display());
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux") {
        // Darwin symbols the guest ABI declares. They fail; macOS links the
        // real ones and does not build this file.
        let stubs = manifest.join("src/linux_host_stubs.c");
        println!("cargo:rerun-if-changed={}", stubs.display());
        let out = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
        let obj = out.join("linux_host_stubs.o");
        let status = std::process::Command::new("cc")
            .args(["-c", "-fPIC", "-O2"])
            .arg(&stubs)
            .arg("-o")
            .arg(&obj)
            .status()
            .expect("cc");
        assert!(status.success(), "linux host stubs failed to compile");
        println!("cargo:rustc-link-arg={}", obj.display());
    }
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        // Cargo links to a hash-suffixed filename; keep its ad-hoc identity stable.
        println!("cargo:rustc-link-arg-bin=linux-run=-Wl,-final_output,dev.aim.linux-run");
        println!(
            "cargo:rustc-link-arg-bin=linux-run=-Wl,-sectcreate,__TEXT,__info_plist,{}",
            plist.display()
        );
    }
}
