// build.rs
fn main() {
    let libs_dir = std::env::current_dir()
        .unwrap()
        .join("libs");
    
    println!("cargo:rustc-env=PYTHONPATH={}", libs_dir.display());
}