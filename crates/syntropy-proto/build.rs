use std::path::{Path, PathBuf};

fn find_protoc() -> Option<PathBuf> {
    // 1. Explicit PROTOC environment variable
    if let Ok(path) = std::env::var("PROTOC") {
        let p = PathBuf::from(path);
        if p.exists() {
            return Some(p);
        }
    }

    // 2. Windows Scoop locations
    #[cfg(windows)]
    if let Ok(home) = std::env::var("USERPROFILE") {
        let home_path = Path::new(&home);
        let candidates = [
            home_path.join("scoop").join("shims").join("protoc.exe"),
            home_path.join("scoop").join("apps").join("protobuf").join("current").join("bin").join("protoc.exe"),
        ];
        for candidate in candidates {
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }

    // 3. Common Unix/macOS locations
    #[cfg(not(windows))]
    {
        let candidates = [
            PathBuf::from("/opt/homebrew/bin/protoc"),
            PathBuf::from("/usr/local/bin/protoc"),
            PathBuf::from("/usr/bin/protoc"),
        ];
        for candidate in candidates {
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }

    None
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/tunnel.proto");

    if let Some(protoc_path) = find_protoc() {
        std::env::set_var("PROTOC", protoc_path);
    }

    tonic_build::compile_protos("proto/tunnel.proto")?;
    Ok(())
}
