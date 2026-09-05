fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/tunnel.proto");
    tonic_build::compile_protos("proto/tunnel.proto")?;
    Ok(())
}
