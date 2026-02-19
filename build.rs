use std::{env::var, error::Error, path::Path};

use tonic_prost_build::configure;

const PROTO_DIRECTORY: &str = "proto/signer/v1";
const PROTO_FILENAME: &str = "signer.proto";
const PROTO_DESCRIPTOR: &str = "proto_descriptor.bin";

/// Build script to compile protobuf definitions into Rust code.
///
/// # Errors
/// * `Box<dyn Error>` - if the protobuf compilation fails.
///
/// # Returns
/// * `Ok(())` - if the build script completes successfully.
/// * `Err(Box<dyn Error>)` - if an error occurs during protobuf compilation.
fn main() -> Result<(), Box<dyn Error>> {
    let proto_filepath: String = Path::new(PROTO_DIRECTORY)
        .join(PROTO_FILENAME)
        .to_string_lossy()
        .into_owned();

    let output_directory: String = var("OUT_DIR")?;
    let proto_descriptor_filepath: String = Path::new(&output_directory)
        .join(PROTO_DESCRIPTOR)
        .to_string_lossy()
        .into_owned();

    match configure()
        .build_server(true)
        .build_client(true)
        .file_descriptor_set_path(proto_descriptor_filepath)
        .compile_protos(&[proto_filepath], &[String::from(PROTO_DIRECTORY)])
    {
        Ok(_) => (),
        Err(error) => return Err(Box::new(error)),
    };

    Ok(())
}
