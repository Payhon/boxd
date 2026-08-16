use std::{env, fs, path::PathBuf};

use sha2::{Digest, Sha256};

const ASSET_ENV: &str = "BOXD_EMBEDDED_LIBKRUN_PATH";
const SHA_ENV: &str = "BOXD_EMBEDDED_LIBKRUN_SHA256";
const LICENSE_ENV: &str = "BOXD_EMBEDDED_LIBKRUN_LICENSE_PATH";
const FW_ASSET_ENV: &str = "BOXD_EMBEDDED_LIBKRUNFW_PATH";
const FW_SHA_ENV: &str = "BOXD_EMBEDDED_LIBKRUNFW_SHA256";
const FW_LICENSE_ENV: &str = "BOXD_EMBEDDED_LIBKRUNFW_LICENSE_PATH";

fn main() {
    println!("cargo:rerun-if-env-changed={ASSET_ENV}");
    println!("cargo:rerun-if-env-changed={SHA_ENV}");
    println!("cargo:rerun-if-env-changed={LICENSE_ENV}");
    println!("cargo:rerun-if-env-changed={FW_ASSET_ENV}");
    println!("cargo:rerun-if-env-changed={FW_SHA_ENV}");
    println!("cargo:rerun-if-env-changed={FW_LICENSE_ENV}");

    let output = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo provides OUT_DIR"));
    let libkrun = embed_asset(&output, "libkrun", ASSET_ENV, SHA_ENV, LICENSE_ENV);
    let libkrunfw = embed_asset(
        &output,
        "libkrunfw",
        FW_ASSET_ENV,
        FW_SHA_ENV,
        FW_LICENSE_ENV,
    );
    assert_eq!(
        libkrun, libkrunfw,
        "libkrun and libkrunfw must either both be embedded or both be absent"
    );
}

fn embed_asset(
    output: &std::path::Path,
    name: &str,
    asset_env: &str,
    sha_env: &str,
    license_env: &str,
) -> bool {
    let artifact_output = output.join(format!("embedded-{name}.bin"));
    let license_output = output.join(format!("embedded-{name}-license.txt"));
    let identity_output = output.join(format!("embedded-{name}-sha256.txt"));
    match (
        env::var_os(asset_env),
        env::var(sha_env).ok(),
        env::var_os(license_env),
    ) {
        (None, None, None) => {
            fs::write(artifact_output, []).expect("write empty development asset");
            fs::write(license_output, []).expect("write empty development license");
            fs::write(identity_output, []).expect("write empty development identity");
            false
        }
        (Some(artifact), Some(expected), Some(license)) => {
            let expected = expected.to_ascii_lowercase();
            assert!(
                expected.len() == 64 && expected.bytes().all(|byte| byte.is_ascii_hexdigit()),
                "{sha_env} must contain exactly 64 hexadecimal characters"
            );
            let bytes = fs::read(&artifact).expect("read configured libkrun asset");
            let actual = format!("{:x}", Sha256::digest(&bytes));
            assert_eq!(
                actual, expected,
                "configured {name} asset does not match {sha_env}"
            );
            let license_bytes = fs::read(&license).expect("read configured libkrun license");
            assert!(
                !license_bytes.is_empty(),
                "configured {name} license must not be empty"
            );
            fs::write(artifact_output, bytes).expect("copy verified libkrun asset");
            fs::write(license_output, license_bytes).expect("copy libkrun license");
            fs::write(identity_output, expected).expect("write embedded artifact identity");
            true
        }
        _ => panic!(
            "{asset_env}, {sha_env}, and {license_env} must either all be set or all be absent"
        ),
    }
}
