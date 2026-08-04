use std::{env, error::Error, fs, io::Read, path::PathBuf};

const MCL_ARCHIVE: &str = "libmcl.a";
const ARCHIVE_MAGIC: [u8; 8] = *b"!<arch>\n";

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed=vendor/mcl");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=MCL_LIB_DIR");

    if let Some(library_directory) = prebuilt_library_directory()? {
        println!("cargo:rustc-link-search=native={library_directory}");
        println!("cargo:rustc-link-lib=static=mcl");
        link_cpp_runtime()?;
        return Ok(());
    }

    let manifest_directory = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR")
            .ok_or("Cargo did not set CARGO_MANIFEST_DIR for solana-bn254-mcl-sys")?,
    );
    let vendor = manifest_directory.join("vendor/mcl");
    cc::Build::new()
        .cpp(true)
        .std("c++11")
        .opt_level(3)
        .include(vendor.join("include"))
        .file(vendor.join("src/fp.cpp"))
        .file(vendor.join("src/bn_c256.cpp"))
        .define("MCL_FP_BIT", "256")
        .define("MCL_FR_BIT", "256")
        .define("MCL_SIZEOF_UNIT", "8")
        .define("MCL_BINT_ASM", "0")
        .define("MCL_MSM", "0")
        .define("MCL_DONT_USE_XBYAK", None)
        .define("NDEBUG", None)
        .flag_if_supported("-fomit-frame-pointer")
        .compile("mcl");
    link_cpp_runtime()?;
    Ok(())
}

fn prebuilt_library_directory() -> Result<Option<String>, Box<dyn Error>> {
    let Some(directory) = env::var_os("MCL_LIB_DIR") else {
        return Ok(None);
    };
    if directory.is_empty() {
        return Err("MCL_LIB_DIR must not be empty".into());
    }

    let directory = fs::canonicalize(PathBuf::from(directory))?;
    if !directory.is_dir() {
        return Err("MCL_LIB_DIR must identify a directory".into());
    }
    let archive = fs::canonicalize(directory.join(MCL_ARCHIVE))?;
    if !archive.starts_with(&directory) {
        return Err("MCL_LIB_DIR/libmcl.a must stay in MCL_LIB_DIR".into());
    }
    let metadata = archive.metadata()?;
    if !metadata.is_file() || metadata.len() <= ARCHIVE_MAGIC.len() as u64 {
        return Err("MCL_LIB_DIR/libmcl.a must be a nonempty regular archive".into());
    }

    let mut magic = [0u8; ARCHIVE_MAGIC.len()];
    fs::File::open(&archive)?.read_exact(&mut magic)?;
    if magic != ARCHIVE_MAGIC {
        return Err("MCL_LIB_DIR/libmcl.a does not have Unix archive format".into());
    }

    let directory = directory
        .to_str()
        .ok_or("MCL_LIB_DIR must contain valid UTF-8")?;
    if directory.contains(['\n', '\r']) {
        return Err("MCL_LIB_DIR must not contain line separators".into());
    }
    Ok(Some(directory.to_owned()))
}

fn link_cpp_runtime() -> Result<(), env::VarError> {
    match env::var("CARGO_CFG_TARGET_OS")?.as_str() {
        "macos" => println!("cargo:rustc-link-lib=c++"),
        "windows" => {}
        _ => println!("cargo:rustc-link-lib=stdc++"),
    }
    Ok(())
}
