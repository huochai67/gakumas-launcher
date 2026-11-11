use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};

use clap::Args;
use sha2::{Digest, Sha256};

use crate::{client::DynError, download::safe_path, profile};

#[derive(Debug, Args)]
pub struct Options {
    #[arg(long, global = true, default_value = if cfg!(windows) { "python" } else { "python3" })]
    pub python: PathBuf,
    #[arg(long, global = true, default_value = "public/decrypt.py")]
    pub decrypt_script: PathBuf,
    #[arg(long, global = true, conflicts_with = "profile_base_url")]
    pub profile: Option<PathBuf>,
    #[arg(long, global = true, conflicts_with = "profile")]
    pub profile_base_url: Option<String>,
    #[arg(long, global = true)]
    pub host: Option<PathBuf>,
    #[arg(long, global = true, default_value = "wine")]
    pub wine: PathBuf,
    #[arg(long, global = true, env = "WINEPREFIX")]
    pub wine_prefix: Option<PathBuf>,
}

pub fn sha256(path: &Path) -> Result<String, DynError> {
    let mut input = fs::File::open(path)?;
    let mut buffer = [0u8; 128 * 1024];
    let mut hash = Sha256::new();
    loop {
        let size = input.read(&mut buffer)?;
        if size == 0 {
            break;
        }
        hash.update(&buffer[..size]);
    }
    Ok(hex::encode(hash.finalize()))
}

/// Restore backed-up original binaries before running DMM manifest integrity checks.
pub fn restore_backups(root: &Path) -> Result<(), DynError> {
    for (bak, orig) in [
        ("GameAssembly.dll.bak", "GameAssembly.dll"),
        ("gakumas.exe.bak", "gakumas.exe"),
    ] {
        let bak_path = root.join(bak);
        if bak_path.is_file() {
            fs::rename(&bak_path, root.join(orig))?;
        }
    }
    Ok(())
}

pub async fn decrypt(root: &Path, options: &Options) -> Result<(), DynError> {
    let ga = root.join("GameAssembly.dll");
    let packed = root.join("GameAssembly.dll.bak");
    if !packed.is_file() {
        if !ga.is_file() {
            return Err("GameAssembly.dll is missing; run download first".into());
        }
        fs::copy(&ga, &packed)?;
    }
    let packed_hash = sha256(&packed)?;
    let source = profile::resolve(
        options.profile.as_deref(),
        options.profile_base_url.as_deref(),
        &packed_hash,
    )
    .await?;
    let script = fs::canonicalize(&options.decrypt_script)
        .map_err(|_| format!("decrypt script not found: {}", options.decrypt_script.display()))?;

    let status = tokio::process::Command::new(&options.python)
        .arg(script)
        .arg(&packed)
        .arg(&ga)
        .arg("--profile")
        .arg(source.path())
        .status()
        .await?;
    if !status.success() {
        return Err("profile decryption failed".into());
    }
    println!("Decrypted GameAssembly.dll: {}", ga.display());
    Ok(())
}

pub async fn prepare(root: &Path, options: &Options, bepinex: Option<&Path>) -> Result<(), DynError> {
    let host = match &options.host {
        Some(path) => fs::canonicalize(path)?,
        None => std::env::current_exe()?
            .parent()
            .ok_or("launcher has no parent directory")?
            .join("gakumas.exe"),
    };
    if !host.is_file() {
        return Err(format!("host gakumas.exe not found at {}; pass --host <PATH>", host.display()).into());
    }

    decrypt(root, options).await?;

    let exe = root.join("gakumas.exe");
    let exe_bak = root.join("gakumas.exe.bak");
    if exe.is_file() && !exe_bak.is_file() {
        fs::copy(&exe, &exe_bak)?;
    }
    fs::copy(&host, &exe)?;

    if let Some(zip_path) = bepinex {
        extract_bepinex(zip_path, root)?;
    }
    println!("Prepared game directory: {}", root.display());
    Ok(())
}

fn extract_bepinex(zip_path: &Path, root: &Path) -> Result<(), DynError> {
    let mut archive = zip::ZipArchive::new(fs::File::open(zip_path)?)?;
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        if entry.is_dir() {
            continue;
        }
        let dest = safe_path(root, entry.name())?;
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut out = fs::File::create(&dest)?;
        std::io::copy(&mut entry, &mut out)?;
    }
    Ok(())
}
