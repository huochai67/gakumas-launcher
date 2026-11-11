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
    #[arg(long, global = true)]
    pub decrypt_script: Option<PathBuf>,
    #[arg(long, global = true, conflicts_with = "profile_base_url")]
    pub profile: Option<PathBuf>,
    #[arg(long, global = true, env = "GAKUMAS_PROFILE_BASE_URL", conflicts_with = "profile")]
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

fn find_decrypt_script(explicit: Option<&Path>) -> Result<PathBuf, DynError> {
    if let Some(path) = explicit {
        return Ok(fs::canonicalize(path)?);
    }
    let mut candidates = vec![PathBuf::from("decrypt.py"), PathBuf::from("public/decrypt.py")];
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            candidates.push(parent.join("decrypt.py"));
            candidates.push(parent.join("../decrypt.py"));
        }
    }
    for candidate in candidates {
        if candidate.is_file() {
            return Ok(fs::canonicalize(candidate)?);
        }
    }
    Err("decrypt.py not found; pass --decrypt-script <PATH>".into())
}

fn find_host_binary(explicit: Option<&Path>, game_root: &Path) -> Result<PathBuf, DynError> {
    if let Some(path) = explicit {
        return Ok(fs::canonicalize(path)?);
    }
    let mut candidates = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            candidates.push(parent.join("gakumas.exe"));
        }
    }
    candidates.push(PathBuf::from("gakumas.exe"));
    candidates.push(PathBuf::from("public/launcher/target/x86_64-pc-windows-msvc/release/gakumas.exe"));
    candidates.push(PathBuf::from("public/launcher/target/x86_64-pc-windows-gnu/release/gakumas.exe"));

    let game_exe = game_root.join("gakumas.exe");
    for candidate in candidates {
        if candidate.is_file() {
            if let Ok(canon) = fs::canonicalize(&candidate) {
                if fs::canonicalize(&game_exe).ok().as_ref() != Some(&canon) {
                    return Ok(canon);
                }
            }
        }
    }
    Err("host gakumas.exe not found; build `--bin gakumas` for Windows x64 or pass --host <PATH>".into())
}

pub async fn decrypt(root: &Path, options: &Options, force: bool) -> Result<(), DynError> {
    let ga = root.join("GameAssembly.dll");
    let packed = root.join("GameAssembly.dll.bak");
    if packed.is_file() && ga.is_file() && !force {
        println!("GameAssembly.dll already decrypted (use --force to re-decrypt).");
        return Ok(());
    }
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
    let script = find_decrypt_script(options.decrypt_script.as_deref())?;

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

pub async fn prepare(
    root: &Path,
    options: &Options,
    bepinex: Option<&Path>,
    force: bool,
) -> Result<(), DynError> {
    decrypt(root, options, force).await?;

    let exe = root.join("gakumas.exe");
    let exe_bak = root.join("gakumas.exe.bak");
    if !exe_bak.is_file() || force || options.host.is_some() {
        let host = find_host_binary(options.host.as_deref(), root)?;
        if exe.is_file() && !exe_bak.is_file() {
            fs::copy(&exe, &exe_bak)?;
        }
        fs::copy(&host, &exe)?;
    }

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
