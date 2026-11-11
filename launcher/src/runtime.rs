use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use clap::Args;
use sha2::{Digest, Sha256};

use crate::{client::DynError, decrypt, download::safe_path, models::AppConfig, profile, token};

#[derive(Debug, Args)]
pub struct Options {
    #[arg(long, global = true, conflicts_with = "profile_base_url")]
    pub profile: Option<PathBuf>,
    #[arg(long, global = true, env = "GAKUMAS_PROFILE_BASE_URL", conflicts_with = "profile")]
    pub profile_base_url: Option<String>,
    #[arg(long, global = true)]
    pub host: Option<PathBuf>,
    #[arg(long, global = true)]
    pub host_url: Option<String>,
    #[arg(long, global = true)]
    pub wine: Option<PathBuf>,
    #[arg(long, global = true, env = "WINEPREFIX")]
    pub wine_prefix: Option<PathBuf>,
}

impl Options {
    pub fn apply_config(&mut self, config: &AppConfig) {
        if self.profile.is_none() && self.profile_base_url.is_none() {
            self.profile_base_url = Some(
                config
                    .profile_base_url
                    .clone()
                    .unwrap_or_else(|| profile::DEFAULT_PROFILE_BASE_URL.to_owned()),
            );
        }
        if self.host.is_none() {
            self.host = config.host.clone();
        }
        if self.host_url.is_none() {
            self.host_url = config.host_url.clone();
        }
        if self.wine.is_none() {
            self.wine = config.wine.clone();
        }
        if self.wine_prefix.is_none() {
            self.wine_prefix = config.wine_prefix.clone();
        }
    }

    pub fn wine_bin(&self) -> PathBuf {
        self.wine.clone().unwrap_or_else(|| PathBuf::from("wine"))
    }
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

fn candidate_host_urls(options: &Options) -> Vec<String> {
    let mut urls = Vec::new();
    if let Some(url) = &options.host_url {
        urls.push(url.clone());
    }
    if let Some(base) = &options.profile_base_url {
        let trimmed = base.trim_end_matches('/');
        if let Some(rest) = trimmed.strip_prefix("https://raw.githubusercontent.com/") {
            let parts: Vec<&str> = rest.split('/').collect();
            if parts.len() >= 2 {
                urls.push(format!(
                    "https://github.com/{}/{}/releases/latest/download/gakumas.exe",
                    parts[0], parts[1]
                ));
            }
        } else if let Some(rest) = trimmed.strip_prefix("https://github.com/") {
            let parts: Vec<&str> = rest.split('/').collect();
            if parts.len() >= 2 {
                urls.push(format!(
                    "https://github.com/{}/{}/releases/latest/download/gakumas.exe",
                    parts[0], parts[1]
                ));
            }
        }
        urls.push(format!("{trimmed}/gakumas.exe"));
    }
    urls
}

async fn resolve_host_binary(options: &Options, game_root: &Path) -> Result<PathBuf, DynError> {
    if let Some(path) = &options.host {
        return Ok(fs::canonicalize(path)?);
    }

    let mut candidates = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            candidates.push(parent.join("gakumas.exe"));
        }
    }
    candidates.push(PathBuf::from("gakumas.exe"));
    if let Ok(cfg_dir) = token::config_dir() {
        candidates.push(cfg_dir.join("gakumas.exe"));
    }
    candidates.push(PathBuf::from(
        "public/launcher/target/x86_64-pc-windows-msvc/release/gakumas.exe",
    ));
    candidates.push(PathBuf::from(
        "public/launcher/target/x86_64-pc-windows-gnu/release/gakumas.exe",
    ));

    let game_exe = game_root.join("gakumas.exe");
    let game_exe_canon = fs::canonicalize(&game_exe).ok();
    for candidate in candidates {
        if candidate.is_file() {
            if let Ok(canon) = fs::canonicalize(&candidate) {
                if game_exe_canon.as_ref() != Some(&canon) {
                    return Ok(canon);
                }
            }
        }
    }

    #[cfg(windows)]
    {
        if let Ok(exe) = std::env::current_exe() {
            if let Ok(canon) = fs::canonicalize(&exe) {
                if game_exe_canon.as_ref() != Some(&canon) {
                    return Ok(canon);
                }
            }
        }
    }

    let urls = candidate_host_urls(options);
    if !urls.is_empty() {
        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(15))
            .timeout(std::time::Duration::from_secs(60))
            .build()?;
        let dest = token::config_dir()?.join("gakumas.exe");
        for url in &urls {
            if let Ok(response) = client.get(url).send().await {
                if response.status().is_success() {
                    if let Ok(bytes) = response.bytes().await {
                        if bytes.len() > 1024 && &bytes[0..2] == b"MZ" {
                            let mut temp = tempfile::NamedTempFile::new_in(dest.parent().unwrap())?;
                            temp.write_all(&bytes)?;
                            temp.persist(&dest)?;
                            println!("Downloaded host binary: {url} -> {}", dest.display());
                            return Ok(dest);
                        }
                    }
                }
            }
        }
    }

    Err("host gakumas.exe not found; place gakumas.exe in ~/.config/gakumas/gakumas.exe, configure profile_base_url/host_url, or pass --host <PATH>".into())
}

pub async fn decrypt(root: &Path, options: &Options, force: bool) -> Result<(), DynError> {
    let ga = root.join("GameAssembly.dll");
    let packed = root.join("GameAssembly.dll.bak");
    let mut has_backup = packed.is_file();
    if has_backup && ga.is_file() {
        if sha256(&packed)? == sha256(&ga)? {
            let _ = fs::remove_file(&packed);
            has_backup = false;
        } else if !force {
            println!("GameAssembly.dll already decrypted (use --force to re-decrypt).");
            return Ok(());
        }
    }
    let input = if has_backup {
        &packed
    } else if ga.is_file() {
        &ga
    } else {
        return Err("GameAssembly.dll is missing; run download first".into());
    };
    let packed_hash = sha256(input)?;
    let source = profile::resolve(
        options.profile.as_deref(),
        options.profile_base_url.as_deref(),
        &packed_hash,
    )
    .await?;

    let backup = (!has_backup).then_some(packed.as_path());
    let output_hash = decrypt::decrypt_with_profile(input, &ga, backup, source.path())?;
    println!("Decrypted GameAssembly.dll (SHA-256: {output_hash}): {}", ga.display());
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
        let host = resolve_host_binary(options, root).await?;
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
