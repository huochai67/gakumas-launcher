use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use futures_util::StreamExt;
use md5::{Digest, Md5};
use sha1::Sha1;
use sha2::Sha256;
use tokio::{io::AsyncWriteExt, sync::Semaphore, task::JoinSet};

use crate::{
    client::{DmmClient, DynError},
    models::{FileEntry, FileManifest},
};

pub fn safe_path(root: &Path, relative: &str) -> Result<PathBuf, DynError> {
    let normalized = relative.replace('\\', "/").trim_start_matches('/').to_owned();
    if normalized.is_empty() || normalized.contains(':') {
        return Err(format!("manifest path is not relative: {relative}").into());
    }
    if normalized.split('/').any(|seg| seg.is_empty() || seg == "." || seg == "..") {
        return Err(format!("manifest path escapes install directory: {relative}").into());
    }
    Ok(root.join(normalized))
}

fn backup_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".bak");
    PathBuf::from(name)
}

pub async fn download_all(
    api: DmmClient,
    manifest: FileManifest,
    root: PathBuf,
    force: bool,
    jobs: usize,
) -> Result<(), DynError> {
    let total = manifest.files.len();
    let domain = manifest.domain;
    let cookie = manifest.signed_cookie;
    let semaphore = Arc::new(Semaphore::new(jobs.max(1)));
    let mut tasks = JoinSet::new();

    for file in manifest.files {
        let semaphore = semaphore.clone();
        let api = api.clone();
        let domain = domain.clone();
        let cookie = cookie.clone();
        let root = root.clone();
        tasks.spawn(async move {
            let _permit = semaphore.acquire_owned().await?;
            let result = download_one(&api, &domain, cookie.as_deref(), &root, &file, force).await;
            result.map(|status| (file.local_path, status))
        });
    }

    let mut completed = 0;
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                tasks.abort_all();
                return Err("canceled".into());
            }
            joined = tasks.join_next() => {
                let Some(joined) = joined else { break; };
                let (path, status) = joined??;
                completed += 1;
                println!("[{completed}/{total}] {}{}", path, if status { "" } else { " skip" });
            }
        }
    }
    Ok(())
}

pub async fn dry_run(
    manifest: FileManifest,
    root: PathBuf,
    force: bool,
    jobs: usize,
) -> Result<Vec<FileEntry>, DynError> {
    println!("Checking file integrity...");
    let pending = check_integrity(manifest.files, root, force, jobs).await?;
    if pending.is_empty() {
        println!("Files to download: 0 (all files verified).");
    } else {
        println!("Files to download ({}):", pending.len());
        for file in &pending {
            println!("{}", file.local_path);
        }
    }
    Ok(pending)
}

pub async fn check_integrity(
    files: Vec<FileEntry>,
    root: PathBuf,
    force: bool,
    jobs: usize,
) -> Result<Vec<FileEntry>, DynError> {
    let total = files.len();
    let semaphore = Arc::new(Semaphore::new(jobs.max(1)));
    let mut tasks = JoinSet::new();

    for (index, file) in files.into_iter().enumerate() {
        let semaphore = semaphore.clone();
        let root = root.clone();
        tasks.spawn(async move {
            let _permit = semaphore.acquire_owned().await?;
            let destination = safe_path(&root, &file.local_path)?;
            let needs_download = if force {
                true
            } else {
                !complete_or_backed_up(&destination, &file).await?
            };
            Ok::<_, DynError>((index, file, needs_download))
        });
    }

    let mut results = Vec::with_capacity(total);
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                tasks.abort_all();
                return Err("canceled".into());
            }
            joined = tasks.join_next() => {
                let Some(joined) = joined else { break; };
                let (index, file, needs_download) = joined??;
                results.push((index, file, needs_download));
            }
        }
    }

    results.sort_by_key(|(index, _, _)| *index);
    let pending = results
        .into_iter()
        .filter_map(|(_, file, needs_download)| if needs_download { Some(file) } else { None })
        .collect();

    Ok(pending)
}

async fn download_one(
    api: &DmmClient,
    domain: &str,
    cookie: Option<&str>,
    root: &Path,
    file: &FileEntry,
    force: bool,
) -> Result<bool, DynError> {
    let destination = safe_path(root, &file.local_path)?;
    if !force && complete_or_backed_up(&destination, file).await? {
        return Ok(false);
    }
    if let Some(parent) = destination.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let temporary = tempfile::NamedTempFile::new_in(destination.parent().unwrap())?;
    let response = api
        .download_response(domain, &file.remote_path, cookie)
        .await?;
    let mut stream = response.bytes_stream();
    let mut output = tokio::fs::File::from_std(temporary.reopen()?);
    while let Some(chunk) = stream.next().await {
        output.write_all(&chunk?).await?;
    }
    output.flush().await?;
    output.sync_all().await?;
    drop(output);
    if tokio::fs::metadata(temporary.path()).await?.len() != file.size {
        return Err(format!("size mismatch for {}", file.local_path).into());
    }
    if file.check_hash
        && file.hash.as_deref().is_some_and(|hash| !hash.is_empty())
        && !verify_hash(temporary.path(), file.hash.as_deref().unwrap()).await?
    {
        return Err(format!("hash mismatch for {}", file.local_path).into());
    }
    let _ = tokio::fs::remove_file(backup_path(&destination)).await;
    temporary.persist(&destination)?;
    Ok(true)
}

async fn complete_or_backed_up(path: &Path, file: &FileEntry) -> Result<bool, DynError> {
    let bak = backup_path(path);
    if bak.is_file() {
        return complete(&bak, file).await;
    }
    complete(path, file).await
}

async fn complete(path: &Path, file: &FileEntry) -> Result<bool, DynError> {
    if !path.is_file() {
        return Ok(false);
    }
    if tokio::fs::metadata(path).await?.len() != file.size {
        return Ok(false);
    }
    if !file.check_hash || file.hash.as_deref().is_none_or(str::is_empty) {
        return Ok(true);
    }
    verify_hash(path, file.hash.as_deref().unwrap()).await
}

async fn verify_hash(path: &Path, expected: &str) -> Result<bool, DynError> {
    let mut file = tokio::fs::File::open(path).await?;
    let mut buffer = vec![0u8; 128 * 1024];
    match expected.len() {
        32 => {
            let mut hasher = Md5::new();
            loop {
                let count = tokio::io::AsyncReadExt::read(&mut file, &mut buffer).await?;
                if count == 0 {
                    break;
                }
                hasher.update(&buffer[..count]);
            }
            Ok(hex::encode(hasher.finalize()).eq_ignore_ascii_case(expected))
        }
        40 => {
            let mut hasher = Sha1::new();
            loop {
                let count = tokio::io::AsyncReadExt::read(&mut file, &mut buffer).await?;
                if count == 0 {
                    break;
                }
                hasher.update(&buffer[..count]);
            }
            Ok(hex::encode(hasher.finalize()).eq_ignore_ascii_case(expected))
        }
        64 => {
            let mut hasher = Sha256::new();
            loop {
                let count = tokio::io::AsyncReadExt::read(&mut file, &mut buffer).await?;
                if count == 0 {
                    break;
                }
                hasher.update(&buffer[..count]);
            }
            Ok(hex::encode(hasher.finalize()).eq_ignore_ascii_case(expected))
        }
        _ => Ok(false),
    }
}
