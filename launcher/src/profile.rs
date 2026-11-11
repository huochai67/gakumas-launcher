use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use reqwest::Client;
use serde::Deserialize;
use url::Url;

use crate::client::DynError;

const FILES: [&str; 5] = ["manifest.json", "key.bin", "sbox.bin", "pass3.bin", "records.bin"];

#[derive(Deserialize)]
struct Status {
    decrypted: bool,
    packed_sha256: Option<String>,
    profile: Option<String>,
}

pub enum Profile {
    Local(PathBuf),
    Downloaded(tempfile::TempDir),
}

impl Profile {
    pub fn path(&self) -> &Path {
        match self {
            Self::Local(path) => path,
            Self::Downloaded(dir) => dir.path(),
        }
    }
}

pub async fn resolve(
    local: Option<&Path>,
    base_url: Option<&str>,
    packed_sha256: &str,
) -> Result<Profile, DynError> {
    match (local, base_url) {
        (Some(path), None) => {
            let path = fs::canonicalize(path)?;
            if !path.is_dir() {
                return Err("profile path is not a directory".into());
            }
            Ok(Profile::Local(path))
        }
        (None, Some(raw_base)) => {
            let base = Url::parse(&format!("{}/", raw_base.trim_end_matches('/')))?;
            let http = Client::new();
            let status: Status = http
                .get(base.join("status.json")?)
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            if !status.decrypted {
                return Err("remote status has decrypted=false".into());
            }
            if status.packed_sha256.as_deref() != Some(packed_sha256) {
                return Err("remote profile packed_sha256 does not match local GameAssembly.dll".into());
            }
            let rel = status
                .profile
                .as_deref()
                .ok_or("remote status has no profile path")?
                .trim_matches('/');
            if rel.is_empty() || rel.contains("..") || rel.contains("://") {
                return Err(format!("invalid remote profile path: {rel}").into());
            }
            let dir_url = base.join(&format!("{rel}/"))?;
            let temp = tempfile::tempdir()?;
            for name in FILES {
                let bytes = http
                    .get(dir_url.join(name)?)
                    .send()
                    .await?
                    .error_for_status()?
                    .bytes()
                    .await?;
                let mut file = fs::File::create(temp.path().join(name))?;
                file.write_all(&bytes)?;
            }
            Ok(Profile::Downloaded(temp))
        }
        (None, None) => Err("decrypt/prepare requires --profile <DIR> or --profile-base-url <URL>".into()),
        (Some(_), Some(_)) => Err("--profile and --profile-base-url are mutually exclusive".into()),
    }
}
