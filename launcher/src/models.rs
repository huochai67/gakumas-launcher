use std::path::PathBuf;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccessTokenInfo {
    #[serde(rename = "access_token")]
    pub access_token: String,
    #[serde(rename = "expires_in_seconds", default)]
    pub expires_in_seconds: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredSession {
    #[serde(flatten)]
    pub token: AccessTokenInfo,
    #[serde(default, alias = "storedAt", alias = "StoredAt")]
    pub stored_at: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(alias = "game_dir")]
    pub dir: Option<PathBuf>,
    #[serde(alias = "profile_repo", alias = "profile_url")]
    pub profile_base_url: Option<String>,
    pub bepinex: Option<PathBuf>,
    pub host: Option<PathBuf>,
    pub host_url: Option<String>,
    pub wine: Option<PathBuf>,
    pub wine_prefix: Option<PathBuf>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HardwareInfo {
    #[serde(rename = "mac_address")]
    pub mac_address: String,
    #[serde(rename = "hdd_serial")]
    pub hdd_serial: String,
    pub motherboard: String,
    pub user_os: String,
}

#[derive(Clone, Debug)]
pub struct LaunchInfo {
    pub file_list_url: String,
    pub latest_version: Option<String>,
    pub execute_args: Option<String>,
    pub sign: Option<String>,
    pub access_token_info: Option<AccessTokenInfo>,
}

#[derive(Clone, Debug)]
pub struct FileEntry {
    pub local_path: String,
    pub remote_path: String,
    pub size: u64,
    pub hash: Option<String>,
    pub check_hash: bool,
}

#[derive(Clone, Debug)]
pub struct FileManifest {
    pub domain: String,
    pub files: Vec<FileEntry>,
    pub signed_cookie: Option<String>,
}
