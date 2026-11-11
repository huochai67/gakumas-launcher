use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccessTokenInfo {
    #[serde(rename = "access_token")]
    pub access_token: String,
    #[serde(rename = "expires_in_seconds")]
    pub expires_in_seconds: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredSession {
    pub token: AccessTokenInfo,
    #[serde(rename = "storedAt", alias = "stored_at", alias = "StoredAt")]
    pub stored_at: String,
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
