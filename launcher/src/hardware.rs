use crate::client::DynError;
use crate::models::HardwareInfo;
#[cfg(windows)]
use serde_json::Value;
use sha2::{Digest, Sha256};

#[cfg(windows)]
const IDENTITY_SCRIPT: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$drive = Get-CimInstance Win32_DiskDrive | Where-Object { $_.Index -eq 0 } | Select-Object -First 1
$volume = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$($env:SystemDrive)'" | Select-Object -First 1
$board = Get-CimInstance Win32_BaseBoard | Select-Object -First 1
$bios = Get-CimInstance Win32_BIOS | Select-Object -First 1
$product = Get-CimInstance Win32_ComputerSystemProduct | Select-Object -First 1
$enclosure = Get-CimInstance Win32_SystemEnclosure | Select-Object -First 1
$mac = Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true -and $_.MACAddress } | Sort-Object MACAddress | Select-Object -First 1
[pscustomobject]@{
  disk = [string]$drive.SerialNumber
  volume = [string]$volume.VolumeSerialNumber
  board = [string]$board.SerialNumber
  bios = [string]$bios.SerialNumber
  product = [string]$product.UUID
  enclosure = [string]$enclosure.SerialNumber
  mac = [string]$mac.MACAddress
} | ConvertTo-Json -Compress
"#;

pub async fn collect() -> Result<HardwareInfo, DynError> {
    #[cfg(not(windows))]
    {
        let seed = crate::token::local_identity_seed()?;
        Ok(local_identity(&seed))
    }
    #[cfg(windows)]
    {
        let output = tokio::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", IDENTITY_SCRIPT])
            .output()
            .await?;
        if !output.status.success() {
            return Err("unable to read Windows hardware identity".into());
        }
        identity(&serde_json::from_slice(&output.stdout)?)
    }
}

#[cfg(not(windows))]
fn local_identity(seed: &[u8]) -> HardwareInfo {
    let digest = |label: &[u8]| {
        let mut hash = Sha256::new();
        hash.update(label);
        hash.update(seed);
        hash.finalize()
    };
    let mac = digest(b"gakumas/mac/");
    let mut mac = <[u8; 6]>::try_from(&mac[..6]).unwrap();
    mac[0] = (mac[0] | 2) & !1;
    HardwareInfo {
        mac_address: hex::encode_upper(mac),
        hdd_serial: hex::encode(digest(b"gakumas/disk/")),
        motherboard: hex::encode(digest(b"gakumas/board/")),
        user_os: "win".to_owned(),
    }
}

#[cfg(windows)]
fn identity(value: &Value) -> Result<HardwareInfo, DynError> {
    let text = |key: &str| {
        value
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .trim()
            .to_owned()
    };
    let mac = text("mac");
    let disk = [text("disk"), text("volume")]
        .into_iter()
        .find(|s| !s.is_empty())
        .unwrap_or_default();
    let board = [text("board"), text("bios"), text("product"), text("enclosure")]
        .into_iter()
        .find(|s| !s.is_empty())
        .unwrap_or_default();

    if mac.is_empty() || disk.is_empty() || board.is_empty() {
        return Err("unable to read Windows hardware identity".into());
    }

    let fingerprint = |v: &str| {
        let v = v.trim();
        if v.len() == 64 && v.chars().all(|c| c.is_ascii_hexdigit()) {
            v.to_lowercase()
        } else {
            hex::encode(Sha256::digest(v.as_bytes()))
        }
    };

    Ok(HardwareInfo {
        mac_address: mac.replace(['-', ':', ' '], "").to_uppercase(),
        hdd_serial: fingerprint(&disk),
        motherboard: fingerprint(&board),
        user_os: "win".to_owned(),
    })
}
