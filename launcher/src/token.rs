use std::{
    fs,
    io::{self, Write},
    path::PathBuf,
};

use crate::{
    client::DynError,
    models::{AppConfig, StoredSession},
};

pub fn config_dir() -> Result<PathBuf, DynError> {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .ok_or("HOME is not set")?;
    let path = PathBuf::from(home).join(".config").join("gakumas");
    fs::create_dir_all(&path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o700));
    }
    Ok(path)
}

pub fn load_config() -> Result<AppConfig, DynError> {
    let path = config_dir()?.join("config.json");
    match fs::read(&path) {
        Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(AppConfig::default()),
        Err(error) => Err(error.into()),
    }
}

pub struct TokenStore {
    path: PathBuf,
}

impl TokenStore {
    pub fn new() -> Result<Self, DynError> {
        Ok(Self {
            path: config_dir()?.join("session.json"),
        })
    }

    pub fn load(&self) -> Result<Option<StoredSession>, DynError> {
        let bytes = match fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let Ok(session) = serde_json::from_slice::<StoredSession>(&bytes) else {
            return Ok(None);
        };
        if session.token.access_token.trim().is_empty() {
            return Ok(None);
        }
        Ok(Some(session))
    }

    pub fn save(&self, session: &StoredSession) -> Result<(), DynError> {
        let mut payload = serde_json::to_vec_pretty(session)?;
        payload.push(b'\n');
        let mut temp = tempfile::NamedTempFile::new_in(self.path.parent().unwrap())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = temp.as_file().set_permissions(fs::Permissions::from_mode(0o600));
        }
        temp.write_all(&payload)?;
        temp.persist(&self.path)?;
        Ok(())
    }

    pub fn delete(&self) -> Result<(), DynError> {
        match fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

#[cfg(not(windows))]
pub fn local_identity_seed() -> Result<Vec<u8>, DynError> {
    let path = config_dir()?.join("identity.bin");
    if let Ok(bytes) = fs::read(&path) {
        if bytes.len() == 32 {
            return Ok(bytes);
        }
    }
    let mut bytes = vec![0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|_| "unable to generate local hardware identity")?;
    fs::write(&path, &bytes)?;
    Ok(bytes)
}
