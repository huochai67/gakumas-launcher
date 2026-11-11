use std::{
    fs,
    io::{self, Write},
    path::PathBuf,
};

use crate::{client::DynError, models::StoredSession};

pub fn state_dir() -> Result<PathBuf, DynError> {
    let path = if let Some(path) = std::env::var_os("GAKUMAS_STATE_DIR") {
        PathBuf::from(path)
    } else if cfg!(windows) {
        PathBuf::from(std::env::var_os("LOCALAPPDATA").ok_or("LOCALAPPDATA is not set")?)
            .join("gakumas")
    } else if let Some(path) = std::env::var_os("XDG_STATE_HOME") {
        PathBuf::from(path).join("gakumas")
    } else {
        PathBuf::from(std::env::var_os("HOME").ok_or("HOME is not set")?)
            .join(".local/state/gakumas")
    };
    fs::create_dir_all(&path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o700));
    }
    Ok(path)
}

pub struct TokenStore {
    path: PathBuf,
}

impl TokenStore {
    pub fn new() -> Result<Self, DynError> {
        Ok(Self {
            path: state_dir()?.join("session.bin"),
        })
    }

    pub fn load(&self) -> Result<Option<StoredSession>, DynError> {
        let bytes = match fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let clear = protect_data(&bytes, false)?;
        Ok(serde_json::from_slice(&clear).ok())
    }

    pub fn save(&self, session: &StoredSession) -> Result<(), DynError> {
        let encrypted = protect_data(&serde_json::to_vec(session)?, true)?;
        let mut temp = tempfile::NamedTempFile::new_in(self.path.parent().unwrap())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = temp.as_file().set_permissions(fs::Permissions::from_mode(0o600));
        }
        temp.write_all(&encrypted)?;
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

pub fn local_identity_seed() -> Result<Vec<u8>, DynError> {
    let path = state_dir()?.join("identity.bin");
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

#[cfg(windows)]
fn protect_data(data: &[u8], protect: bool) -> Result<Vec<u8>, DynError> {
    use std::{
        mem::zeroed,
        ptr::{null, null_mut},
        slice::from_raw_parts,
    };
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::Cryptography::{
            CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
        },
    };
    let input = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    };
    let mut output: CRYPT_INTEGER_BLOB = unsafe { zeroed() };
    let ok = unsafe {
        if protect {
            CryptProtectData(&input, null(), null(), null(), null(), CRYPTPROTECT_UI_FORBIDDEN, &mut output)
        } else {
            CryptUnprotectData(&input, null_mut(), null(), null(), null(), CRYPTPROTECT_UI_FORBIDDEN, &mut output)
        }
    };
    if ok == 0 {
        return Err(io::Error::last_os_error().into());
    }
    let result = unsafe { from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe {
        LocalFree(output.pbData as *mut std::ffi::c_void);
    }
    Ok(result)
}

#[cfg(not(windows))]
fn protect_data(data: &[u8], _protect: bool) -> Result<Vec<u8>, DynError> {
    Ok(data.to_vec())
}
