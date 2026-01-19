use anyhow::{anyhow, Result};
use serde::Deserialize;
use std::{fs, path::PathBuf};

#[cfg(not(target_os = "windows"))]
use keyring::{Entry, Error as KeyringError};

#[cfg(target_os = "windows")]
use std::ptr;
#[cfg(target_os = "windows")]
use windows_sys::Win32::{
    Security::Cryptography::{CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB},
    System::Memory::LocalFree,
};

/// Supported keystore backends.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum KeystoreMode {
    File,
    Keychain,
}

impl Default for KeystoreMode {
    fn default() -> Self {
        KeystoreMode::File
    }
}

/// Configuration for keystore usage. Defaults to file storage for backward compatibility.
#[derive(Debug, Clone, Deserialize)]
pub struct KeystoreConfig {
    #[serde(default)]
    pub mode: KeystoreMode,
    /// Service name used by OS keychains. Ignored for file mode.
    #[serde(default = "default_service")]
    pub service: String,
    /// Account/item name used by OS keychains. Ignored for file mode.
    #[serde(default = "default_account")]
    pub account: String,
    /// Optional fallback key path; used for file mode or to permit a disk copy.
    #[serde(default)]
    pub fallback_path: Option<PathBuf>,
}

impl Default for KeystoreConfig {
    fn default() -> Self {
        Self {
            mode: KeystoreMode::File,
            service: default_service(),
            account: default_account(),
            fallback_path: None,
        }
    }
}

fn default_service() -> String {
    "404.static_proxy".to_string()
}

fn default_account() -> String {
    "ca_key".to_string()
}

pub trait KeyStore: Send + Sync {
    fn get_secret(&self, key: &str) -> Result<Option<Vec<u8>>>;
    fn set_secret(&self, key: &str, value: &[u8]) -> Result<()>;
    fn delete_secret(&self, key: &str) -> Result<()>;
}

/// Factory to build a keystore from config. `fallback` is used for file mode and optional disk copies.
pub fn build_keystore(cfg: &KeystoreConfig, fallback: PathBuf) -> Box<dyn KeyStore> {
    match cfg.mode {
        KeystoreMode::File => {
            let path = cfg.fallback_path.clone().unwrap_or(fallback);
            Box::new(FileKeyStore { path })
        }
        KeystoreMode::Keychain => {
            #[cfg(target_os = "windows")]
            {
                if cfg.fallback_path.is_none() {
                    return Box::new(WindowsDpapiKeyStore::new(fallback));
                }
            }

            #[cfg(not(target_os = "windows"))]
            {
                return Box::new(KeychainKeyStore {
                    service: cfg.service.clone(),
                    account: cfg.account.clone(),
                    // Fallback remains opt-in: only used if explicitly configured.
                    fallback: cfg.fallback_path.clone(),
                });
            }

            #[cfg(target_os = "windows")]
            {
                // Windows with an explicit fallback continues to use the file keystore semantics.
                let path = cfg.fallback_path.clone().unwrap_or(fallback);
                return Box::new(FileKeyStore { path });
            }
        }
    }
}

struct FileKeyStore {
    path: PathBuf,
}

impl KeyStore for FileKeyStore {
    fn get_secret(&self, _key: &str) -> Result<Option<Vec<u8>>> {
        if self.path.exists() {
            Ok(Some(fs::read(&self.path)?))
        } else {
            Ok(None)
        }
    }

    fn set_secret(&self, _key: &str, value: &[u8]) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&self.path, value)?;
        Ok(())
    }

    fn delete_secret(&self, _key: &str) -> Result<()> {
        if self.path.exists() {
            let _ = fs::remove_file(&self.path);
        }
        Ok(())
    }
}

#[cfg(not(target_os = "windows"))]
struct KeychainKeyStore {
    service: String,
    account: String,
    fallback: Option<PathBuf>,
}

#[cfg(not(target_os = "windows"))]
impl KeyStore for KeychainKeyStore {
    fn get_secret(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let entry = Entry::new(&self.service, &format!("{}/{}", self.account, key))
            .map_err(|e| anyhow!("keychain entry failed: {e}"))?;
        match entry.get_password() {
            Ok(value) => {
                if value.trim().is_empty() {
                    if let Some(path) = &self.fallback {
                        if path.exists() {
                            return Ok(Some(fs::read(path)?));
                        }
                    }
                    return Ok(None);
                }
                Ok(Some(value.into_bytes()))
            }
            Err(KeyringError::NoEntry) => {
                if let Some(path) = &self.fallback {
                    if path.exists() {
                        return Ok(Some(fs::read(path)?));
                    }
                }
                Ok(None)
            }
            Err(e) => Err(anyhow!("keychain get failed: {e}")),
        }
    }

    fn set_secret(&self, key: &str, value: &[u8]) -> Result<()> {
        let entry = Entry::new(&self.service, &format!("{}/{}", self.account, key))
            .map_err(|e| anyhow!("keychain entry failed: {e}"))?;
        entry
            .set_password(std::str::from_utf8(value).unwrap_or_default())
            .map_err(|e| anyhow!("keychain set failed: {e}"))?;

        if let Some(path) = &self.fallback {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(path, value)?;
        }

        Ok(())
    }

    fn delete_secret(&self, key: &str) -> Result<()> {
        let entry = Entry::new(&self.service, &format!("{}/{}", self.account, key))
            .map_err(|e| anyhow!("keychain entry failed: {e}"))?;
        let _ = entry.set_password("");
        if let Some(path) = &self.fallback {
            if path.exists() {
                let _ = fs::remove_file(path);
            }
        }
        Ok(())
    }
}

#[cfg(target_os = "windows")]
struct WindowsDpapiKeyStore {
    path: PathBuf,
}

#[cfg(target_os = "windows")]
impl WindowsDpapiKeyStore {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

#[cfg(target_os = "windows")]
impl KeyStore for WindowsDpapiKeyStore {
    fn get_secret(&self, _key: &str) -> Result<Option<Vec<u8>>> {
        if self.path.exists() {
            let enc = fs::read(&self.path)?;
            if let Ok(bytes) = dpapi_unprotect(&enc) {
                return Ok(Some(bytes));
            }
        }

        Ok(None)
    }

    fn set_secret(&self, _key: &str, value: &[u8]) -> Result<()> {
        let enc = dpapi_protect(value)?;
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&self.path, enc)?;

        Ok(())
    }

    fn delete_secret(&self, _key: &str) -> Result<()> {
        if self.path.exists() {
            let _ = fs::remove_file(&self.path);
        }

        Ok(())
    }
}

#[cfg(target_os = "windows")]
fn dpapi_protect(data: &[u8]) -> Result<Vec<u8>> {
    let mut in_blob = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    };
    let mut out_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };

    let ok = unsafe {
        CryptProtectData(
            &mut in_blob,
            ptr::null(),
            ptr::null(),
            ptr::null_mut(),
            ptr::null_mut(),
            0,
            &mut out_blob,
        )
    };

    if ok == 0 {
        return Err(anyhow!("CryptProtectData failed"));
    }

    let out = unsafe {
        let slice = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize);
        let vec = slice.to_vec();
        LocalFree(out_blob.pbData as isize);
        vec
    };

    Ok(out)
}

#[cfg(target_os = "windows")]
fn dpapi_unprotect(data: &[u8]) -> Result<Vec<u8>> {
    if data.is_empty() {
        return Err(anyhow!("empty blob"));
    }

    let mut in_blob = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    };
    let mut out_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };

    let ok = unsafe {
        CryptUnprotectData(
            &mut in_blob,
            ptr::null_mut(),
            ptr::null(),
            ptr::null_mut(),
            ptr::null_mut(),
            0,
            &mut out_blob,
        )
    };

    if ok == 0 {
        return Err(anyhow!("CryptUnprotectData failed"));
    }

    let out = unsafe {
        let slice = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize);
        let vec = slice.to_vec();
        LocalFree(out_blob.pbData as isize);
        vec
    };

    Ok(out)
}
