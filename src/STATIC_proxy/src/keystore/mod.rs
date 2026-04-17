use anyhow::{anyhow, Result};
use serde::Deserialize;
use std::path::PathBuf;

#[cfg(not(target_os = "windows"))]
use keyring::{Entry, Error as KeyringError};

#[cfg(target_os = "windows")]
use std::fs;
#[cfg(target_os = "windows")]
use std::ptr;
#[cfg(target_os = "windows")]
use windows_sys::Win32::{
    Foundation::LocalFree,
    Security::Cryptography::{CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB},
};

/// Supported keystore backends.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum KeystoreMode {
    Keychain,
}

impl Default for KeystoreMode {
    fn default() -> Self {
        KeystoreMode::Keychain
    }
}

/// Configuration for secure keystore usage.
#[derive(Debug, Clone, Deserialize)]
pub struct KeystoreConfig {
    #[serde(default)]
    pub mode: KeystoreMode,
    /// Service name used by OS keychains.
    #[serde(default = "default_service")]
    pub service: String,
    /// Account/item name used by OS keychains.
    #[serde(default = "default_account")]
    pub account: String,
}

impl Default for KeystoreConfig {
    fn default() -> Self {
        Self {
            mode: KeystoreMode::Keychain,
            service: default_service(),
            account: default_account(),
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

/// Factory to build a keystore from config.
pub fn build_keystore(cfg: &KeystoreConfig, _protected_storage_path: PathBuf) -> Box<dyn KeyStore> {
    match cfg.mode {
        KeystoreMode::Keychain => {
            #[cfg(target_os = "windows")]
            {
                Box::new(WindowsDpapiKeyStore::new(_protected_storage_path))
            }

            #[cfg(not(target_os = "windows"))]
            {
                Box::new(KeychainKeyStore {
                    service: cfg.service.clone(),
                    account: cfg.account.clone(),
                })
            }
        }
    }
}

#[cfg(not(target_os = "windows"))]
struct KeychainKeyStore {
    service: String,
    account: String,
}

#[cfg(not(target_os = "windows"))]
impl KeyStore for KeychainKeyStore {
    fn get_secret(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let entry = Entry::new(&self.service, &format!("{}/{}", self.account, key))
            .map_err(|e| anyhow!("keychain entry failed: {e}"))?;
        match entry.get_password() {
            Ok(value) => {
                if value.trim().is_empty() {
                    return Ok(None);
                }
                Ok(Some(value.into_bytes()))
            }
            Err(KeyringError::NoEntry) => Ok(None),
            Err(e) => Err(anyhow!("keychain get failed: {e}")),
        }
    }

    fn set_secret(&self, key: &str, value: &[u8]) -> Result<()> {
        let entry = Entry::new(&self.service, &format!("{}/{}", self.account, key))
            .map_err(|e| anyhow!("keychain entry failed: {e}"))?;
        let value = std::str::from_utf8(value)
            .map_err(|_| anyhow!("keychain only supports UTF-8 secrets"))?;
        entry
            .set_password(value)
            .map_err(|e| anyhow!("keychain set failed: {e}"))?;

        Ok(())
    }

    fn delete_secret(&self, key: &str) -> Result<()> {
        let entry = Entry::new(&self.service, &format!("{}/{}", self.account, key))
            .map_err(|e| anyhow!("keychain entry failed: {e}"))?;
        let _ = entry.set_password("");
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
        LocalFree(out_blob.pbData.cast());
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
        LocalFree(out_blob.pbData.cast());
        vec
    };

    Ok(out)
}
