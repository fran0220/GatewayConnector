use std::{collections::HashMap, fmt, sync::Mutex};

use gateway_connector_core::CredentialRef;
use thiserror::Error;
use zeroize::Zeroize;

/// Secret bearer with redacted diagnostics and zeroized storage on drop.
pub struct ApiKey(String);

impl ApiKey {
    pub fn new(value: impl Into<String>) -> Result<Self, VaultError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(VaultError::EmptyCredential);
        }
        Ok(Self(value))
    }

    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl Clone for ApiKey {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl fmt::Debug for ApiKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ApiKey([REDACTED])")
    }
}

impl Drop for ApiKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub trait CredentialStore: Send + Sync + fmt::Debug {
    fn get(&self, credential: &CredentialRef) -> Result<Option<ApiKey>, VaultError>;
    fn set(&self, credential: &CredentialRef, api_key: &ApiKey) -> Result<(), VaultError>;
    fn delete(&self, credential: &CredentialRef) -> Result<(), VaultError>;
}

#[derive(Debug)]
pub struct OsCredentialStore {
    service: String,
}

impl OsCredentialStore {
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    fn entry(&self, credential: &CredentialRef) -> Result<keyring::Entry, VaultError> {
        keyring::Entry::new(&self.service, credential.as_str())
            .map_err(|error| VaultError::Unavailable(error.to_string()))
    }
}

impl CredentialStore for OsCredentialStore {
    fn get(&self, credential: &CredentialRef) -> Result<Option<ApiKey>, VaultError> {
        match self.entry(credential)?.get_password() {
            Ok(value) => ApiKey::new(value).map(Some),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(VaultError::Unavailable(error.to_string())),
        }
    }

    fn set(&self, credential: &CredentialRef, api_key: &ApiKey) -> Result<(), VaultError> {
        self.entry(credential)?
            .set_password(api_key.expose_secret())
            .map_err(|error| VaultError::Unavailable(error.to_string()))
    }

    fn delete(&self, credential: &CredentialRef) -> Result<(), VaultError> {
        match self.entry(credential)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(VaultError::Unavailable(error.to_string())),
        }
    }
}

#[derive(Debug, Default)]
pub struct InMemoryCredentialStore {
    entries: Mutex<HashMap<CredentialRef, ApiKey>>,
}

impl CredentialStore for InMemoryCredentialStore {
    fn get(&self, credential: &CredentialRef) -> Result<Option<ApiKey>, VaultError> {
        self.entries
            .lock()
            .map_err(|_| VaultError::Poisoned)
            .map(|entries| entries.get(credential).cloned())
    }

    fn set(&self, credential: &CredentialRef, api_key: &ApiKey) -> Result<(), VaultError> {
        self.entries
            .lock()
            .map_err(|_| VaultError::Poisoned)?
            .insert(credential.clone(), api_key.clone());
        Ok(())
    }

    fn delete(&self, credential: &CredentialRef) -> Result<(), VaultError> {
        self.entries
            .lock()
            .map_err(|_| VaultError::Poisoned)?
            .remove(credential);
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("the API key is empty")]
    EmptyCredential,
    #[error("the operating-system credential store is unavailable: {0}")]
    Unavailable(String),
    #[error("the in-memory credential store lock is poisoned")]
    Poisoned,
}

#[cfg(test)]
mod tests {
    use super::*;
    use gateway_connector_core::ProfileId;

    #[test]
    fn in_memory_store_round_trips_without_exposing_debug_value() {
        let store = InMemoryCredentialStore::default();
        let reference = CredentialRef::for_profile(ProfileId::new());
        let key = ApiKey::new("very-secret").expect("valid key");
        assert_eq!(format!("{key:?}"), "ApiKey([REDACTED])");
        store.set(&reference, &key).expect("store key");
        assert_eq!(
            store
                .get(&reference)
                .expect("read key")
                .expect("key exists")
                .expose_secret(),
            "very-secret"
        );
        store.delete(&reference).expect("delete key");
        assert!(store.get(&reference).expect("read key").is_none());
    }
}
