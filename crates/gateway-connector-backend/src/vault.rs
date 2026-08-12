use std::{collections::HashMap, fmt, sync::Mutex};

use gateway_connector_core::{ConnectionProfile, CredentialRef, ProfileId};
use thiserror::Error;
use zeroize::Zeroize;

use crate::{ProfileStore, StoreError};

/// Credential secret with redacted diagnostics and zeroized storage on drop.
pub struct ApiKey(String);

impl ApiKey {
    pub fn new(value: impl Into<String>) -> Result<Self, VaultError> {
        let value = value.into();
        if value.trim().is_empty() || value.chars().any(char::is_control) {
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

/// Local credential persistence. Production uses the app profile config file;
/// tests may use an in-memory map.
pub trait CredentialStore: Send + Sync + fmt::Debug {
    fn get(&self, profile: &ConnectionProfile) -> Result<Option<ApiKey>, VaultError>;
    fn set(&self, profile: &ConnectionProfile, api_key: &ApiKey) -> Result<(), VaultError>;
    fn delete(&self, credential: &CredentialRef) -> Result<(), VaultError>;
}

/// Stores API keys / access tokens on the connection profile document itself
/// (`profiles.json`). There is no OS keychain / keyring dependency.
#[derive(Debug)]
pub struct ProfileCredentialStore {
    profiles: std::sync::Arc<dyn ProfileStore>,
}

impl ProfileCredentialStore {
    pub fn new(profiles: std::sync::Arc<dyn ProfileStore>) -> Self {
        Self { profiles }
    }

    fn load_profile(&self, profile_id: ProfileId) -> Result<Option<ConnectionProfile>, VaultError> {
        let profiles = self.profiles.load().map_err(VaultError::from)?;
        Ok(profiles.into_iter().find(|profile| profile.id == profile_id))
    }
}

impl CredentialStore for ProfileCredentialStore {
    fn get(&self, profile: &ConnectionProfile) -> Result<Option<ApiKey>, VaultError> {
        if !profile.credential_secret.is_empty() {
            return ApiKey::new(profile.credential_secret.clone()).map(Some);
        }
        let Some(stored) = self.load_profile(profile.id)? else {
            return Ok(None);
        };
        if stored.credential_secret.is_empty() {
            return Ok(None);
        }
        ApiKey::new(stored.credential_secret).map(Some)
    }

    fn set(&self, profile: &ConnectionProfile, api_key: &ApiKey) -> Result<(), VaultError> {
        let mut stored = self
            .load_profile(profile.id)?
            .ok_or(VaultError::ProfileMissing)?;
        stored.credential_secret = api_key.expose_secret().to_owned();
        stored.validate().map_err(|error| {
            VaultError::Unavailable(format!("profile invalid after credential write: {error}"))
        })?;
        self.profiles.save(&stored).map_err(VaultError::from)?;
        Ok(())
    }

    fn delete(&self, credential: &CredentialRef) -> Result<(), VaultError> {
        let profiles = self.profiles.load().map_err(VaultError::from)?;
        let Some(mut stored) = profiles
            .into_iter()
            .find(|profile| profile.credential == *credential)
        else {
            return Ok(());
        };
        if stored.credential_secret.is_empty() {
            return Ok(());
        }
        stored.credential_secret.clear();
        // Profile may be about to be deleted; treat a missing-row save race as ok.
        match self.profiles.save(&stored) {
            Ok(()) | Err(StoreError::ActiveProfileExists) => Ok(()),
            Err(error) => Err(VaultError::from(error)),
        }
    }
}

#[derive(Debug, Default)]
pub struct InMemoryCredentialStore {
    entries: Mutex<HashMap<CredentialRef, ApiKey>>,
}

impl CredentialStore for InMemoryCredentialStore {
    fn get(&self, profile: &ConnectionProfile) -> Result<Option<ApiKey>, VaultError> {
        let entries = self.entries.lock().map_err(|_| VaultError::Poisoned)?;
        Ok(entries.get(&profile.credential).cloned())
    }

    fn set(&self, profile: &ConnectionProfile, api_key: &ApiKey) -> Result<(), VaultError> {
        self.entries
            .lock()
            .map_err(|_| VaultError::Poisoned)?
            .insert(profile.credential.clone(), api_key.clone());
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
    #[error("the credential is empty")]
    EmptyCredential,
    #[error("credential storage failed: {0}")]
    Unavailable(String),
    #[error("no profile exists for this credential write")]
    ProfileMissing,
    #[error("the credential store lock is poisoned")]
    Poisoned,
    #[error("profile store error: {0}")]
    ProfileStore(#[from] StoreError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::InMemoryProfileStore;
    use gateway_connector_core::{CanonicalBaseUrl, Protocol};
    use std::sync::Arc;

    #[test]
    fn profile_store_round_trips_secret_in_app_config() {
        let profiles = Arc::new(InMemoryProfileStore::default());
        let store = ProfileCredentialStore::new(profiles.clone());
        let profile = ConnectionProfile::new(
            "Test",
            CanonicalBaseUrl::parse("https://gateway.example").expect("base URL"),
            Protocol::Auto,
        )
        .expect("profile");
        profiles.create(&profile).expect("create profile");
        let key = ApiKey::new("very-secret").expect("valid key");
        assert_eq!(format!("{key:?}"), "ApiKey([REDACTED])");
        store.set(&profile, &key).expect("store key");
        let loaded = profiles.load().expect("load")[0].clone();
        assert_eq!(loaded.credential_secret, "very-secret");
        assert_eq!(
            store
                .get(&loaded)
                .expect("read key")
                .expect("key exists")
                .expose_secret(),
            "very-secret"
        );
        store
            .delete(&profile.credential)
            .expect("delete credential");
        let cleared = profiles.load().expect("load")[0].clone();
        assert!(cleared.credential_secret.is_empty());
        assert!(store.get(&cleared).expect("read key").is_none());
    }

    #[test]
    fn in_memory_store_round_trips_without_exposing_debug_value() {
        let store = InMemoryCredentialStore::default();
        let profile = ConnectionProfile::new(
            "Test",
            CanonicalBaseUrl::parse("https://gateway.example").expect("base URL"),
            Protocol::Auto,
        )
        .expect("profile");
        let key = ApiKey::new("very-secret").expect("valid key");
        assert_eq!(format!("{key:?}"), "ApiKey([REDACTED])");
        store.set(&profile, &key).expect("store key");
        assert_eq!(
            store
                .get(&profile)
                .expect("read key")
                .expect("key exists")
                .expose_secret(),
            "very-secret"
        );
        store
            .delete(&profile.credential)
            .expect("delete credential");
        assert!(store.get(&profile).expect("read key").is_none());
    }
}
