use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::Mutex,
};

use gateway_connector_core::{ConnectionProfile, ProfileId};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub trait ProfileStore: Send + Sync + std::fmt::Debug {
    fn load(&self) -> Result<Vec<ConnectionProfile>, StoreError>;
    fn save(&self, profile: &ConnectionProfile) -> Result<(), StoreError>;
    fn delete(&self, profile_id: ProfileId) -> Result<(), StoreError>;
}

#[derive(Debug, Default)]
pub struct InMemoryProfileStore {
    profiles: Mutex<Vec<ConnectionProfile>>,
}

impl ProfileStore for InMemoryProfileStore {
    fn load(&self) -> Result<Vec<ConnectionProfile>, StoreError> {
        self.profiles
            .lock()
            .map_err(|_| StoreError::Poisoned)
            .map(|profiles| profiles.clone())
    }

    fn save(&self, profile: &ConnectionProfile) -> Result<(), StoreError> {
        let mut profiles = self.profiles.lock().map_err(|_| StoreError::Poisoned)?;
        profiles.retain(|existing| existing.id != profile.id);
        profiles.push(profile.clone());
        Ok(())
    }

    fn delete(&self, profile_id: ProfileId) -> Result<(), StoreError> {
        self.profiles
            .lock()
            .map_err(|_| StoreError::Poisoned)?
            .retain(|profile| profile.id != profile_id);
        Ok(())
    }
}

#[derive(Debug)]
pub struct JsonProfileStore {
    path: PathBuf,
    lock: Mutex<()>,
}

impl JsonProfileStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            lock: Mutex::new(()),
        }
    }

    fn read_unlocked(&self) -> Result<ProfileFile, StoreError> {
        match fs::read(&self.path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(StoreError::InvalidJson),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(ProfileFile::default())
            }
            Err(error) => Err(StoreError::Io(error)),
        }
    }

    fn write_unlocked(&self, file: &ProfileFile) -> Result<(), StoreError> {
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent).map_err(StoreError::Io)?;
        let bytes = serde_json::to_vec_pretty(file).map_err(StoreError::InvalidJson)?;
        let temporary = self.path.with_extension("tmp");
        let mut options = fs::OpenOptions::new();
        options.create(true).truncate(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut output = options.open(&temporary).map_err(StoreError::Io)?;
        output.write_all(&bytes).map_err(StoreError::Io)?;
        output.sync_all().map_err(StoreError::Io)?;
        fs::rename(temporary, &self.path).map_err(StoreError::Io)
    }
}

impl ProfileStore for JsonProfileStore {
    fn load(&self) -> Result<Vec<ConnectionProfile>, StoreError> {
        let _guard = self.lock.lock().map_err(|_| StoreError::Poisoned)?;
        Ok(self.read_unlocked()?.profiles)
    }

    fn save(&self, profile: &ConnectionProfile) -> Result<(), StoreError> {
        let _guard = self.lock.lock().map_err(|_| StoreError::Poisoned)?;
        let mut file = self.read_unlocked()?;
        file.profiles.retain(|existing| existing.id != profile.id);
        file.profiles.push(profile.clone());
        self.write_unlocked(&file)
    }

    fn delete(&self, profile_id: ProfileId) -> Result<(), StoreError> {
        let _guard = self.lock.lock().map_err(|_| StoreError::Poisoned)?;
        let mut file = self.read_unlocked()?;
        file.profiles.retain(|profile| profile.id != profile_id);
        self.write_unlocked(&file)
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct ProfileFile {
    #[serde(default)]
    profiles: Vec<ConnectionProfile>,
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("profile storage failed: {0}")]
    Io(std::io::Error),
    #[error("profile JSON is invalid: {0}")]
    InvalidJson(serde_json::Error),
    #[error("the profile store lock is poisoned")]
    Poisoned,
}

#[cfg(test)]
mod tests {
    use super::*;
    use gateway_connector_core::{CanonicalBaseUrl, Protocol};

    #[test]
    fn json_store_persists_only_profile_data() {
        let directory = tempfile::tempdir().expect("temp directory");
        let path = directory.path().join("profiles.json");
        let store = JsonProfileStore::new(&path);
        let profile = ConnectionProfile::new(
            "Gateway",
            CanonicalBaseUrl::parse("https://gateway.example").expect("valid URL"),
            Protocol::Auto,
        )
        .expect("valid profile");
        store.save(&profile).expect("save profile");
        assert_eq!(store.load().expect("load profiles"), vec![profile]);
        let json = fs::read_to_string(path).expect("read profile file");
        assert!(!json.contains("api_key"));
        assert!(!json.contains("bearer"));
    }
}
