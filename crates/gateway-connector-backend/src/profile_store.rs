use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::Mutex,
};

use fs2::FileExt;
use gateway_connector_core::{ConnectionProfile, ProfileId};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub trait ProfileStore: Send + Sync + std::fmt::Debug {
    fn load(&self) -> Result<Vec<ConnectionProfile>, StoreError>;
    fn create(&self, profile: &ConnectionProfile) -> Result<(), StoreError>;
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

    fn create(&self, profile: &ConnectionProfile) -> Result<(), StoreError> {
        let mut profiles = self.profiles.lock().map_err(|_| StoreError::Poisoned)?;
        if !profiles.is_empty() {
            return Err(StoreError::ActiveProfileExists);
        }
        profiles.push(profile.clone());
        Ok(())
    }

    fn save(&self, profile: &ConnectionProfile) -> Result<(), StoreError> {
        let mut profiles = self.profiles.lock().map_err(|_| StoreError::Poisoned)?;
        if profiles.iter().any(|existing| existing.id != profile.id) {
            return Err(StoreError::ActiveProfileExists);
        }
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
        if let Err(error) = replace_file(&temporary, &self.path) {
            let _ = fs::remove_file(temporary);
            return Err(error);
        }
        Ok(())
    }

    fn acquire_file_lock(&self) -> Result<fs::File, StoreError> {
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent).map_err(StoreError::Io)?;
        let lock_path = self.path.with_extension("lock");
        let mut options = fs::OpenOptions::new();
        options.create(true).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(lock_path).map_err(StoreError::Io)?;
        file.lock_exclusive().map_err(StoreError::Io)?;
        Ok(file)
    }
}

#[cfg(not(windows))]
fn replace_file(from: &Path, to: &Path) -> Result<(), StoreError> {
    fs::rename(from, to).map_err(StoreError::Io)
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn replace_file(from: &Path, to: &Path) -> Result<(), StoreError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    let from: Vec<u16> = from.as_os_str().encode_wide().chain(Some(0)).collect();
    let to: Vec<u16> = to.as_os_str().encode_wide().chain(Some(0)).collect();
    if unsafe {
        MoveFileExW(
            from.as_ptr(),
            to.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        Err(StoreError::Io(std::io::Error::last_os_error()))
    } else {
        Ok(())
    }
}

impl ProfileStore for JsonProfileStore {
    fn load(&self) -> Result<Vec<ConnectionProfile>, StoreError> {
        let _guard = self.lock.lock().map_err(|_| StoreError::Poisoned)?;
        let _file_lock = self.acquire_file_lock()?;
        Ok(self.read_unlocked()?.profiles)
    }

    fn create(&self, profile: &ConnectionProfile) -> Result<(), StoreError> {
        let _guard = self.lock.lock().map_err(|_| StoreError::Poisoned)?;
        let _file_lock = self.acquire_file_lock()?;
        let mut file = self.read_unlocked()?;
        if !file.profiles.is_empty() {
            return Err(StoreError::ActiveProfileExists);
        }
        file.profiles.push(profile.clone());
        self.write_unlocked(&file)
    }

    fn save(&self, profile: &ConnectionProfile) -> Result<(), StoreError> {
        let _guard = self.lock.lock().map_err(|_| StoreError::Poisoned)?;
        let _file_lock = self.acquire_file_lock()?;
        let mut file = self.read_unlocked()?;
        if file
            .profiles
            .iter()
            .any(|existing| existing.id != profile.id)
        {
            return Err(StoreError::ActiveProfileExists);
        }
        file.profiles.retain(|existing| existing.id != profile.id);
        file.profiles.push(profile.clone());
        self.write_unlocked(&file)
    }

    fn delete(&self, profile_id: ProfileId) -> Result<(), StoreError> {
        let _guard = self.lock.lock().map_err(|_| StoreError::Poisoned)?;
        let _file_lock = self.acquire_file_lock()?;
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
    #[error("a different connection profile is already active")]
    ActiveProfileExists,
}

#[cfg(test)]
mod tests {
    use super::*;
    use gateway_connector_core::{CanonicalBaseUrl, Protocol};
    use std::sync::{Arc, Barrier};

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
        assert!(!json.contains("very-secret"));
        assert!(!json.contains("bearer"));
    }

    #[test]
    fn separate_store_instances_atomically_enforce_one_profile() {
        let directory = tempfile::tempdir().expect("temp directory");
        let path = directory.path().join("profiles.json");
        let profiles = ["One", "Two"].map(|name| {
            ConnectionProfile::new(
                name,
                CanonicalBaseUrl::parse("https://gateway.example").expect("valid URL"),
                Protocol::Auto,
            )
            .expect("valid profile")
        });
        let barrier = Arc::new(Barrier::new(2));
        let handles = profiles.map(|profile| {
            let path = path.clone();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let store = JsonProfileStore::new(path);
                barrier.wait();
                store.create(&profile)
            })
        });
        let results = handles.map(|handle| handle.join().expect("store thread"));
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(StoreError::ActiveProfileExists)))
                .count(),
            1
        );
        assert_eq!(
            JsonProfileStore::new(path)
                .load()
                .expect("load profiles")
                .len(),
            1
        );
    }
}
