use std::{
    fs,
    io::{Read, Write},
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
        reject_reparse_components(&self.path)?;
        match open_nofollow(&self.path, false) {
            Ok(mut input) => {
                let mut bytes = Vec::new();
                input.read_to_end(&mut bytes).map_err(StoreError::Io)?;
                serde_json::from_slice(&bytes).map_err(StoreError::InvalidJson)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(ProfileFile::default())
            }
            Err(error) => Err(StoreError::Io(error)),
        }
    }

    fn write_unlocked(&self, file: &ProfileFile) -> Result<(), StoreError> {
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        reject_reparse_components(parent)?;
        fs::create_dir_all(parent).map_err(StoreError::Io)?;
        reject_reparse_components(parent)?;
        reject_reparse_components(&self.path)?;
        let bytes = serde_json::to_vec_pretty(file).map_err(StoreError::InvalidJson)?;
        let (temporary, mut output) = create_temporary(&self.path)?;
        output.write_all(&bytes).map_err(StoreError::Io)?;
        output.sync_all().map_err(StoreError::Io)?;
        if let Err(error) = replace_file(&temporary, &self.path) {
            let _ = fs::remove_file(temporary);
            return Err(error);
        }
        sync_parent(parent)?;
        Ok(())
    }

    fn acquire_file_lock(&self) -> Result<fs::File, StoreError> {
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        let lock_path = self.path.with_extension("lock");
        reject_reparse_components(parent)?;
        fs::create_dir_all(parent).map_err(StoreError::Io)?;
        reject_reparse_components(parent)?;
        reject_reparse_components(&lock_path)?;
        let file = open_nofollow(&lock_path, true).map_err(StoreError::Io)?;
        reject_reparse_components(&lock_path)?;
        file.lock_exclusive().map_err(StoreError::Io)?;
        Ok(file)
    }
}

fn reject_reparse_components(path: &Path) -> Result<(), StoreError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if is_reparse(&metadata) => {
                return Err(StoreError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "profile storage path contains a symlink or reparse point",
                )));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => return Err(StoreError::Io(error)),
        }
    }
    Ok(())
}

fn is_reparse(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
    }
    #[cfg(not(windows))]
    false
}

fn open_nofollow(path: &Path, create: bool) -> std::io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.read(true).write(create).create(create);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options.open(path)
}

fn create_temporary(path: &Path) -> Result<(PathBuf, fs::File), StoreError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    for _ in 0..128 {
        let temporary = parent.join(format!(".{name}.{:016x}.tmp", rand::random::<u64>()));
        reject_reparse_components(&temporary)?;
        let mut options = fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        match options.open(&temporary) {
            Ok(file) => return Ok((temporary, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(StoreError::Io(error)),
        }
    }
    Err(StoreError::Io(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not allocate a unique profile temporary file",
    )))
}

fn sync_parent(parent: &Path) -> Result<(), StoreError> {
    #[cfg(unix)]
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(StoreError::Io)?;
    Ok(())
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

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_parent_profile_and_lock_paths() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("temp directory");
        let real = directory.path().join("real");
        fs::create_dir(&real).expect("real directory");
        let linked = directory.path().join("linked");
        symlink(&real, &linked).expect("parent symlink");
        assert!(
            JsonProfileStore::new(linked.join("profiles.json"))
                .load()
                .is_err()
        );

        let path = real.join("profiles.json");
        let target = real.join("target");
        fs::write(&target, b"{}").expect("target");
        symlink(&target, &path).expect("profile symlink");
        assert!(JsonProfileStore::new(&path).load().is_err());
        fs::remove_file(&path).expect("remove profile symlink");
        let lock_path = real.join("profiles.lock");
        if lock_path.exists() {
            fs::remove_file(&lock_path).expect("remove prior lock");
        }

        symlink(&target, lock_path).expect("lock symlink");
        assert!(JsonProfileStore::new(path).load().is_err());
    }

    #[test]
    fn unique_temporary_files_do_not_clobber_an_existing_candidate() {
        let directory = tempfile::tempdir().expect("temp directory");
        let path = directory.path().join("profiles.json");
        let stale = directory.path().join("profiles.tmp");
        fs::write(&stale, b"do not overwrite").expect("stale temporary");
        JsonProfileStore::new(&path)
            .delete(ProfileId::new())
            .expect("write profile store");
        assert_eq!(
            fs::read(stale).expect("stale temporary"),
            b"do not overwrite"
        );
        assert!(
            fs::read_dir(directory.path())
                .expect("directory")
                .filter_map(Result::ok)
                .all(|entry| !entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".profiles.json."))
        );
    }
}
