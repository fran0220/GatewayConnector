//! One-root portable acceptance layout for the generic executable.
//!
//! This prevents accidental use of normal application/coordinator/Agent paths.
//! It is not a security sandbox against another process running as the same user.

use std::{
    ffi::{OsStr, OsString},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};

use fs2::FileExt;
use gateway_connector_backend::Distribution;
use gateway_connector_core::{AgentId, FixedAgentRoots};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const MARKER_NAME: &str = ".gateway-connector-isolated-root.json";
const LOCK_NAME: &str = ".gateway-connector-isolated-root.lock";
const TEMP_PREFIX: &str = ".gateway-connector-isolated-root.";
const TEMP_SUFFIX: &str = ".tmp";
const MARKER_KIND: &str = "gateway-connector-isolated-root";
const MARKER_SCHEMA: u32 = 1;
const MAX_MARKER_BYTES: u64 = 16 * 1024;

#[derive(Debug, Clone)]
pub enum LaunchRequest {
    Normal,
    Isolated(Box<IsolatedLayout>),
}

impl LaunchRequest {
    /// Parses the exact generic production command before any default path
    /// resolver or persistent store is constructed.
    pub fn from_args(
        distribution: &Distribution,
        args: impl IntoIterator<Item = OsString>,
    ) -> Result<Self, IsolatedRootError> {
        let mut args = args.into_iter();
        let Some(flag) = args.next() else {
            return Ok(Self::Normal);
        };
        if flag != OsStr::new("--isolated-root") {
            return Err(IsolatedRootError::InvalidArguments);
        }
        let root = args.next().ok_or(IsolatedRootError::MissingIsolatedRoot)?;
        if args.next().is_some() {
            return Err(IsolatedRootError::InvalidArguments);
        }
        if !distribution.allow_isolated_root {
            return Err(IsolatedRootError::Disabled);
        }
        IsolatedLayout::prepare(PathBuf::from(root)).map(|layout| Self::Isolated(Box::new(layout)))
    }
}

#[derive(Debug, Clone)]
pub struct IsolatedLayout {
    root: PathBuf,
    root_id: [u8; 16],
    path_digest: [u8; 32],
    profiles_file: PathBuf,
    preferences_file: PathBuf,
    state_dir: PathBuf,
    coordinator_dir: PathBuf,
    agent_roots: [PathBuf; 5],
}

impl IsolatedLayout {
    pub fn prepare(requested: PathBuf) -> Result<Self, IsolatedRootError> {
        let root = prepare_root(&requested)?;
        let initial = classify_root(&root)?;
        match initial {
            RootContents::Marked => {
                // Reject malformed, copied, or special markers without even
                // creating the otherwise harmless root lock file.
                read_and_validate_marker(&root)?;
            }
            RootContents::Initializable => {}
            RootContents::UnmarkedNonEmpty => {
                return Err(IsolatedRootError::UnmarkedNonEmpty(root));
            }
        }

        let lock_path = root.join(LOCK_NAME);
        let lock = open_plain(&lock_path, true)?;
        lock.lock_exclusive()
            .map_err(|source| isolated_io(&lock_path, source))?;

        let marker = match classify_root(&root)? {
            RootContents::Marked => read_and_validate_marker(&root)?,
            RootContents::Initializable => {
                remove_interrupted_temporaries(&root)?;
                create_marker(&root)?
            }
            RootContents::UnmarkedNonEmpty => {
                return Err(IsolatedRootError::UnmarkedNonEmpty(root));
            }
        };

        let data_dir = root.join("data");
        let state_dir = root.join("state");
        let coordinator_dir = root.join("coordinator");
        let agents_dir = root.join("agents");
        for path in [&data_dir, &state_dir, &coordinator_dir, &agents_dir] {
            ensure_plain_descendant(&root, path)?;
        }
        let agent_roots = AgentId::ALL.map(|agent| agents_dir.join(agent.as_str()));
        for path in &agent_roots {
            ensure_plain_descendant(&root, path)?;
        }

        let root_id = decode_hex::<16>(&marker.root_id)
            .ok_or_else(|| IsolatedRootError::InvalidMarker("root_id is invalid".into()))?;
        let path_digest = canonical_path_digest(&root);
        let layout = Self {
            profiles_file: data_dir.join("profiles.json"),
            preferences_file: data_dir.join("ui-preferences.json"),
            state_dir,
            coordinator_dir,
            agent_roots,
            root,
            root_id,
            path_digest,
        };
        layout.revalidate()?;
        Ok(layout)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn profiles_file(&self) -> &Path {
        &self.profiles_file
    }

    pub fn preferences_file(&self) -> &Path {
        &self.preferences_file
    }

    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    pub fn coordinator_dir(&self) -> &Path {
        &self.coordinator_dir
    }

    pub fn agent_roots(&self) -> FixedAgentRoots {
        FixedAgentRoots::new(self.agent_roots.clone())
    }

    pub fn revalidate(&self) -> Result<(), IsolatedRootError> {
        validate_existing_components(&self.root)?;
        let marker = read_and_validate_marker(&self.root)?;
        let root_id = decode_hex::<16>(&marker.root_id)
            .ok_or_else(|| IsolatedRootError::InvalidMarker("root_id is invalid".into()))?;
        if root_id != self.root_id || canonical_path_digest(&self.root) != self.path_digest {
            return Err(IsolatedRootError::InvalidMarker(
                "isolated root identity changed".into(),
            ));
        }
        let data_dir = self
            .profiles_file
            .parent()
            .expect("isolated profile file has a data directory");
        for path in self.agent_roots.iter().map(PathBuf::as_path).chain([
            data_dir,
            self.state_dir.as_path(),
            self.coordinator_dir.as_path(),
        ]) {
            validate_plain_descendant(&self.root, path)?;
        }
        let preferences_lock = data_dir.join("preferences.lock");
        for path in [
            &self.profiles_file,
            &self.preferences_file,
            &preferences_lock,
        ] {
            validate_optional_plain_file(&self.root, path)?;
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum IsolatedRootError {
    #[error("usage: gateway-connector [--isolated-root <absolute-path>]")]
    InvalidArguments,
    #[error("--isolated-root requires an absolute path")]
    MissingIsolatedRoot,
    #[error("this distribution disables isolated-root mode")]
    Disabled,
    #[error("isolated root must be an absolute, unambiguous path: {0}")]
    InvalidPath(PathBuf),
    #[error("isolated root must be a new leaf or an existing directory: {0}")]
    InvalidRoot(PathBuf),
    #[error("isolated root path contains a symlink, reparse point, or special component: {0}")]
    UnsafeComponent(PathBuf),
    #[error("isolated root is non-empty and has no valid GatewayConnector marker: {0}")]
    UnmarkedNonEmpty(PathBuf),
    #[error("isolated root marker is invalid: {0}")]
    InvalidMarker(String),
    #[error("isolated-root filesystem operation failed at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct RootIdentity {
    device: u64,
    file: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IsolatedRootMarker {
    kind: String,
    schema_version: u32,
    root_id: String,
    root_identity: RootIdentity,
    canonical_path_sha256: String,
    binding_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RootContents {
    Initializable,
    Marked,
    UnmarkedNonEmpty,
}

fn prepare_root(requested: &Path) -> Result<PathBuf, IsolatedRootError> {
    if !requested.is_absolute()
        || requested
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(IsolatedRootError::InvalidPath(requested.to_owned()));
    }
    let parent = requested
        .parent()
        .filter(|parent| *parent != requested)
        .ok_or_else(|| IsolatedRootError::InvalidRoot(requested.to_owned()))?;
    let name = requested
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| IsolatedRootError::InvalidRoot(requested.to_owned()))?;

    validate_existing_components(requested)?;
    let existing = match fs::symlink_metadata(requested) {
        Ok(metadata) => {
            if !metadata.is_dir() || is_reparse(&metadata) {
                return Err(IsolatedRootError::UnsafeComponent(requested.to_owned()));
            }
            true
        }
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => false,
        Err(source) => return Err(isolated_io(requested, source)),
    };

    let canonical = if existing {
        fs::canonicalize(requested).map_err(|source| isolated_io(requested, source))?
    } else {
        let metadata =
            fs::symlink_metadata(parent).map_err(|source| isolated_io(parent, source))?;
        if !metadata.is_dir() || is_reparse(&metadata) {
            return Err(IsolatedRootError::UnsafeComponent(parent.to_owned()));
        }
        let canonical_parent =
            fs::canonicalize(parent).map_err(|source| isolated_io(parent, source))?;
        validate_existing_components(&canonical_parent)?;
        let candidate = canonical_parent.join(name);
        fs::create_dir(&candidate).map_err(|source| isolated_io(&candidate, source))?;
        set_private_directory(&candidate)?;
        sync_directory(&canonical_parent)?;
        fs::canonicalize(&candidate).map_err(|source| isolated_io(&candidate, source))?
    };
    validate_existing_components(&canonical)?;
    let metadata =
        fs::symlink_metadata(&canonical).map_err(|source| isolated_io(&canonical, source))?;
    if !metadata.is_dir() || is_reparse(&metadata) {
        return Err(IsolatedRootError::UnsafeComponent(canonical));
    }
    Ok(canonical)
}

fn classify_root(root: &Path) -> Result<RootContents, IsolatedRootError> {
    let mut has_marker = false;
    let mut initializable = true;
    for entry in fs::read_dir(root).map_err(|source| isolated_io(root, source))? {
        let entry = entry.map_err(|source| isolated_io(root, source))?;
        let name = entry.file_name();
        if name == OsStr::new(MARKER_NAME) {
            has_marker = true;
            continue;
        }
        if name == OsStr::new(LOCK_NAME) || is_marker_temporary(&name) {
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|source| isolated_io(&entry.path(), source))?;
            if !metadata.is_file() || is_reparse(&metadata) {
                return Err(IsolatedRootError::UnsafeComponent(entry.path()));
            }
            continue;
        }
        initializable = false;
    }
    Ok(if has_marker {
        RootContents::Marked
    } else if initializable {
        RootContents::Initializable
    } else {
        RootContents::UnmarkedNonEmpty
    })
}

fn is_marker_temporary(name: &OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    let Some(middle) = name
        .strip_prefix(TEMP_PREFIX)
        .and_then(|name| name.strip_suffix(TEMP_SUFFIX))
    else {
        return false;
    };
    middle.len() == 16
        && middle
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn remove_interrupted_temporaries(root: &Path) -> Result<(), IsolatedRootError> {
    for entry in fs::read_dir(root).map_err(|source| isolated_io(root, source))? {
        let entry = entry.map_err(|source| isolated_io(root, source))?;
        if is_marker_temporary(&entry.file_name()) {
            let path = entry.path();
            let metadata =
                fs::symlink_metadata(&path).map_err(|source| isolated_io(&path, source))?;
            if !metadata.is_file() || is_reparse(&metadata) {
                return Err(IsolatedRootError::UnsafeComponent(path));
            }
            fs::remove_file(&path).map_err(|source| isolated_io(&path, source))?;
        }
    }
    sync_directory(root)
}

fn create_marker(root: &Path) -> Result<IsolatedRootMarker, IsolatedRootError> {
    let root_identity = existing_identity(root)?;
    let root_id = rand::random::<[u8; 16]>();
    let path_digest = canonical_path_digest(root);
    let mut marker = IsolatedRootMarker {
        kind: MARKER_KIND.into(),
        schema_version: MARKER_SCHEMA,
        root_id: encode_hex(&root_id),
        root_identity,
        canonical_path_sha256: encode_hex(&path_digest),
        binding_sha256: String::new(),
    };
    marker.binding_sha256 = marker_binding(&marker);
    let bytes = serde_json::to_vec_pretty(&marker)
        .map_err(|error| IsolatedRootError::InvalidMarker(error.to_string()))?;

    let (temporary, mut file) = create_marker_temporary(root)?;
    let marker_path = root.join(MARKER_NAME);
    let result = (|| {
        file.write_all(&bytes)
            .map_err(|source| isolated_io(&temporary, source))?;
        file.write_all(b"\n")
            .map_err(|source| isolated_io(&temporary, source))?;
        file.sync_all()
            .map_err(|source| isolated_io(&temporary, source))?;
        drop(file);
        publish_marker(&temporary, &marker_path)?;
        sync_directory(root)?;
        read_and_validate_marker(root)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn read_and_validate_marker(root: &Path) -> Result<IsolatedRootMarker, IsolatedRootError> {
    let path = root.join(MARKER_NAME);
    let mut file = open_plain(&path, false)?;
    let metadata = file
        .metadata()
        .map_err(|source| isolated_io(&path, source))?;
    if !metadata.is_file() || is_reparse(&metadata) || metadata.len() > MAX_MARKER_BYTES {
        return Err(IsolatedRootError::InvalidMarker(
            "marker is not a bounded plain file".into(),
        ));
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_MARKER_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| isolated_io(&path, source))?;
    if bytes.len() as u64 > MAX_MARKER_BYTES {
        return Err(IsolatedRootError::InvalidMarker(
            "marker exceeds its size limit".into(),
        ));
    }
    let marker: IsolatedRootMarker = serde_json::from_slice(&bytes)
        .map_err(|error| IsolatedRootError::InvalidMarker(error.to_string()))?;
    if marker.kind != MARKER_KIND {
        return Err(IsolatedRootError::InvalidMarker(
            "marker kind does not match GatewayConnector".into(),
        ));
    }
    if marker.schema_version != MARKER_SCHEMA {
        return Err(IsolatedRootError::InvalidMarker(format!(
            "unsupported marker schema {}",
            marker.schema_version
        )));
    }
    if decode_hex::<16>(&marker.root_id).is_none()
        || decode_hex::<32>(&marker.canonical_path_sha256).is_none()
        || decode_hex::<32>(&marker.binding_sha256).is_none()
    {
        return Err(IsolatedRootError::InvalidMarker(
            "marker contains an invalid digest or identifier".into(),
        ));
    }
    if marker.root_identity != existing_identity(root)? {
        return Err(IsolatedRootError::InvalidMarker(
            "marker belongs to a different physical directory".into(),
        ));
    }
    if marker.canonical_path_sha256 != encode_hex(&canonical_path_digest(root)) {
        return Err(IsolatedRootError::InvalidMarker(
            "marker belongs to a different canonical path".into(),
        ));
    }
    if marker.binding_sha256 != marker_binding(&marker) {
        return Err(IsolatedRootError::InvalidMarker(
            "marker authentication digest does not match".into(),
        ));
    }
    Ok(marker)
}

fn marker_binding(marker: &IsolatedRootMarker) -> String {
    let mut hash = Sha256::new();
    hash.update(b"GatewayConnector isolated root marker v1\0");
    for value in [
        marker.kind.as_bytes(),
        marker.root_id.as_bytes(),
        marker.canonical_path_sha256.as_bytes(),
    ] {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value);
    }
    hash.update(marker.schema_version.to_be_bytes());
    hash.update(marker.root_identity.device.to_be_bytes());
    hash.update(marker.root_identity.file.to_be_bytes());
    encode_hex(&hash.finalize())
}

fn create_marker_temporary(root: &Path) -> Result<(PathBuf, File), IsolatedRootError> {
    for _ in 0..128 {
        let path = root.join(format!(
            "{TEMP_PREFIX}{:016x}{TEMP_SUFFIX}",
            rand::random::<u64>()
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        nofollow_options(&mut options);
        match options.open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(source) => return Err(isolated_io(&path, source)),
        }
    }
    Err(isolated_io(
        root,
        std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "could not allocate a unique isolated-root marker temporary",
        ),
    ))
}

fn open_plain(path: &Path, create: bool) -> Result<File, IsolatedRootError> {
    validate_existing_components(path)?;
    let mut options = OpenOptions::new();
    options.read(true).write(create).create(create);
    nofollow_options(&mut options);
    let file = options
        .open(path)
        .map_err(|source| isolated_io(path, source))?;
    let metadata = file
        .metadata()
        .map_err(|source| isolated_io(path, source))?;
    if !metadata.is_file() || is_reparse(&metadata) {
        return Err(IsolatedRootError::UnsafeComponent(path.to_owned()));
    }
    Ok(file)
}

fn nofollow_options(options: &mut OpenOptions) {
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
}

fn validate_existing_components(path: &Path) -> Result<(), IsolatedRootError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if matches!(component, Component::Prefix(_)) {
            continue;
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) if is_reparse(&metadata) => {
                return Err(IsolatedRootError::UnsafeComponent(current));
            }
            Ok(metadata) if current != path && !metadata.is_dir() => {
                return Err(IsolatedRootError::UnsafeComponent(current));
            }
            Ok(_) => {}
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => break,
            Err(source) => return Err(isolated_io(&current, source)),
        }
    }
    Ok(())
}

fn ensure_plain_descendant(root: &Path, path: &Path) -> Result<(), IsolatedRootError> {
    let relative = path
        .strip_prefix(root)
        .ok()
        .filter(|relative| !relative.as_os_str().is_empty())
        .ok_or_else(|| IsolatedRootError::InvalidPath(path.to_owned()))?;
    let mut current = root.to_owned();
    validate_plain_directory(&current)?;
    for component in relative.components() {
        if !matches!(component, Component::Normal(_)) {
            return Err(IsolatedRootError::InvalidPath(path.to_owned()));
        }
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.is_dir() && !is_reparse(&metadata) => {}
            Ok(_) => return Err(IsolatedRootError::UnsafeComponent(current)),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                let parent = current
                    .parent()
                    .ok_or_else(|| IsolatedRootError::InvalidPath(current.clone()))?;
                fs::create_dir(&current).map_err(|source| isolated_io(&current, source))?;
                set_private_directory(&current)?;
                sync_directory(parent)?;
                validate_plain_directory(&current)?;
            }
            Err(source) => return Err(isolated_io(&current, source)),
        }
    }
    Ok(())
}

fn validate_plain_descendant(root: &Path, path: &Path) -> Result<(), IsolatedRootError> {
    let relative = path
        .strip_prefix(root)
        .ok()
        .filter(|relative| !relative.as_os_str().is_empty())
        .ok_or_else(|| IsolatedRootError::InvalidPath(path.to_owned()))?;
    let mut current = root.to_owned();
    validate_plain_directory(&current)?;
    for component in relative.components() {
        if !matches!(component, Component::Normal(_)) {
            return Err(IsolatedRootError::InvalidPath(path.to_owned()));
        }
        current.push(component.as_os_str());
        validate_plain_directory(&current)?;
    }
    Ok(())
}

fn validate_plain_directory(path: &Path) -> Result<(), IsolatedRootError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| isolated_io(path, source))?;
    if !metadata.is_dir() || is_reparse(&metadata) {
        return Err(IsolatedRootError::UnsafeComponent(path.to_owned()));
    }
    Ok(())
}

fn validate_optional_plain_file(root: &Path, path: &Path) -> Result<(), IsolatedRootError> {
    if !path.starts_with(root) || path == root {
        return Err(IsolatedRootError::InvalidPath(path.to_owned()));
    }
    validate_existing_components(path)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !is_reparse(&metadata) => Ok(()),
        Ok(_) => Err(IsolatedRootError::UnsafeComponent(path.to_owned())),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(isolated_io(path, source)),
    }
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

#[cfg_attr(windows, allow(unsafe_code))]
fn existing_identity(path: &Path) -> Result<RootIdentity, IsolatedRootError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| isolated_io(path, source))?;
    if !metadata.is_dir() || is_reparse(&metadata) {
        return Err(IsolatedRootError::UnsafeComponent(path.to_owned()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(RootIdentity {
            device: metadata.dev(),
            file: metadata.ino(),
        })
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use std::{mem::zeroed, os::windows::io::AsRawHandle};
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
            GetFileInformationByHandle,
        };

        let handle = OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|source| isolated_io(path, source))?;
        let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
        if unsafe { GetFileInformationByHandle(handle.as_raw_handle() as _, &mut information) } == 0
        {
            return Err(isolated_io(path, std::io::Error::last_os_error()));
        }
        Ok(RootIdentity {
            device: u64::from(information.dwVolumeSerialNumber),
            file: (u64::from(information.nFileIndexHigh) << 32)
                | u64::from(information.nFileIndexLow),
        })
    }
}

fn canonical_path_digest(path: &Path) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"GatewayConnector canonical isolated root path v1\0");
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        hash.update(path.as_os_str().as_bytes());
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        for value in path.as_os_str().encode_wide() {
            hash.update(value.to_le_bytes());
        }
    }
    hash.finalize().into()
}

#[cfg(unix)]
fn set_private_directory(path: &Path) -> Result<(), IsolatedRootError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|source| isolated_io(path, source))
}

#[cfg(not(unix))]
fn set_private_directory(_path: &Path) -> Result<(), IsolatedRootError> {
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), IsolatedRootError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| isolated_io(path, source))
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), IsolatedRootError> {
    Ok(())
}

#[cfg(not(windows))]
fn publish_marker(from: &Path, to: &Path) -> Result<(), IsolatedRootError> {
    if fs::symlink_metadata(to).is_ok() {
        return Err(isolated_io(
            to,
            std::io::Error::new(std::io::ErrorKind::AlreadyExists, "marker already exists"),
        ));
    }
    fs::rename(from, to).map_err(|source| isolated_io(to, source))
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn publish_marker(from: &Path, to: &Path) -> Result<(), IsolatedRootError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_WRITE_THROUGH, MoveFileExW};

    let from_wide: Vec<u16> = from.as_os_str().encode_wide().chain(Some(0)).collect();
    let to_wide: Vec<u16> = to.as_os_str().encode_wide().chain(Some(0)).collect();
    if unsafe { MoveFileExW(from_wide.as_ptr(), to_wide.as_ptr(), MOVEFILE_WRITE_THROUGH) } == 0 {
        Err(isolated_io(to, std::io::Error::last_os_error()))
    } else {
        Ok(())
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

fn decode_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2 {
        return None;
    }
    let mut output = [0; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hex_digit(pair[0])? << 4) | hex_digit(pair[1])?;
    }
    Some(output)
}

fn hex_digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn isolated_io(path: &Path, source: std::io::Error) -> IsolatedRootError {
    IsolatedRootError::Io {
        path: path.to_owned(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::{Cursor, Write},
        sync::Arc,
        thread,
    };

    use gateway_connector_backend::{
        ApiKey, ConnectRequest, ConnectorBackend, CredentialStore, Distribution,
        GENERIC_DISTRIBUTION, InMemoryCredentialStore, JsonProfileStore, SystemBrowser,
    };
    use gateway_connector_core::{AgentId, Protocol};
    use sha2::{Digest, Sha256};
    use tiny_http::{Response, Server};
    use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

    use super::*;
    use crate::{AppState, ProjectionLifecycle, ProjectionSemantic, QueryStatus};

    fn test_path(parent: &tempfile::TempDir, name: &str) -> PathBuf {
        fs::canonicalize(parent.path())
            .expect("canonical temporary parent")
            .join(name)
    }

    #[test]
    fn command_is_exact_and_distribution_policy_is_deny_by_default() {
        assert!(matches!(
            LaunchRequest::from_args(&GENERIC_DISTRIBUTION, Vec::<OsString>::new())
                .expect("normal launch"),
            LaunchRequest::Normal
        ));
        let parent = tempfile::tempdir().expect("temporary parent");
        let root = test_path(&parent, "isolated");
        let request = LaunchRequest::from_args(
            &GENERIC_DISTRIBUTION,
            [
                OsString::from("--isolated-root"),
                root.clone().into_os_string(),
            ],
        )
        .expect("isolated launch");
        assert!(matches!(request, LaunchRequest::Isolated(_)));

        let disabled = Distribution {
            allow_isolated_root: false,
            ..GENERIC_DISTRIBUTION
        };
        let disabled_root = test_path(&parent, "disabled");
        assert!(matches!(
            LaunchRequest::from_args(
                &disabled,
                [
                    OsString::from("--isolated-root"),
                    disabled_root.clone().into_os_string()
                ]
            ),
            Err(IsolatedRootError::Disabled)
        ));
        assert!(!disabled_root.exists());
        assert!(matches!(
            LaunchRequest::from_args(&GENERIC_DISTRIBUTION, [OsString::from("--isolated-root")]),
            Err(IsolatedRootError::MissingIsolatedRoot)
        ));
        assert!(matches!(
            LaunchRequest::from_args(
                &GENERIC_DISTRIBUTION,
                [
                    OsString::from("--isolated-root"),
                    OsString::from("relative"),
                ]
            ),
            Err(IsolatedRootError::InvalidPath(_))
        ));
        assert!(matches!(
            LaunchRequest::from_args(&GENERIC_DISTRIBUTION, [OsString::from("--other")]),
            Err(IsolatedRootError::InvalidArguments)
        ));
    }

    #[test]
    fn layout_initializes_reopens_and_derives_every_path_below_one_root() {
        let parent = tempfile::tempdir().expect("temporary parent");
        let requested = test_path(&parent, "isolated");
        let first = IsolatedLayout::prepare(requested.clone()).expect("initialize layout");
        assert!(first.root().is_absolute());
        assert!(first.root().join(MARKER_NAME).is_file());

        for path in first.agent_roots.iter().chain([
            &first.profiles_file,
            &first.preferences_file,
            &first.state_dir,
            &first.coordinator_dir,
        ]) {
            assert!(path.starts_with(first.root()), "{}", path.display());
            assert_ne!(path, first.root());
        }
        assert_eq!(first.agent_roots().discover().len(), AgentId::ALL.len());
        assert!(
            first
                .agent_roots()
                .discover()
                .iter()
                .all(|agent| agent.detected)
        );

        let second = IsolatedLayout::prepare(requested).expect("reopen layout");
        assert_eq!(second.root_id, first.root_id);
        assert_eq!(second.profiles_file(), first.profiles_file());
    }

    #[test]
    fn two_roots_never_share_profile_or_coordinator_paths() {
        let parent = tempfile::tempdir().expect("temporary parent");
        let first = IsolatedLayout::prepare(test_path(&parent, "one")).expect("first");
        let second = IsolatedLayout::prepare(test_path(&parent, "two")).expect("second");
        assert_ne!(first.root_id, second.root_id);
        assert_ne!(first.coordinator_dir(), second.coordinator_dir());
        assert_ne!(first.profiles_file(), second.profiles_file());
    }

    #[test]
    fn unmarked_or_tampered_roots_fail_closed() {
        let parent = tempfile::tempdir().expect("temporary parent");
        let unmarked = test_path(&parent, "unmarked");
        fs::create_dir(&unmarked).expect("unmarked root");
        fs::write(unmarked.join("sentinel"), b"keep").expect("sentinel");
        assert!(matches!(
            IsolatedLayout::prepare(unmarked.clone()),
            Err(IsolatedRootError::UnmarkedNonEmpty(_))
        ));
        assert_eq!(
            fs::read(unmarked.join("sentinel")).expect("sentinel"),
            b"keep"
        );
        assert!(!unmarked.join(LOCK_NAME).exists());

        let first = IsolatedLayout::prepare(test_path(&parent, "first")).expect("first root");
        let copied = test_path(&parent, "copied");
        fs::create_dir(&copied).expect("copied root");
        fs::copy(first.root().join(MARKER_NAME), copied.join(MARKER_NAME)).expect("copy marker");
        assert!(matches!(
            IsolatedLayout::prepare(copied.clone()),
            Err(IsolatedRootError::InvalidMarker(_))
        ));
        assert!(!copied.join(LOCK_NAME).exists());

        let malformed = test_path(&parent, "malformed");
        fs::create_dir(&malformed).expect("malformed root");
        fs::write(malformed.join(MARKER_NAME), b"not JSON").expect("malformed marker");
        assert!(matches!(
            IsolatedLayout::prepare(malformed.clone()),
            Err(IsolatedRootError::InvalidMarker(_))
        ));
        assert!(!malformed.join(LOCK_NAME).exists());

        let marker_path = first.root().join(MARKER_NAME);
        let mut marker: serde_json::Value =
            serde_json::from_slice(&fs::read(&marker_path).expect("marker")).expect("JSON");
        marker["schema_version"] = 99.into();
        fs::write(
            &marker_path,
            serde_json::to_vec_pretty(&marker).expect("marker JSON"),
        )
        .expect("tamper marker");
        assert!(matches!(
            IsolatedLayout::prepare(first.root().to_owned()),
            Err(IsolatedRootError::InvalidMarker(_))
        ));
    }

    #[test]
    fn interrupted_marker_temporary_is_the_only_unmarked_recovery_artifact() {
        let parent = tempfile::tempdir().expect("temporary parent");
        let root = test_path(&parent, "interrupted");
        fs::create_dir(&root).expect("root");
        fs::write(root.join(LOCK_NAME), b"").expect("lock");
        let temporary = root.join(format!("{TEMP_PREFIX}0123456789abcdef{TEMP_SUFFIX}"));
        fs::write(&temporary, b"partial marker").expect("temporary");
        let layout = IsolatedLayout::prepare(root).expect("recover initialization");
        assert!(!temporary.exists());
        assert!(layout.root().join(MARKER_NAME).is_file());
    }

    #[cfg(unix)]
    #[test]
    fn symlink_roots_ancestors_and_markers_are_rejected() {
        use std::os::unix::fs::symlink;

        let parent = tempfile::tempdir().expect("temporary parent");
        let parent = fs::canonicalize(parent.path()).expect("canonical parent");
        let target = parent.join("target");
        fs::create_dir(&target).expect("target");
        let linked = parent.join("linked");
        symlink(&target, &linked).expect("root symlink");
        assert!(matches!(
            IsolatedLayout::prepare(linked.clone()),
            Err(IsolatedRootError::UnsafeComponent(_))
        ));
        assert!(matches!(
            IsolatedLayout::prepare(linked.join("child")),
            Err(IsolatedRootError::UnsafeComponent(_))
        ));

        let unmarked = parent.join("special-marker");
        fs::create_dir(&unmarked).expect("special marker root");
        let marker_target = parent.join("marker-target");
        fs::write(&marker_target, b"not a marker").expect("marker target");
        symlink(&marker_target, unmarked.join(MARKER_NAME)).expect("marker symlink");
        assert!(matches!(
            IsolatedLayout::prepare(unmarked.clone()),
            Err(IsolatedRootError::UnsafeComponent(_))
        ));
        assert!(!unmarked.join(LOCK_NAME).exists());

        let layout = IsolatedLayout::prepare(parent.join("marker-link")).expect("layout");
        let marker = layout.root().join(MARKER_NAME);
        let saved = layout.root().join("saved-marker");
        fs::rename(&marker, &saved).expect("save marker");
        symlink(&saved, &marker).expect("marker symlink");
        assert!(matches!(
            layout.revalidate(),
            Err(IsolatedRootError::UnsafeComponent(_))
        ));
    }

    #[cfg(windows)]
    #[test]
    fn windows_junction_roots_ancestors_and_fixture_swaps_are_rejected() {
        use std::process::Command;

        fn junction(link: &Path, target: &Path) {
            let status = Command::new("cmd")
                .arg("/C")
                .arg("mklink")
                .arg("/J")
                .arg(link)
                .arg(target)
                .status()
                .expect("create junction");
            assert!(status.success());
        }

        let parent = tempfile::tempdir().expect("temporary parent");
        let parent = fs::canonicalize(parent.path()).expect("canonical parent");
        let target = parent.join("target");
        fs::create_dir(&target).expect("target");
        let linked = parent.join("linked");
        junction(&linked, &target);
        assert!(matches!(
            IsolatedLayout::prepare(linked.clone()),
            Err(IsolatedRootError::UnsafeComponent(_))
        ));
        assert!(matches!(
            IsolatedLayout::prepare(linked.join("child")),
            Err(IsolatedRootError::UnsafeComponent(_))
        ));

        let layout = IsolatedLayout::prepare(parent.join("fixture-swap")).expect("layout");
        let claude = layout.agent_roots[0].clone();
        fs::remove_dir(&claude).expect("remove fixture root");
        junction(&claude, &target);
        assert!(matches!(
            layout.revalidate(),
            Err(IsolatedRootError::UnsafeComponent(_))
        ));
    }

    #[test]
    fn full_direct_lifecycle_stays_under_the_isolated_layout() {
        let parent = tempfile::tempdir().expect("temporary parent");
        let outside = test_path(&parent, "real-sentinels");
        fs::create_dir(&outside).expect("sentinel root");
        for name in [
            "normal-state",
            "shared-coordinator",
            "claude",
            "codex",
            "gemini",
            "grokbuild",
            "opencode",
        ] {
            let path = outside.join(name);
            fs::create_dir(&path).expect("sentinel directory");
            fs::write(path.join("sentinel"), name).expect("sentinel");
        }
        let before = snapshot_tree(&outside);
        let layout = IsolatedLayout::prepare(test_path(&parent, "isolated")).expect("layout");
        let credentials = Arc::new(InMemoryCredentialStore::default());
        let (base_url, server) = direct_server();

        let backend = isolated_backend(&layout, Arc::clone(&credentials));
        let mut connection = backend
            .connect(ConnectRequest {
                display_name: "Isolated Test".into(),
                base_url,
                api_key: ApiKey::new("isolated-secret").expect("credential"),
                protocol: Protocol::OpenaiChat,
            })
            .expect("connect");
        assert!(connection.synchronized_skills.is_empty());
        for selection in connection.profile.agents.values_mut() {
            selection.protocol = Protocol::OpenaiChat;
            selection.default_model = Some("chat-model".into());
        }
        backend
            .save_profile(&connection.profile)
            .expect("save selections");
        let installs = backend.discover_agents().expect("fixed discovery");
        assert_eq!(installs.len(), AgentId::ALL.len());
        assert!(
            installs
                .iter()
                .all(|install| install.detected && install.root.starts_with(layout.root()))
        );
        let mut app_state = AppState::connected(connection.clone());
        app_state.set_projection_status(
            QueryStatus::Known(installs),
            QueryStatus::Known(Default::default()),
        );
        let claude_root = layout.agent_roots().root(AgentId::Claude).to_path_buf();
        let claude_settings = claude_root.join("settings.json");
        let claude_account = claude_root.join(".claude.json");
        let original_settings = br#"{"theme":"fixture"}"#;
        let original_account = br#"{"hasCompletedOnboarding":false}"#;
        fs::write(&claude_settings, original_settings).expect("initial Claude settings");
        fs::write(&claude_account, original_account).expect("initial Claude account");

        let plan = backend.plan_projection(&connection).expect("preview");
        assert!(!plan.changes.is_empty());
        assert!(
            plan.changes
                .iter()
                .all(|change| change.path.starts_with(layout.root()))
        );
        app_state.set_preview(plan);
        assert_eq!(
            app_projection_semantic(&app_state),
            ProjectionSemantic::PreviewReady
        );
        assert!(
            !layout
                .agent_roots()
                .root(AgentId::Codex)
                .join("config.toml")
                .is_file()
        );

        fs::remove_file(&claude_account).expect("replace later destination");
        fs::create_dir(&claude_account).expect("blocking later destination");
        let rejected_plan = app_state.start_apply().expect("consume failed preview");
        assert_eq!(
            app_projection_semantic(&app_state),
            ProjectionSemantic::Applying
        );
        let apply_error = backend
            .apply_projection(&connection.profile, &rejected_plan)
            .expect_err("fixture must force an apply error")
            .to_string();
        assert!(
            !apply_error.contains("changed after this plan was created"),
            "fixture must reach transactional mutation and rollback: {apply_error}"
        );
        app_state.fail_apply();
        assert_eq!(
            app_projection_semantic(&app_state),
            ProjectionSemantic::ApplyFailed
        );
        assert!(
            app_state.start_apply().is_none(),
            "failed preview is consumed"
        );
        assert_eq!(
            fs::read(&claude_settings).expect("rolled-back Claude settings"),
            original_settings
        );
        fs::remove_dir(&claude_account).expect("remove blocking destination");
        fs::write(&claude_account, original_account).expect("restore Claude account");

        let plan = backend
            .plan_projection(&connection)
            .expect("fresh preview after rollback");
        app_state.set_preview(plan);
        let plan = app_state.start_apply().expect("consume preview for apply");
        let applied_plan = plan.clone();
        backend
            .apply_projection(&connection.profile, &plan)
            .expect("apply");
        app_state.finish_apply(plan);
        assert_eq!(
            app_projection_semantic(&app_state),
            ProjectionSemantic::AppliedAwaitingVerification
        );
        assert!(matches!(
            &app_state,
            AppState::Connected {
                projection: ProjectionLifecycle::AppliedAwaitingVerification(_),
                ..
            }
        ));
        assert!(app_state.start_apply().is_none(), "preview is consumed");
        assert!(
            layout
                .agent_roots()
                .root(AgentId::Codex)
                .join("config.toml")
                .is_file()
        );
        assert!(
            !backend
                .managed_agents(&connection.profile)
                .expect("ownership after apply")
                .is_empty()
        );
        assert_eq!(
            app_state.mcp_evidence(),
            crate::McpEvidence::ConfiguredForAgents
        );

        let plan = app_state.start_verify().expect("current applied plan");
        let verification = backend.verify_projection(&plan).expect("verify");
        assert!(verification.ok);
        app_state.finish_verify(verification);
        assert_eq!(
            app_projection_semantic(&app_state),
            ProjectionSemantic::Verified
        );
        assert!(
            app_state.start_verify().is_none(),
            "verification consumes the applied plan"
        );

        let mut drift_state = AppState::connected(connection.clone());
        drift_state.set_preview(applied_plan);
        let drift_plan = drift_state.start_apply().expect("applied plan fixture");
        drift_state.finish_apply(drift_plan);
        let codex_config = layout
            .agent_roots()
            .root(AgentId::Codex)
            .join("config.toml");
        let expected_config = fs::read(&codex_config).expect("managed config");
        fs::write(&codex_config, b"changed outside GatewayConnector\n").expect("introduce drift");
        let drift_plan = drift_state.start_verify().expect("verify applied state");
        let drift = backend
            .verify_projection(&drift_plan)
            .expect("drift report");
        assert!(!drift.ok);
        assert!(drift.mismatches.contains(&codex_config));
        drift_state.finish_verify(drift);
        assert_eq!(
            app_projection_semantic(&drift_state),
            ProjectionSemantic::VerificationFailed
        );
        assert!(drift_state.start_verify().is_none());
        fs::write(&codex_config, expected_config).expect("restore managed config after drift test");
        drop(backend);

        let resumed_backend = isolated_backend(&layout, Arc::clone(&credentials));
        let resumed = resumed_backend
            .resume_saved()
            .expect("resume")
            .expect("saved connection");
        assert_eq!(resumed.profile.id, connection.profile.id);
        let mut resumed_state = AppState::connected(resumed.clone());
        resumed_state.set_projection_status(
            QueryStatus::Known(resumed_backend.discover_agents().expect("resumed installs")),
            QueryStatus::Known(
                resumed_backend
                    .managed_agents(&resumed.profile)
                    .expect("resumed ownership"),
            ),
        );
        assert_eq!(
            app_projection_semantic(&resumed_state),
            ProjectionSemantic::ManagedExisting
        );
        assert_ne!(
            app_projection_semantic(&resumed_state),
            ProjectionSemantic::PreviewReady
        );
        resumed_state.start_disconnect();
        assert_eq!(
            app_projection_semantic(&resumed_state),
            ProjectionSemantic::Disconnecting
        );
        resumed_backend
            .disconnect(&resumed.profile)
            .expect("disconnect");
        resumed_state = AppState::FirstRun;
        assert!(matches!(resumed_state, AppState::FirstRun));
        assert!(
            !layout
                .agent_roots()
                .root(AgentId::Codex)
                .join("config.toml")
                .exists()
        );
        assert!(
            credentials
                .get(&resumed.profile)
                .expect("vault read")
                .is_none()
        );
        server.join().expect("mock server");

        layout.revalidate().expect("layout after lifecycle");
        assert_eq!(snapshot_tree(&outside), before);
        assert!(
            layout
                .state_dir
                .join("connector")
                .starts_with(layout.root())
        );
        assert!(
            layout
                .coordinator_dir
                .join("transactions")
                .starts_with(layout.root())
        );
    }

    fn app_projection_semantic(state: &AppState) -> ProjectionSemantic {
        let AppState::Connected { projection, .. } = state else {
            panic!("expected connected app state")
        };
        projection.semantic()
    }

    #[test]
    fn provisioned_catalog_resume_and_recovery_stay_under_the_isolated_layout() {
        let parent = tempfile::tempdir().expect("temporary parent");
        let outside = test_path(&parent, "real-sentinels");
        fs::create_dir(&outside).expect("sentinel root");
        fs::write(outside.join("sentinel"), b"untouched").expect("sentinel");
        let before = snapshot_tree(&outside);
        let layout = IsolatedLayout::prepare(test_path(&parent, "isolated")).expect("layout");
        let credentials = Arc::new(InMemoryCredentialStore::default());
        let (base_url, distribution, server) = enhanced_server();

        let backend =
            isolated_backend_with_distribution(&layout, Arc::clone(&credentials), distribution);
        let connected = backend
            .connect(ConnectRequest {
                display_name: "Isolated Provisioned Test".into(),
                base_url,
                api_key: ApiKey::new("isolated-secret").expect("credential"),
                protocol: Protocol::OpenaiChat,
            })
            .expect("connect");
        assert_eq!(connected.synchronized_skills.len(), 1);
        assert!(
            connected
                .synchronized_skills
                .values()
                .all(|path| path.starts_with(layout.root()))
        );
        assert_eq!(
            connected
                .provisioning
                .as_ref()
                .expect("provisioning")
                .mcp_servers
                .len(),
            1
        );
        let mut app_state = AppState::connected(connected.clone());
        assert_eq!(
            app_state.mcp_evidence(),
            crate::McpEvidence::AvailableFromPlatform
        );
        let plan = backend
            .plan_projection(&connected)
            .expect("provisioned preview");
        app_state.set_preview(plan);
        let plan = app_state.start_apply().expect("provisioned apply state");
        backend
            .apply_projection(&connected.profile, &plan)
            .expect("provisioned apply");
        app_state.finish_apply(plan);
        assert_eq!(
            app_state.mcp_evidence(),
            crate::McpEvidence::ConfiguredForAgents
        );
        drop(backend);

        let resumed_backend =
            isolated_backend_with_distribution(&layout, Arc::clone(&credentials), distribution);
        let resumed = resumed_backend
            .resume_saved()
            .expect("resume")
            .expect("saved connection");
        assert_eq!(resumed.synchronized_skills.len(), 1);
        assert!(
            resumed
                .synchronized_skills
                .values()
                .all(|path| path.starts_with(layout.root()))
        );
        resumed_backend
            .disconnect(&resumed.profile)
            .expect("disconnect");
        server.join().expect("mock server");

        layout.revalidate().expect("layout after lifecycle");
        assert_eq!(snapshot_tree(&outside), before);
        assert!(layout.state_dir.join("catalog").starts_with(layout.root()));
        assert!(
            layout
                .state_dir
                .join("connector/transactions")
                .starts_with(layout.root())
        );
    }

    fn isolated_backend(
        layout: &IsolatedLayout,
        credentials: Arc<InMemoryCredentialStore>,
    ) -> ConnectorBackend {
        isolated_backend_with_distribution(layout, credentials, &GENERIC_DISTRIBUTION)
    }

    fn isolated_backend_with_distribution(
        layout: &IsolatedLayout,
        credentials: Arc<InMemoryCredentialStore>,
        distribution: &'static Distribution,
    ) -> ConnectorBackend {
        let credentials: Arc<dyn CredentialStore> = credentials;
        ConnectorBackend::with_dependencies(
            credentials,
            Arc::new(JsonProfileStore::new(layout.profiles_file())),
            distribution,
            Arc::new(SystemBrowser),
        )
        .and_then(|backend| {
            backend.with_isolated_runtime_directories(
                layout.state_dir(),
                layout.coordinator_dir(),
                layout.agent_roots(),
            )
        })
        .expect("isolated backend")
    }

    fn direct_server() -> (String, thread::JoinHandle<()>) {
        let server = Server::http("127.0.0.1:0").expect("mock server");
        let base_url = format!("http://{}", server.server_addr());
        let handle = thread::spawn(move || {
            // connect + resume each hit /v1/models once.
            for _ in 0..2 {
                let request = server.recv().expect("request");
                assert_eq!(request.url(), "/v1/models");
                assert!(request.headers().iter().any(|header| {
                    header.field.equiv("authorization")
                        && header.value.as_str() == "Bearer isolated-secret"
                }));
                request
                    .respond(Response::from_string(
                        r#"{"data":[{"id":"chat-model","chat_capable":true}]}"#,
                    ))
                    .expect("models response");
            }
        });
        (base_url, handle)
    }

    fn enhanced_server() -> (String, &'static Distribution, thread::JoinHandle<()>) {
        let archive = skill_zip(b"# Isolated Skill\n");
        let server = Server::http("127.0.0.1:0").expect("mock server");
        let base_url = format!("http://{}", server.server_addr());
        let manifest_url =
            Box::leak(format!("{base_url}/connector-manifest.json").into_boxed_str());
        let distribution = Box::leak(Box::new(Distribution {
            expected_platform_id: Some("isolated-test"),
            manifest_url: Some(manifest_url),
            allow_isolated_root: true,
            ..GENERIC_DISTRIBUTION
        }));
        let manifest = serde_json::json!({
            "success": true,
            "data": {
                "schema_version": 2,
                "platform": {"id": "isolated-test", "name": "Isolated Test"},
                "gateway": {"base_url": base_url, "protocols": ["openai_chat"]},
                "provisioning_url": format!("{base_url}/provisioning"),
                "connection_bearer_origins": [base_url, "https://services.example"],
                "supported_agents": ["claude", "codex", "gemini", "grokbuild", "opencode"]
            }
        })
        .to_string();
        let provisioning = serde_json::json!({
            "success": true,
            "data": {
                "schema_version": 2,
                "models": [{"id": "catalog-model", "chat_capable": true}],
                "default_model": "catalog-model",
                "mcp_servers": [{
                    "id": "fixture-docs",
                    "name": "Fixture Docs MCP",
                    "url": "https://services.example/mcp/docs",
                    "authorization": "connection_bearer"
                }],
                "skills": [{
                    "id": "isolated-skill",
                    "name": "Isolated Skill",
                    "version": "1.0.0",
                    "archive": {
                        "url": format!("{base_url}/skill.zip"),
                        "sha256": format!("{:x}", Sha256::digest(&archive)),
                        "size_bytes": archive.len(),
                        "format": "zip",
                        "authorization": "connection_bearer"
                    }
                }]
            }
        })
        .to_string();
        let handle = thread::spawn(move || {
            for _ in 0..6 {
                let request = server.recv().expect("request");
                let response = match request.url() {
                    "/connector-manifest.json" => Response::from_string(manifest.clone()),
                    "/provisioning" => Response::from_string(provisioning.clone()),
                    "/skill.zip" => Response::from_data(archive.clone()),
                    path => panic!("unexpected enhanced-mode path: {path}"),
                };
                request.respond(response).expect("response");
            }
        });
        (base_url, distribution, handle)
    }

    fn skill_zip(contents: &[u8]) -> Vec<u8> {
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        writer
            .start_file(
                "SKILL.md",
                SimpleFileOptions::default().compression_method(CompressionMethod::Deflated),
            )
            .expect("Skill entry");
        writer.write_all(contents).expect("Skill body");
        writer.finish().expect("finish ZIP").into_inner()
    }

    fn snapshot_tree(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
        fn visit(root: &Path, current: &Path, output: &mut Vec<(PathBuf, Vec<u8>)>) {
            let mut entries = fs::read_dir(current)
                .expect("read tree")
                .map(|entry| entry.expect("tree entry"))
                .collect::<Vec<_>>();
            entries.sort_by_key(fs::DirEntry::file_name);
            for entry in entries {
                let path = entry.path();
                if entry.file_type().expect("file type").is_dir() {
                    visit(root, &path, output);
                } else {
                    output.push((
                        path.strip_prefix(root).expect("relative").to_owned(),
                        fs::read(path).expect("file"),
                    ));
                }
            }
        }

        let mut output = Vec::new();
        visit(root, root, &mut output);
        output
    }
}
