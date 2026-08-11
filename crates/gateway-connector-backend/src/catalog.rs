use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::{Component, Path, PathBuf},
    time::Duration,
};

use fs2::FileExt;
use gateway_connector_core::{ConnectionManifest, Provisioning, Skill, SkillArchiveAuthorization};
use reqwest::{StatusCode, header};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::ApiKey;

const MAX_REDIRECTS: usize = 5;
const MAX_ENTRIES: usize = 4096;
const MAX_EXPANDED: u64 = 256 * 1024 * 1024;
const OWNER_MARKER: &str = ".gateway-connector-owner";

#[derive(Debug, Error)]
pub(crate) enum CatalogError {
    #[error("Skill catalog network request failed: {0}")]
    Network(#[from] reqwest::Error),
    #[error("Skill archive response is invalid: {0}")]
    Invalid(String),
    #[error("Skill catalog state error at {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
}

fn io(path: &Path) -> impl FnOnce(std::io::Error) -> CatalogError + '_ {
    move |source| CatalogError::Io {
        path: path.into(),
        source,
    }
}

#[derive(Debug)]
pub(crate) struct SkillCatalog {
    state_dir: PathBuf,
    client: reqwest::blocking::Client,
    direct_client: reqwest::blocking::Client,
}

impl SkillCatalog {
    pub(crate) fn new(state_dir: PathBuf) -> Result<Self, CatalogError> {
        let builder = || {
            reqwest::blocking::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(30))
                .user_agent(concat!("GatewayConnector/", env!("CARGO_PKG_VERSION")))
        };
        Ok(Self {
            state_dir,
            client: builder().build()?,
            direct_client: builder().no_proxy().build()?,
        })
    }

    pub(crate) fn synchronize(
        &self,
        manifest: &ConnectionManifest,
        provisioning: &Provisioning,
        token: &ApiKey,
    ) -> Result<BTreeMap<String, PathBuf>, CatalogError> {
        self.synchronize_with_limits(manifest, provisioning, token, MAX_ENTRIES, MAX_EXPANDED)
    }

    fn synchronize_with_limits(
        &self,
        manifest: &ConnectionManifest,
        provisioning: &Provisioning,
        token: &ApiKey,
        max_entries: usize,
        max_expanded: u64,
    ) -> Result<BTreeMap<String, PathBuf>, CatalogError> {
        let parent = self.state_dir.join("synchronized-skills");
        ensure_plain_directory_tree(&parent)?;
        reject_non_directory(&parent)?;
        let lock_path = parent.join(".catalog.lock");
        let lock = open_plain_lock(&lock_path)?;
        lock.lock_exclusive().map_err(io(&lock_path))?;
        validate_plain_directory_tree(&parent)?;
        let root = parent.join(&manifest.platform.id);
        reconcile(&root)?;
        reject_existing_special(&root)?;
        let nonce = transaction_nonce(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
            std::process::id(),
        );
        let staged = transaction_path(&root, "staged", &nonce)?;
        let previous = transaction_path(&root, "previous", &nonce)?;
        reject_existing_special(&staged)?;
        let result = (|| {
            // Authentication, digest checks, and all central-directory budget checks complete
            // before the transaction creates or extracts into its staging directory.
            let archives = provisioning
                .skills
                .iter()
                .map(|skill| self.download(manifest, skill, token))
                .collect::<Result<Vec<_>, _>>()?;
            preflight_catalog(&archives, max_entries, max_expanded)?;
            validate_plain_directory_tree(&parent)?;
            reject_existing_special(&root)?;
            reject_existing_special(&staged)?;
            reject_existing_special(&previous)?;
            fs::create_dir(&staged).map_err(io(&staged))?;
            reject_non_directory(&staged)?;
            let mut actual_budget = ExtractionBudget {
                entries: max_entries,
                expanded: max_expanded,
            };
            for (skill, bytes) in provisioning.skills.iter().zip(&archives) {
                extract_zip_shared(bytes, &staged.join(&skill.id), &mut actual_budget)?;
            }
            validate_plain_directory_tree(&parent)?;
            reject_non_directory(&staged)?;
            reject_existing_special(&root)?;
            reject_existing_special(&previous)?;
            if root.exists() {
                fs::rename(&root, &previous).map_err(io(&root))?;
            }
            fs::rename(&staged, &root).map_err(io(&root))?;
            Ok(())
        })();
        if let Err(error) = result {
            let _ = remove_tree(&staged);
            if previous.exists() && !root.exists() {
                fs::rename(&previous, &root).map_err(io(&root))?;
            }
            return Err(error);
        }
        if previous.exists() {
            let _ = remove_tree(&previous);
        }
        Ok(provisioning
            .skills
            .iter()
            .map(|s| (s.id.clone(), root.join(&s.id)))
            .collect())
    }

    fn download(
        &self,
        manifest: &ConnectionManifest,
        skill: &Skill,
        token: &ApiKey,
    ) -> Result<Vec<u8>, CatalogError> {
        let origin = skill.archive.url.origin();
        let bearer = skill.archive.authorization == SkillArchiveAuthorization::ConnectionBearer;
        if bearer
            && !manifest
                .connection_bearer_origins
                .iter()
                .any(|u| u.origin() == origin)
        {
            return Err(CatalogError::Invalid(
                "authenticated archive origin is not allowed".into(),
            ));
        }
        let mut url = skill.archive.url.clone();
        for redirects in 0..=MAX_REDIRECTS {
            if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
                return Err(CatalogError::Invalid(
                    "archive URL or redirect contains credentials or a fragment".into(),
                ));
            }
            let client = if url.scheme() == "http" {
                &self.direct_client
            } else {
                &self.client
            };
            let mut request = client.get(url.clone());
            if bearer {
                request = request.bearer_auth(token.expose_secret());
            }
            let mut response = request.send()?;
            if response.status().is_redirection() {
                if redirects == MAX_REDIRECTS {
                    return Err(CatalogError::Invalid("too many redirects".into()));
                }
                let location = response
                    .headers()
                    .get(header::LOCATION)
                    .ok_or_else(|| CatalogError::Invalid("redirect has no Location".into()))?
                    .to_str()
                    .map_err(|_| CatalogError::Invalid("invalid redirect".into()))?;
                let next = url
                    .join(location)
                    .map_err(|_| CatalogError::Invalid("invalid redirect".into()))?;
                if next.origin() != origin
                    || !next.username().is_empty()
                    || next.password().is_some()
                    || next.fragment().is_some()
                {
                    return Err(CatalogError::Invalid("unsafe archive redirect".into()));
                }
                url = next;
                continue;
            }
            if response.status() != StatusCode::OK {
                return Err(CatalogError::Invalid(format!("HTTP {}", response.status())));
            }
            if response
                .content_length()
                .is_some_and(|n| n != skill.archive.size_bytes)
            {
                return Err(CatalogError::Invalid(
                    "archive size mismatch (Content-Length)".into(),
                ));
            }
            let mut bytes = Vec::new();
            response
                .by_ref()
                .take(skill.archive.size_bytes + 1)
                .read_to_end(&mut bytes)
                .map_err(io(Path::new("archive response")))?;
            if bytes.len() as u64 != skill.archive.size_bytes {
                return Err(CatalogError::Invalid("archive size mismatch".into()));
            }
            if format!("{:x}", Sha256::digest(&bytes)) != skill.archive.sha256 {
                return Err(CatalogError::Invalid("archive digest mismatch".into()));
            }
            return Ok(bytes);
        }
        unreachable!()
    }
}

fn preflight_catalog(
    archives: &[Vec<u8>],
    max_entries: usize,
    max_expanded: u64,
) -> Result<(), CatalogError> {
    let mut entries = 0usize;
    let mut expanded = 0u64;
    for bytes in archives {
        let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bytes))
            .map_err(|_| CatalogError::Invalid("invalid ZIP".into()))?;
        let declared = declared_entries(bytes)?;
        if declared != zip.len() {
            return Err(CatalogError::Invalid("inconsistent ZIP directory".into()));
        }
        entries = entries
            .checked_add(declared)
            .ok_or_else(|| CatalogError::Invalid("ZIP entry count overflow".into()))?;
        if entries > max_entries {
            return Err(CatalogError::Invalid("too many catalog ZIP entries".into()));
        }
        for index in 0..zip.len() {
            let entry = zip
                .by_index(index)
                .map_err(|_| CatalogError::Invalid("invalid ZIP".into()))?;
            expanded = expanded
                .checked_add(entry.size())
                .ok_or_else(|| CatalogError::Invalid("expanded size overflow".into()))?;
            if expanded > max_expanded {
                return Err(CatalogError::Invalid("catalog expands beyond limit".into()));
            }
        }
    }
    Ok(())
}

fn reject_non_directory(path: &Path) -> Result<(), CatalogError> {
    let m = fs::symlink_metadata(path).map_err(io(path))?;
    if !m.is_dir() || is_reparse(&m) {
        return Err(CatalogError::Invalid(
            "catalog state root is not a directory".into(),
        ));
    }
    Ok(())
}
fn reject_existing_special(path: &Path) -> Result<(), CatalogError> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.is_dir() && !is_reparse(&m) => Ok(()),
        Ok(_) => Err(CatalogError::Invalid(
            "catalog path is a reparse point, symlink, or special file".into(),
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(io(path)(e)),
    }
}
fn remove_tree(path: &Path) -> std::io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.is_dir() && !is_reparse(&m) => fs::remove_dir_all(path),
        Ok(_) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "refusing to remove a catalog reparse point, symlink, or special file",
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

fn ensure_plain_directory_tree(path: &Path) -> Result<(), CatalogError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        if matches!(component, Component::ParentDir) {
            return Err(CatalogError::Invalid(
                "catalog state path contains a parent traversal".into(),
            ));
        }
        current.push(component.as_os_str());
        if matches!(component, Component::Prefix(_) | Component::CurDir) {
            continue;
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.is_dir() && !is_reparse(&metadata) => {}
            Ok(_) => {
                return Err(CatalogError::Invalid(
                    "catalog state path contains a reparse point, symlink, or special file".into(),
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&current).map_err(io(&current))?;
                reject_non_directory(&current)?;
            }
            Err(error) => return Err(io(&current)(error)),
        }
    }
    validate_plain_directory_tree(path)
}

fn validate_plain_directory_tree(path: &Path) -> Result<(), CatalogError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        if matches!(component, Component::ParentDir) {
            return Err(CatalogError::Invalid(
                "catalog state path contains a parent traversal".into(),
            ));
        }
        current.push(component.as_os_str());
        if matches!(component, Component::Prefix(_) | Component::CurDir) {
            continue;
        }
        reject_non_directory(&current)?;
    }
    Ok(())
}

fn open_plain_lock(path: &Path) -> Result<fs::File, CatalogError> {
    let parent = path
        .parent()
        .ok_or_else(|| CatalogError::Invalid("catalog lock has no parent".into()))?;
    validate_plain_directory_tree(parent)?;
    let mut options = fs::OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
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
    let file = options.open(path).map_err(io(path))?;
    let metadata = file.metadata().map_err(io(path))?;
    if !metadata.is_file() || is_reparse(&metadata) {
        return Err(CatalogError::Invalid(
            "catalog lock is a reparse point, symlink, or special file".into(),
        ));
    }
    validate_plain_directory_tree(parent)?;
    Ok(file)
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

fn transaction_nonce(timestamp_nanos: u128, process_id: u32) -> String {
    format!("{timestamp_nanos:039}-{process_id:010}")
}

fn transaction_prefix(root: &Path, kind: &str) -> Result<String, CatalogError> {
    let name = root
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| CatalogError::Invalid("invalid catalog path".into()))?;
    Ok(format!("{name}~{kind}-"))
}

fn transaction_path(root: &Path, kind: &str, nonce: &str) -> Result<PathBuf, CatalogError> {
    let parent = root
        .parent()
        .ok_or_else(|| CatalogError::Invalid("invalid catalog path".into()))?;
    Ok(parent.join(format!("{}{nonce}", transaction_prefix(root, kind)?)))
}

fn reconcile(root: &Path) -> Result<(), CatalogError> {
    let parent = root
        .parent()
        .ok_or_else(|| CatalogError::Invalid("invalid catalog path".into()))?;
    validate_plain_directory_tree(parent)?;
    let root_exists = match fs::symlink_metadata(root) {
        Ok(metadata) if metadata.is_dir() && !is_reparse(&metadata) => true,
        Ok(_) => {
            return Err(CatalogError::Invalid(
                "catalog path is a reparse point, symlink, or special file".into(),
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(io(root)(error)),
    };
    let staged_prefix = transaction_prefix(root, "staged")?;
    let previous_prefix = transaction_prefix(root, "previous")?;
    let mut previous = vec![];
    for entry in fs::read_dir(parent).map_err(io(parent))? {
        let entry = entry.map_err(io(parent))?;
        let n = entry.file_name();
        let n = n.to_string_lossy();
        if n.starts_with(&staged_prefix) {
            reject_existing_special(&entry.path())?;
            remove_tree(&entry.path()).map_err(io(&entry.path()))?;
        } else if n.starts_with(&previous_prefix) {
            reject_existing_special(&entry.path())?;
            previous.push(entry.path());
        }
    }
    previous.sort();
    if root_exists {
        for p in previous {
            remove_tree(&p).map_err(io(&p))?;
        }
    } else if let Some(p) = previous.pop() {
        fs::rename(&p, root).map_err(io(root))?;
        for p in previous {
            remove_tree(&p).map_err(io(&p))?;
        }
    }
    Ok(())
}

#[derive(Debug)]
struct Planned {
    index: usize,
    path: PathBuf,
    key: String,
    dir: bool,
    size: u64,
    #[cfg(unix)]
    mode: u32,
}
fn reserved(c: &str) -> bool {
    let s = c.split('.').next().unwrap_or_default().to_ascii_uppercase();
    matches!(s.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || s.strip_prefix("COM")
            .or_else(|| s.strip_prefix("LPT"))
            .is_some_and(|x| matches!(x, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9"))
}
fn safe_path(raw: &str, dir: bool) -> Result<(PathBuf, String), CatalogError> {
    if raw.is_empty()
        || raw.starts_with('/')
        || raw.starts_with('\\')
        || raw.contains('\\')
        || raw.contains('\0')
    {
        return Err(CatalogError::Invalid("unsafe archive path".into()));
    }
    let mut parts = raw.split('/').collect::<Vec<_>>();
    if dir && parts.last() == Some(&"") {
        parts.pop();
    }
    if parts.is_empty()
        || parts.iter().any(|c| {
            c.is_empty()
                || *c == "."
                || *c == ".."
                || !c.is_ascii()
                || c.ends_with(' ')
                || c.ends_with('.')
                || c.chars()
                    .any(|x| x.is_control() || matches!(x, '<' | '>' | ':' | '"' | '|' | '?' | '*'))
                || reserved(c)
                || c.eq_ignore_ascii_case(OWNER_MARKER)
        })
    {
        return Err(CatalogError::Invalid("non-portable archive path".into()));
    }
    Ok((parts.iter().collect(), parts.join("/").to_ascii_lowercase()))
}
fn declared_entries(bytes: &[u8]) -> Result<usize, CatalogError> {
    const EOCD: usize = 22;
    if bytes.len() < EOCD {
        return Err(CatalogError::Invalid("invalid ZIP directory".into()));
    }
    let start = bytes.len().saturating_sub(EOCD + u16::MAX as usize);
    for offset in (start..=bytes.len() - EOCD).rev() {
        if bytes[offset..].starts_with(b"PK\x05\x06") {
            let u16_at = |at| u16::from_le_bytes([bytes[offset + at], bytes[offset + at + 1]]);
            let u32_at = |at| {
                u32::from_le_bytes([
                    bytes[offset + at],
                    bytes[offset + at + 1],
                    bytes[offset + at + 2],
                    bytes[offset + at + 3],
                ])
            };
            if offset + EOCD + u16_at(20) as usize != bytes.len() {
                continue;
            }
            let count = u16_at(10);
            if u16_at(4) != 0
                || u16_at(6) != 0
                || u16_at(8) != count
                || count == u16::MAX
                || u32_at(12) == u32::MAX
                || u32_at(16) == u32::MAX
            {
                return Err(CatalogError::Invalid("ZIP64 or multidisk archive".into()));
            }
            return Ok(count as usize);
        }
    }
    Err(CatalogError::Invalid("invalid ZIP directory".into()))
}
#[cfg(test)]
fn extract_zip(bytes: &[u8], target: &Path) -> Result<(), CatalogError> {
    extract_zip_with_limits(bytes, target, MAX_ENTRIES, MAX_EXPANDED)
}

#[derive(Debug)]
struct ExtractionBudget {
    entries: usize,
    expanded: u64,
}

fn extract_zip_shared(
    bytes: &[u8],
    target: &Path,
    budget: &mut ExtractionBudget,
) -> Result<(), CatalogError> {
    extract_zip_with_budget(bytes, target, budget)
}

#[cfg(test)]
fn extract_zip_with_limits(
    bytes: &[u8],
    target: &Path,
    max_entries: usize,
    max_expanded: u64,
) -> Result<(), CatalogError> {
    extract_zip_with_budget(
        bytes,
        target,
        &mut ExtractionBudget {
            entries: max_entries,
            expanded: max_expanded,
        },
    )
}

fn extract_zip_with_budget(
    bytes: &[u8],
    target: &Path,
    budget: &mut ExtractionBudget,
) -> Result<(), CatalogError> {
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bytes))
        .map_err(|_| CatalogError::Invalid("invalid ZIP".into()))?;
    if declared_entries(bytes)? != zip.len() {
        return Err(CatalogError::Invalid("inconsistent ZIP directory".into()));
    }
    if zip.len() > budget.entries {
        return Err(CatalogError::Invalid("too many catalog ZIP entries".into()));
    }
    if zip
        .has_overlapping_files()
        .map_err(|_| CatalogError::Invalid("invalid ZIP".into()))?
    {
        return Err(CatalogError::Invalid("overlapping ZIP entries".into()));
    }
    let mut seen = BTreeSet::new();
    let mut exact = BTreeSet::new();
    let mut total = 0u64;
    let mut plan = vec![];
    for index in 0..zip.len() {
        let e = zip
            .by_index(index)
            .map_err(|_| CatalogError::Invalid("invalid ZIP".into()))?;
        if !exact.insert(e.name().to_owned()) {
            return Err(CatalogError::Invalid("exact duplicate ZIP path".into()));
        }
        let dir = e.is_dir();
        let (path, key) = safe_path(e.name(), dir)?;
        if !seen.insert(key.clone()) {
            return Err(CatalogError::Invalid("duplicate ZIP path".into()));
        }
        let mode = e
            .unix_mode()
            .unwrap_or(if dir { 0o040755 } else { 0o100644 });
        let kind = mode & 0o170000;
        if (kind != 0 && kind != 0o100000 && kind != 0o040000)
            || (dir && kind == 0o100000)
            || (!dir && kind == 0o040000)
        {
            return Err(CatalogError::Invalid("symlink or special ZIP entry".into()));
        }
        total = total
            .checked_add(e.size())
            .ok_or_else(|| CatalogError::Invalid("expanded size overflow".into()))?;
        if total > budget.expanded {
            return Err(CatalogError::Invalid("ZIP expands beyond limit".into()));
        }
        plan.push(Planned {
            index,
            path,
            key,
            dir,
            size: e.size(),
            #[cfg(unix)]
            mode,
        });
    }
    for e in &plan {
        if !e.dir
            && plan
                .iter()
                .any(|o| o.key.starts_with(&format!("{}/", e.key)))
        {
            return Err(CatalogError::Invalid(
                "file-directory prefix collision".into(),
            ));
        }
    }
    if !plan.iter().any(|e| !e.dir && e.key == "skill.md") {
        return Err(CatalogError::Invalid("missing root SKILL.md".into()));
    }
    for p in plan {
        budget.entries = budget
            .entries
            .checked_sub(1)
            .ok_or_else(|| CatalogError::Invalid("catalog ZIP entry budget exhausted".into()))?;
        let mut e = zip
            .by_index(p.index)
            .map_err(|_| CatalogError::Invalid("invalid ZIP".into()))?;
        let out = target.join(p.path);
        if p.dir {
            fs::create_dir_all(&out).map_err(io(&out))?;
            continue;
        }
        if let Some(parent) = out.parent() {
            fs::create_dir_all(parent).map_err(io(parent))?;
        }
        let mut f = fs::File::create(&out).map_err(io(&out))?;
        let n =
            std::io::copy(&mut e.by_ref().take(budget.expanded + 1), &mut f).map_err(io(&out))?;
        if n != p.size || n > budget.expanded {
            return Err(CatalogError::Invalid("expanded size mismatch".into()));
        }
        budget.expanded -= n;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&out, fs::Permissions::from_mode(p.mode & 0o777))
                .map_err(io(&out))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Cursor, Write},
        sync::{Arc, Mutex},
        thread,
        time::Duration,
    };
    use tiny_http::{Header, Response, Server, StatusCode};
    use url::Url;
    use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

    fn skill_zip(entries: &[(&str, &[u8], u32)]) -> Vec<u8> {
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        for (path, bytes, mode) in entries {
            writer
                .start_file(
                    path,
                    SimpleFileOptions::default()
                        .compression_method(CompressionMethod::Deflated)
                        .unix_permissions(*mode),
                )
                .expect("start ZIP entry");
            writer.write_all(bytes).expect("write ZIP entry");
        }
        writer.finish().expect("finish ZIP").into_inner()
    }

    fn symlink_zip() -> Vec<u8> {
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        writer
            .start_file("SKILL.md", SimpleFileOptions::default())
            .expect("Skill entry");
        writer.write_all(b"skill").expect("Skill body");
        writer
            .add_symlink("escape", "../outside", SimpleFileOptions::default())
            .expect("symlink entry");
        writer.finish().expect("finish ZIP").into_inner()
    }

    fn exact_duplicate_zip() -> Vec<u8> {
        let mut bytes = skill_zip(&[("SKILL.md", b"one", 0o644), ("SKILL.MD", b"two", 0o644)]);
        for offset in 0..=bytes.len() - b"SKILL.MD".len() {
            if &bytes[offset..offset + b"SKILL.MD".len()] == b"SKILL.MD" {
                bytes[offset..offset + b"SKILL.MD".len()].copy_from_slice(b"SKILL.md");
            }
        }
        bytes
    }

    fn digest(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    #[test]
    fn catalog_preflight_shares_expanded_and_entry_budgets() {
        let compressible = vec![b'x'; 64];
        let first = skill_zip(&[("SKILL.md", &compressible, 0o644)]);
        let second = skill_zip(&[("SKILL.md", &compressible, 0o644)]);
        let expanded_error = preflight_catalog(&[first.clone(), second.clone()], 10, 100)
            .expect_err("aggregate expanded budget");
        assert!(expanded_error.to_string().contains("expands beyond"));

        let entry_error =
            preflight_catalog(&[first, second], 1, 1_000).expect_err("aggregate entry budget");
        assert!(entry_error.to_string().contains("entries"));

        // A per-archive reset would accept roughly 64 GiB across 256 Skills.
        // The shared production budget rejects the same highly-compressible
        // shape as soon as its aggregate declared expansion exceeds 256 MiB.
        let large_compressible = vec![b'x'; 1024 * 1024 + 1];
        let archive = skill_zip(&[("SKILL.md", &large_compressible, 0o644)]);
        let catalog = vec![archive; 256];
        let aggregate_error = preflight_catalog(&catalog, MAX_ENTRIES, MAX_EXPANDED)
            .expect_err("256-entry aggregate expansion must be rejected");
        assert!(aggregate_error.to_string().contains("expands beyond"));
    }

    #[test]
    fn aggregate_budget_failure_preserves_published_catalog_without_staging() {
        let expanded = vec![b'x'; 64];
        let archive = skill_zip(&[("SKILL.md", &expanded, 0o644)]);
        let server = Server::http("127.0.0.1:0").expect("archive server");
        let origin = format!("http://{}", server.server_addr());
        let response = archive.clone();
        let handle = thread::spawn(move || {
            for _ in 0..2 {
                server
                    .recv()
                    .expect("archive request")
                    .respond(Response::from_data(response.clone()))
                    .expect("archive response");
            }
        });
        let records = vec![
            skill("one", &format!("{origin}/one.zip"), &archive, "none"),
            skill("two", &format!("{origin}/two.zip"), &archive, "none"),
        ];
        let state = tempfile::tempdir().expect("catalog state");
        let published = state
            .path()
            .join("synchronized-skills/test-platform/old/SKILL.md");
        fs::create_dir_all(published.parent().expect("published parent")).expect("published root");
        fs::write(&published, b"published").expect("published Skill");

        let error = SkillCatalog::new(state.path().to_owned())
            .expect("catalog")
            .synchronize_with_limits(
                &manifest(&origin, &[&origin]),
                &provisioning(records),
                &ApiKey::new("unused-token").expect("token"),
                10,
                100,
            )
            .expect_err("aggregate budget");
        handle.join().expect("archive server");
        assert!(error.to_string().contains("expands beyond"), "{error}");
        assert_eq!(fs::read(&published).expect("published Skill"), b"published");
        let catalog_parent = state.path().join("synchronized-skills");
        assert!(
            fs::read_dir(catalog_parent)
                .expect("catalog parent")
                .all(|entry| !entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .contains("staged-"))
        );
    }

    fn manifest(origin: &str, bearer_origins: &[&str]) -> ConnectionManifest {
        ConnectionManifest::parse(
            serde_json::json!({"success":true,"data":{
                "schema_version":2,
                "platform":{"id":"test-platform","name":"Test Platform"},
                "gateway":{"base_url":origin,"protocols":["openai_chat"]},
                "provisioning_url":format!("{origin}/provisioning"),
                "connection_bearer_origins":bearer_origins,
                "supported_agents":["codex"]
            }})
            .to_string()
            .as_bytes(),
        )
        .expect("manifest")
    }

    fn provisioning(skills: Vec<serde_json::Value>) -> Provisioning {
        Provisioning::parse(
            serde_json::json!({"success":true,"data":{
                "schema_version":2,
                "models":[{"id":"model-a","chat_capable":true}],
                "default_model":"model-a",
                "mcp_servers":[],
                "skills":skills
            }})
            .to_string()
            .as_bytes(),
        )
        .expect("provisioning")
    }

    fn skill(id: &str, url: &str, bytes: &[u8], authorization: &str) -> serde_json::Value {
        serde_json::json!({
            "id":id,
            "name":id,
            "version":"1.0.0",
            "archive":{
                "url":url,
                "sha256":digest(bytes),
                "size_bytes":bytes.len(),
                "format":"zip",
                "authorization":authorization
            }
        })
    }

    #[test]
    fn zip_validation_rejects_unsafe_and_ambiguous_archives_before_extracting() {
        let cases = [
            (
                "traversal",
                skill_zip(&[("SKILL.md", b"skill", 0o644), ("../escape", b"x", 0o644)]),
            ),
            ("symlink", symlink_zip()),
            (
                "case-duplicate",
                skill_zip(&[("SKILL.md", b"one", 0o644), ("skill.md", b"two", 0o644)]),
            ),
            ("exact-duplicate", exact_duplicate_zip()),
            (
                "windows-reserved",
                skill_zip(&[("SKILL.md", b"skill", 0o644), ("CON.txt", b"x", 0o644)]),
            ),
            (
                "backslash",
                skill_zip(&[("SKILL.md", b"skill", 0o644), ("dir\\file", b"x", 0o644)]),
            ),
            (
                "reserved-marker",
                skill_zip(&[("SKILL.md", b"skill", 0o644), (OWNER_MARKER, b"x", 0o644)]),
            ),
            (
                "prefix-collision",
                skill_zip(&[
                    ("SKILL.md", b"skill", 0o644),
                    ("docs", b"file", 0o644),
                    ("docs/page.md", b"child", 0o644),
                ]),
            ),
            (
                "wrapper",
                skill_zip(&[("wrapped/SKILL.md", b"skill", 0o644)]),
            ),
            ("missing-root", skill_zip(&[("README.md", b"no", 0o644)])),
        ];
        let temp = tempfile::tempdir().expect("temp directory");
        for (name, bytes) in cases {
            let target = temp.path().join(name);
            let error = extract_zip(&bytes, &target).expect_err("unsafe ZIP must fail");
            assert!(
                !target.exists(),
                "{name} extracted before rejection: {error}"
            );
        }
        assert!(!temp.path().join("escape").exists());
    }

    #[test]
    fn zip_validation_enforces_entry_and_expanded_budgets() {
        let bytes = skill_zip(&[("SKILL.md", b"four", 0o644), ("extra.txt", b"x", 0o644)]);
        let temp = tempfile::tempdir().expect("temp directory");
        assert!(extract_zip_with_limits(&bytes, &temp.path().join("entries"), 1, 100).is_err());
        assert!(extract_zip_with_limits(&bytes, &temp.path().join("size"), 10, 3).is_err());
        let output = temp.path().join("valid");
        extract_zip_with_limits(&bytes, &output, 10, 100).expect("valid ZIP");
        assert_eq!(fs::read(output.join("SKILL.md")).expect("Skill"), b"four");
    }

    #[test]
    fn catalog_downloads_public_and_private_archives_with_exact_auth() {
        let public = skill_zip(&[("SKILL.md", b"public", 0o644)]);
        let private = skill_zip(&[("SKILL.md", b"private", 0o700)]);
        let server = Server::http("127.0.0.1:0").expect("archive server");
        let origin = format!("http://{}", server.server_addr());
        let captures = Arc::new(Mutex::new(Vec::new()));
        let thread_captures = Arc::clone(&captures);
        let public_response = public.clone();
        let private_response = private.clone();
        let handle = thread::spawn(move || {
            for _ in 0..2 {
                let request = server.recv().expect("archive request");
                let authorization = request
                    .headers()
                    .iter()
                    .find(|header| header.field.equiv("authorization"))
                    .map(|header| header.value.as_str().to_owned());
                thread_captures
                    .lock()
                    .expect("captures")
                    .push((request.url().to_owned(), authorization));
                let body = if request.url() == "/public.zip" {
                    public_response.clone()
                } else {
                    private_response.clone()
                };
                request
                    .respond(Response::from_data(body))
                    .expect("response");
            }
        });
        let manifest = manifest(&origin, &[&origin]);
        let provisioning = provisioning(vec![
            skill("public", &format!("{origin}/public.zip"), &public, "none"),
            skill(
                "private",
                &format!("{origin}/private.zip"),
                &private,
                "connection_bearer",
            ),
        ]);
        provisioning.validate_for(&manifest).expect("catalog");
        let temp = tempfile::tempdir().expect("temp directory");
        let paths = SkillCatalog::new(temp.path().to_owned())
            .expect("catalog")
            .synchronize(
                &manifest,
                &provisioning,
                &ApiKey::new("catalog-token").expect("token"),
            )
            .expect("synchronize");
        handle.join().expect("archive server");
        let captures = captures.lock().expect("captures");
        assert_eq!(
            captures.as_slice(),
            [
                ("/public.zip".to_owned(), None),
                (
                    "/private.zip".to_owned(),
                    Some("Bearer catalog-token".to_owned())
                )
            ]
        );
        assert_eq!(
            fs::read(paths["private"].join("SKILL.md")).expect("private Skill"),
            b"private"
        );
    }

    #[test]
    fn redirect_and_digest_failures_preserve_the_published_catalog() {
        let bytes = skill_zip(&[("SKILL.md", b"replacement", 0o644)]);
        let source = Server::http("127.0.0.1:0").expect("source server");
        let source_origin = format!("http://{}", source.server_addr());
        let target = Server::http("127.0.0.1:0").expect("target server");
        let target_url = format!("http://{}/leak", target.server_addr());
        let handle = thread::spawn(move || {
            let request = source.recv().expect("source request");
            assert_eq!(
                request
                    .headers()
                    .iter()
                    .find(|header| header.field.equiv("authorization"))
                    .map(|header| header.value.as_str()),
                Some("Bearer must-not-leak")
            );
            request
                .respond(
                    Response::empty(StatusCode(302))
                        .with_header(Header::from_bytes("Location", target_url).expect("Location")),
                )
                .expect("redirect");
        });
        let manifest = manifest(&source_origin, &[&source_origin]);
        let provisioning = provisioning(vec![skill(
            "replacement",
            &format!("{source_origin}/archive.zip"),
            &bytes,
            "connection_bearer",
        )]);
        let temp = tempfile::tempdir().expect("temp directory");
        let old = temp
            .path()
            .join("synchronized-skills/test-platform/old/SKILL.md");
        fs::create_dir_all(old.parent().expect("old parent")).expect("old root");
        fs::write(&old, b"old").expect("old Skill");
        let error = SkillCatalog::new(temp.path().to_owned())
            .expect("catalog")
            .synchronize(
                &manifest,
                &provisioning,
                &ApiKey::new("must-not-leak").expect("token"),
            )
            .expect_err("cross-origin redirect");
        handle.join().expect("source server");
        assert!(error.to_string().contains("redirect"));
        assert!(
            target
                .recv_timeout(Duration::from_millis(250))
                .is_ok_and(|request| request.is_none())
        );
        assert_eq!(fs::read(&old).expect("old Skill preserved"), b"old");
        let parent = old.ancestors().nth(3).expect("catalog parent");
        assert!(fs::read_dir(parent).expect("catalog parent").all(|entry| {
            !entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .contains("staged-")
        }));
    }

    #[test]
    fn empty_catalog_replaces_stale_state_and_startup_recovers_previous_tree() {
        let temp = tempfile::tempdir().expect("temp directory");
        let parent = temp.path().join("synchronized-skills");
        fs::create_dir_all(&parent).expect("catalog parent");
        let recovery_root = parent.join("test.platform");
        let staged = transaction_path(&recovery_root, "staged", &transaction_nonce(3, 10))
            .expect("staged path");
        fs::create_dir(&staged).expect("staging");
        let older = transaction_path(&recovery_root, "previous", &transaction_nonce(1, 9_999))
            .expect("older path");
        fs::create_dir_all(older.join("old")).expect("old previous");
        fs::write(older.join("old/SKILL.md"), b"older").expect("older Skill");
        let newer = transaction_path(&recovery_root, "previous", &transaction_nonce(2, 1))
            .expect("newer path");
        fs::create_dir_all(newer.join("new")).expect("new previous");
        fs::write(newer.join("new/SKILL.md"), b"newer").expect("newer Skill");
        reconcile(&recovery_root).expect("startup recovery");
        assert_eq!(
            fs::read(recovery_root.join("new/SKILL.md")).expect("restored Skill"),
            b"newer"
        );
        assert!(!staged.exists());
        assert!(!older.exists());

        let origin = "http://127.0.0.1:1";
        let paths = SkillCatalog::new(temp.path().to_owned())
            .expect("catalog")
            .synchronize(
                &manifest(origin, &[origin]),
                &provisioning(Vec::new()),
                &ApiKey::new("unused-token").expect("token"),
            )
            .expect("empty catalog");
        assert!(paths.is_empty());
        assert!(parent.join("test-platform").is_dir());
        assert_eq!(
            fs::read_dir(parent.join("test-platform"))
                .expect("empty root")
                .count(),
            0
        );
    }

    #[test]
    fn transaction_namespace_does_not_overlap_other_platform_ids() {
        let temp = tempfile::tempdir().expect("temp directory");
        let root = temp.path().join("foo");
        let other_platform = temp.path().join("foo.previous-other");
        fs::create_dir_all(&other_platform).expect("other platform");
        fs::write(other_platform.join("SKILL.md"), b"other").expect("other Skill");

        reconcile(&root).expect("reconcile unrelated root");

        assert_eq!(
            fs::read(other_platform.join("SKILL.md")).expect("other Skill preserved"),
            b"other"
        );
        assert!(!root.exists());
    }

    #[test]
    fn special_current_root_does_not_destroy_recovery_tree() {
        let temp = tempfile::tempdir().expect("temp directory");
        let root = temp.path().join("platform");
        fs::write(&root, b"not a directory").expect("special root");
        let previous =
            transaction_path(&root, "previous", &transaction_nonce(1, 1)).expect("previous path");
        fs::create_dir_all(previous.join("skill")).expect("previous tree");
        fs::write(previous.join("skill/SKILL.md"), b"previous").expect("previous Skill");

        let error = reconcile(&root).expect_err("special root must fail");

        assert!(error.to_string().contains("special"));
        assert_eq!(
            fs::read(previous.join("skill/SKILL.md")).expect("recovery tree preserved"),
            b"previous"
        );
    }

    #[cfg(unix)]
    #[test]
    fn catalog_state_symlink_fails_before_mutating_its_target() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("temporary directory");
        let state = temp.path().join("state");
        let outside = temp.path().join("outside");
        fs::create_dir_all(&state).expect("state");
        fs::create_dir_all(&outside).expect("outside");
        fs::write(outside.join("sentinel"), b"untouched").expect("sentinel");
        symlink(&outside, state.join("synchronized-skills")).expect("catalog symlink");

        let origin = "http://127.0.0.1:1";
        let error = SkillCatalog::new(state)
            .expect("catalog")
            .synchronize(
                &manifest(origin, &[origin]),
                &provisioning(Vec::new()),
                &ApiKey::new("unused-token").expect("token"),
            )
            .expect_err("catalog symlink must fail closed");

        assert!(error.to_string().contains("reparse point"));
        assert_eq!(
            fs::read(outside.join("sentinel")).expect("sentinel"),
            b"untouched"
        );
        assert_eq!(fs::read_dir(&outside).expect("outside").count(), 1);
    }

    #[cfg(windows)]
    #[test]
    fn catalog_state_junction_fails_before_mutating_its_target() {
        use std::process::Command;

        let temp = tempfile::tempdir().expect("temporary directory");
        let state = temp.path().join("state");
        let outside = temp.path().join("outside");
        fs::create_dir_all(&state).expect("state");
        fs::create_dir_all(&outside).expect("outside");
        fs::write(outside.join("sentinel"), b"untouched").expect("sentinel");
        let junction = state.join("synchronized-skills");
        let status = Command::new("cmd")
            .arg("/C")
            .arg("mklink")
            .arg("/J")
            .arg(&junction)
            .arg(&outside)
            .status()
            .expect("create catalog junction");
        assert!(status.success());

        let origin = "http://127.0.0.1:1";
        let error = SkillCatalog::new(state)
            .expect("catalog")
            .synchronize(
                &manifest(origin, &[origin]),
                &provisioning(Vec::new()),
                &ApiKey::new("unused-token").expect("token"),
            )
            .expect_err("catalog junction must fail closed");

        assert!(error.to_string().contains("reparse point"));
        assert_eq!(
            fs::read(outside.join("sentinel")).expect("sentinel"),
            b"untouched"
        );
        assert_eq!(fs::read_dir(&outside).expect("outside").count(), 1);
    }

    #[test]
    fn exact_size_and_digest_are_required() {
        let bytes = skill_zip(&[("SKILL.md", b"skill", 0o644)]);
        let server = Server::http("127.0.0.1:0").expect("archive server");
        let origin = format!("http://{}", server.server_addr());
        let response = bytes.clone();
        let handle = thread::spawn(move || {
            for _ in 0..2 {
                let request = server.recv().expect("archive request");
                request
                    .respond(Response::from_data(response.clone()))
                    .expect("response");
            }
        });
        let mut record = skill("bad", &format!("{origin}/bad.zip"), &bytes, "none");
        record["archive"]["sha256"] = serde_json::Value::String("0".repeat(64));
        let error = SkillCatalog::new(tempfile::tempdir().expect("temp").path().to_owned())
            .expect("catalog")
            .synchronize(
                &manifest(&origin, &[&origin]),
                &provisioning(vec![record]),
                &ApiKey::new("unused-token").expect("token"),
            )
            .expect_err("digest mismatch");
        assert!(error.to_string().contains("digest"));

        let mut record = skill("bad", &format!("{origin}/bad.zip"), &bytes, "none");
        record["archive"]["size_bytes"] = serde_json::json!(bytes.len() + 1);
        let error = SkillCatalog::new(tempfile::tempdir().expect("temp").path().to_owned())
            .expect("catalog")
            .synchronize(
                &manifest(&origin, &[&origin]),
                &provisioning(vec![record]),
                &ApiKey::new("unused-token").expect("token"),
            )
            .expect_err("size mismatch");
        assert!(error.to_string().contains("size"));
        handle.join().expect("archive server");
    }

    #[test]
    fn provisioning_rejects_uppercase_archive_digest() {
        let bytes = skill_zip(&[("SKILL.md", b"skill", 0o644)]);
        let record = skill("bad", "https://gateway.example/bad.zip", &bytes, "none");
        let mut document = serde_json::json!({"success":true,"data":{
            "schema_version":2,
            "models":[{"id":"model-a","chat_capable":true}],
            "default_model":"model-a",
            "mcp_servers":[],
            "skills":[record]
        }});
        let digest = document["data"]["skills"][0]["archive"]["sha256"]
            .as_str()
            .expect("digest")
            .to_ascii_uppercase();
        document["data"]["skills"][0]["archive"]["sha256"] = serde_json::Value::String(digest);
        let error = Provisioning::parse(document.to_string().as_bytes())
            .expect_err("uppercase digest must fail");
        assert!(error.to_string().to_ascii_lowercase().contains("sha-256"));
    }

    #[test]
    fn archive_redirect_with_userinfo_is_rejected_before_following() {
        let bytes = skill_zip(&[("SKILL.md", b"skill", 0o644)]);
        let server = Server::http("127.0.0.1:0").expect("archive server");
        let origin = format!("http://{}", server.server_addr());
        let port = Url::parse(&origin).expect("origin").port().expect("port");
        let handle = thread::spawn(move || {
            let request = server.recv().expect("archive request");
            request
                .respond(
                    Response::empty(StatusCode(302)).with_header(
                        Header::from_bytes(
                            "Location",
                            format!("http://user:password@127.0.0.1:{port}/archive.zip"),
                        )
                        .expect("Location"),
                    ),
                )
                .expect("redirect");
        });
        let error = SkillCatalog::new(tempfile::tempdir().expect("temp").path().to_owned())
            .expect("catalog")
            .synchronize(
                &manifest(&origin, &[&origin]),
                &provisioning(vec![skill(
                    "skill",
                    &format!("{origin}/archive.zip"),
                    &bytes,
                    "connection_bearer",
                )]),
                &ApiKey::new("must-not-forward").expect("token"),
            )
            .expect_err("userinfo redirect");
        handle.join().expect("archive server");
        assert!(error.to_string().contains("redirect"));
    }
}
