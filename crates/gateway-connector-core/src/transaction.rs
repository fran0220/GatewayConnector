use crate::{AgentId, AgentInstall, ConnectionManifest, Error, Provisioning, Result, Secret, io};
use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, AeadCore, OsRng},
};
use fs2::FileExt;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::io::Write;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};
use toml_edit::{DocumentMut, Item, Table, value};

const SKILL_OWNER_FILE: &str = ".gateway-connector-owner";

#[derive(Debug)]
pub struct ApplyInput<'a> {
    pub manifest: &'a ConnectionManifest,
    pub provisioning: &'a Provisioning,
    pub bearer: &'a Secret,
    pub selected_models: BTreeMap<AgentId, String>,
    pub installs: Vec<AgentInstall>,
    pub synchronized_skills: BTreeMap<String, PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangeKind {
    Create,
    Update,
    Remove,
    ProjectSkill,
}
#[derive(Debug, Clone)]
pub struct Change {
    pub path: PathBuf,
    pub kind: ChangeKind,
    pub managed_entries: Vec<String>,
}
#[derive(Clone)]
enum Op {
    File {
        path: PathBuf,
        bytes: Vec<u8>,
    },
    Dir {
        path: PathBuf,
        source: PathBuf,
        marker: Vec<u8>,
    },
    Remove {
        path: PathBuf,
    },
}
type FileProjection = (PathBuf, Vec<u8>, Vec<String>);
enum Saved {
    Missing,
    Bytes(Vec<u8>),
    Disk(PathBuf),
}
#[derive(Clone)]
pub struct Plan {
    pub platform_id: String,
    pub changes: Vec<Change>,
    ops: Vec<Op>,
    receipt: Receipt,
    key: [u8; 32],
    expected_files: BTreeMap<PathBuf, Option<String>>,
    expected_skills: BTreeMap<PathBuf, Option<Vec<u8>>>,
    expected_receipt: Option<String>,
}
impl std::fmt::Debug for Plan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Plan")
            .field("platform_id", &self.platform_id)
            .field("changes", &self.changes)
            .finish()
    }
}
impl Plan {
    pub fn credential_matches(&self, bearer: &Secret) -> Result<bool> {
        Ok(self.key == receipt_key(bearer)?)
    }
}
#[derive(Debug)]
pub struct Verification {
    pub ok: bool,
    pub mismatches: Vec<PathBuf>,
}

#[derive(Clone, Serialize, Deserialize)]
struct Receipt {
    platform_id: String,
    files: Vec<FileReceipt>,
    skills: Vec<SkillReceipt>,
    #[serde(default)]
    leases: Vec<ProjectionLease>,
}
#[derive(Clone, Serialize, Deserialize)]
struct FileReceipt {
    path: PathBuf,
    original: Option<Vec<u8>>,
    applied: Vec<u8>,
}
#[derive(Clone, Serialize, Deserialize)]
struct SkillReceipt {
    path: PathBuf,
    applied_hash: Vec<u8>,
    marker: Vec<u8>,
    kind: SkillKind,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ProjectionLease {
    platform_id: String,
    agent: String,
    root: PathBuf,
}
#[derive(Default, Serialize, Deserialize)]
struct ProjectionCoordinator {
    leases: Vec<ProjectionLease>,
}
#[derive(Clone, Copy, Serialize, Deserialize)]
enum SkillKind {
    Directory,
}
#[derive(Serialize, Deserialize)]
struct SealedReceipt {
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}
#[derive(Debug)]
pub struct Connector {
    state_dir: PathBuf,
    coordinator_dir: PathBuf,
}
impl Connector {
    pub fn new(state_dir: impl Into<PathBuf>) -> Self {
        let state_dir = state_dir.into();
        let coordinator_dir = state_dir.join("projection-coordinator");
        Self {
            state_dir,
            coordinator_dir,
        }
    }
    pub fn with_coordinator(
        state_dir: impl Into<PathBuf>,
        coordinator_dir: impl Into<PathBuf>,
    ) -> Self {
        Self {
            state_dir: state_dir.into(),
            coordinator_dir: coordinator_dir.into(),
        }
    }
    pub fn plan(&self, input: ApplyInput<'_>) -> Result<Plan> {
        input.manifest.validate()?;
        input.provisioning.validate_for(input.manifest)?;
        if !input
            .provisioning
            .models
            .iter()
            .any(|model| model.chat_capable)
        {
            return Err(Error::Validation(
                "cannot project Agent configuration: account has no chat-capable model".into(),
            ));
        }
        let mut installs = input.installs;
        for install in installs.iter_mut().filter(|install| install.detected) {
            install.root = fs::canonicalize(&install.root).map_err(|error| {
                Error::Validation(format!(
                    "could not canonicalize detected {} root {}: {error}",
                    install.agent.as_str(),
                    install.root.display()
                ))
            })?;
        }
        let platform = &input.manifest.platform.id;
        let provider = owned(platform, "provider", "default");
        let mut ops = Vec::new();
        let mut changes = Vec::new();
        let mut projected_paths = BTreeSet::new();
        let key = receipt_key(input.bearer)?;
        let expected_receipt = snapshot_file(&self.receipt_path(platform))?;
        let old_receipt = self.load_receipt(platform, &key)?;
        let mut projection_bases = BTreeMap::new();
        let mut expected_files = BTreeMap::new();
        let mut expected_skills = BTreeMap::new();
        let ownership_path = self.ownership_path();
        let ownership_snapshot = snapshot_file(&ownership_path)?;
        let mut coordinator = self.load_coordinator()?;
        if let Some(receipt) = &old_receipt {
            for lease in &receipt.leases {
                if !coordinator.leases.contains(lease) {
                    return Err(Error::Validation(format!(
                        "shared Agent ownership changed for {} at {}; disconnect or repair the owning Connector first",
                        lease.agent,
                        lease.root.display()
                    )));
                }
            }
        }
        let leases = installs
            .iter()
            .filter(|install| {
                install.detected && input.manifest.supported_agents.contains(&install.agent)
            })
            .map(|install| ProjectionLease {
                platform_id: platform.clone(),
                agent: install.agent.as_str().into(),
                root: install.root.clone(),
            })
            .collect::<Vec<_>>();
        for lease in &leases {
            if let Some(owner) = coordinator.leases.iter().find(|existing| {
                lease_key(existing) == lease_key(lease) && existing.platform_id.as_str() != platform
            }) {
                return Err(Error::Validation(format!(
                    "{} at {} is already managed by platform {}; disconnect it there before applying {}",
                    lease.agent,
                    lease.root.display(),
                    owner.platform_id,
                    platform
                )));
            }
        }
        coordinator
            .leases
            .retain(|lease| lease.platform_id.as_str() != platform);
        coordinator.leases.extend(leases.iter().cloned());
        coordinator
            .leases
            .sort_by_key(|lease| (lease_key(lease), lease.platform_id.clone()));
        expected_files.insert(ownership_path.clone(), ownership_snapshot);
        if let Some(receipt) = &old_receipt {
            for file in &receipt.files {
                expected_files.insert(file.path.clone(), snapshot_file(&file.path)?);
                if let Some(bytes) = reconciled_file(file)? {
                    projection_bases.insert(file.path.clone(), bytes);
                }
            }
            for skill in &receipt.skills {
                if exists(&skill.path) && !skill_matches(skill) {
                    return Err(Error::Validation(format!(
                        "managed Skill has local changes: {}",
                        skill.path.display()
                    )));
                }
                expected_skills.insert(skill.path.clone(), snapshot_skill(&skill.path)?);
            }
        }
        let mut files = Vec::new();
        let mut skills = Vec::new();
        // Stage each platform/skill source once, independently of Agent count.
        for skill in &input.provisioning.skills {
            let source = input.synchronized_skills.get(&skill.id).ok_or_else(|| {
                Error::Validation(format!(
                    "missing verified synchronized source for {}",
                    skill.id
                ))
            })?;
            if !source.is_dir() {
                return Err(Error::Validation(format!(
                    "skill source {} is not a directory",
                    source.display()
                )));
            }
            if source.join(SKILL_OWNER_FILE).exists() {
                return Err(Error::Validation(format!(
                    "synchronized Skill contains reserved ownership marker: {}",
                    source.display()
                )));
            }
            let source_hash = hash_skill_content(source)?;
            expected_skills.insert(source.clone(), Some(source_hash.clone()));
            let ssot = self.state_dir.join("skills").join(platform).join(&skill.id);
            claim_path(&mut projected_paths, &ssot)?;
            changes.push(Change {
                path: ssot.clone(),
                kind: ChangeKind::ProjectSkill,
                managed_entries: vec![skill.id.clone()],
            });
            skills.push(SkillReceipt {
                path: ssot.clone(),
                applied_hash: source_hash,
                marker: ownership_marker(),
                kind: SkillKind::Directory,
            });
            let marker = skills
                .last()
                .expect("staged Skill receipt exists")
                .marker
                .clone();
            ops.push(Op::Dir {
                path: ssot,
                source: source.clone(),
                marker,
            });
        }
        for install in installs.iter().filter(|x| x.detected) {
            if !input.manifest.supported_agents.contains(&install.agent) {
                continue;
            }
            let model = input
                .selected_models
                .get(&install.agent)
                .unwrap_or(&input.provisioning.default_model);
            if !input
                .provisioning
                .models
                .iter()
                .any(|m| &m.id == model && m.chat_capable)
            {
                return Err(Error::Validation(format!(
                    "selected model {model} is not a chat-capable catalog model"
                )));
            }
            let projections = project(
                install,
                input.manifest,
                input.provisioning,
                input.bearer,
                model,
                &provider,
                &projection_bases,
            )?;
            for (path, bytes, entries) in projections {
                claim_path(&mut projected_paths, &path)?;
                if is_symlink(&path) {
                    return Err(Error::Validation(format!(
                        "configuration symlinks are not supported: {}",
                        path.display()
                    )));
                }
                expected_files
                    .entry(path.clone())
                    .or_insert(snapshot_file(&path)?);
                let kind = if path.exists() {
                    ChangeKind::Update
                } else {
                    ChangeKind::Create
                };
                changes.push(Change {
                    path: path.clone(),
                    kind,
                    managed_entries: entries,
                });
                let original = old_receipt
                    .as_ref()
                    .and_then(|r| r.files.iter().find(|f| f.path == path))
                    .map(|f| f.original.clone())
                    .unwrap_or_else(|| fs::read(&path).ok());
                files.push(FileReceipt {
                    path: path.clone(),
                    original,
                    applied: bytes.clone(),
                });
                ops.push(Op::File { path, bytes });
            }
            for skill in &input.provisioning.skills {
                let ssot = self.state_dir.join("skills").join(platform).join(&skill.id);
                let target = install.root.join("skills").join(&skill.id);
                claim_path(&mut projected_paths, &target)?;
                let previous = old_receipt
                    .as_ref()
                    .and_then(|receipt| receipt.skills.iter().find(|owned| owned.path == target));
                if exists(&target) {
                    match previous {
                        Some(previous) if skill_matches(previous) => {}
                        Some(_) => {
                            return Err(Error::Validation(format!(
                                "managed Skill has local changes: {}",
                                target.display()
                            )));
                        }
                        None => {
                            return Err(Error::Validation(format!(
                                "managed Skill target collides with unknown content: {}",
                                target.display()
                            )));
                        }
                    }
                }
                expected_skills
                    .entry(target.clone())
                    .or_insert(snapshot_skill(&target)?);
                changes.push(Change {
                    path: target.clone(),
                    kind: ChangeKind::ProjectSkill,
                    managed_entries: vec![skill.id.clone()],
                });
                let applied_hash = skills
                    .iter()
                    .find(|receipt| receipt.path == ssot)
                    .expect("staged Skill receipt exists")
                    .applied_hash
                    .clone();
                skills.push(SkillReceipt {
                    path: target.clone(),
                    applied_hash,
                    marker: ownership_marker(),
                    kind: SkillKind::Directory,
                });
                let marker = skills
                    .last()
                    .expect("target Skill receipt exists")
                    .marker
                    .clone();
                ops.push(Op::Dir {
                    path: target,
                    source: ssot,
                    marker,
                });
            }
        }
        let receipt = Receipt {
            platform_id: platform.clone(),
            files,
            skills,
            leases,
        };
        let mut cleanup_ops = Vec::new();
        if let Some(old) = &old_receipt {
            for file in &old.files {
                if !receipt.files.iter().any(|new| new.path == file.path) {
                    match reconciled_file(file)? {
                        Some(bytes)
                            if fs::read(&file.path).ok().as_deref() != Some(bytes.as_slice()) =>
                        {
                            changes.push(Change {
                                path: file.path.clone(),
                                kind: ChangeKind::Update,
                                managed_entries: vec!["restore prior configuration".into()],
                            });
                            cleanup_ops.push(Op::File {
                                path: file.path.clone(),
                                bytes,
                            });
                        }
                        Some(_) => {}
                        None if exists(&file.path) => {
                            changes.push(Change {
                                path: file.path.clone(),
                                kind: ChangeKind::Remove,
                                managed_entries: vec!["remove managed configuration".into()],
                            });
                            cleanup_ops.push(Op::Remove {
                                path: file.path.clone(),
                            });
                        }
                        None => {}
                    }
                }
            }
            for skill in &old.skills {
                if !receipt.skills.iter().any(|new| new.path == skill.path) && exists(&skill.path) {
                    changes.push(Change {
                        path: skill.path.clone(),
                        kind: ChangeKind::Remove,
                        managed_entries: vec!["remove managed Skill".into()],
                    });
                    cleanup_ops.push(Op::Remove {
                        path: skill.path.clone(),
                    });
                }
            }
        }
        cleanup_ops.extend(ops);
        cleanup_ops.push(Op::File {
            path: ownership_path,
            bytes: serde_json::to_vec_pretty(&coordinator)
                .map_err(|error| Error::Transaction(error.to_string()))?,
        });
        Ok(Plan {
            platform_id: platform.clone(),
            changes,
            ops: cleanup_ops,
            receipt,
            key,
            expected_files,
            expected_skills,
            expected_receipt,
        })
    }
    pub fn apply(&self, plan: &Plan) -> Result<()> {
        fs::create_dir_all(&self.state_dir).map_err(|e| io(&self.state_dir, e))?;
        let _lock = self.lock(&plan.platform_id)?;
        if snapshot_file(&self.receipt_path(&plan.platform_id))? != plan.expected_receipt {
            return Err(Error::Validation(
                "Connector state changed after this plan was created; preview again".into(),
            ));
        }
        for (path, expected) in &plan.expected_files {
            if &snapshot_file(path)? != expected {
                return Err(Error::Validation(format!(
                    "configuration changed after this plan was created: {}",
                    path.display()
                )));
            }
        }
        for (path, expected) in &plan.expected_skills {
            if &snapshot_skill(path)? != expected {
                return Err(Error::Validation(format!(
                    "Skill changed after this plan was created: {}",
                    path.display()
                )));
            }
        }
        let mut all_ops = plan.ops.clone();
        let receipt_path = self.receipt_path(&plan.platform_id);
        let receipt_bytes = seal_receipt(&plan.receipt, &plan.key)?;
        all_ops.push(Op::File {
            path: receipt_path,
            bytes: receipt_bytes,
        });
        execute_ops(&self.state_dir, &plan.platform_id, all_ops)
    }
    pub fn verify(&self, plan: &Plan) -> Result<Verification> {
        let mut mismatches = Vec::new();
        for op in &plan.ops {
            match op {
                Op::File { path, bytes } => {
                    if fs::read(path).ok().as_deref() != Some(bytes) {
                        mismatches.push(path.clone())
                    }
                }
                Op::Dir {
                    path,
                    source,
                    marker,
                } => {
                    let content_matches =
                        match (hash_skill_content(path), hash_skill_content(source)) {
                            (Ok(applied), Ok(expected)) => applied == expected,
                            _ => false,
                        };
                    if fs::read(path.join(SKILL_OWNER_FILE)).ok().as_deref()
                        != Some(marker.as_slice())
                        || !content_matches
                    {
                        mismatches.push(path.clone())
                    }
                }
                Op::Remove { path } => {
                    if exists(path) {
                        mismatches.push(path.clone())
                    }
                }
            }
        }
        Ok(Verification {
            ok: mismatches.is_empty(),
            mismatches,
        })
    }
    pub fn disconnect(&self, platform: &str, bearer: &Secret) -> Result<()> {
        fs::create_dir_all(&self.state_dir).map_err(|e| io(&self.state_dir, e))?;
        let _lock = self.lock(platform)?;
        let rp = self.receipt_path(platform);
        if !rp.exists() {
            return Ok(());
        }
        let receipt = open_receipt(
            &fs::read(&rp).map_err(|e| io(&rp, e))?,
            &receipt_key(bearer)?,
        )?;
        if receipt.platform_id != platform {
            return Err(Error::Transaction(
                "receipt does not belong to the requested platform".into(),
            ));
        }
        let mut ops = Vec::new();
        for file in &receipt.files {
            match reconciled_file(file)? {
                Some(bytes) if fs::read(&file.path).ok().as_deref() != Some(bytes.as_slice()) => {
                    ops.push(Op::File {
                        path: file.path.clone(),
                        bytes,
                    });
                }
                Some(_) => {}
                None if exists(&file.path) => ops.push(Op::Remove {
                    path: file.path.clone(),
                }),
                None => {}
            }
        }
        let mut skills = receipt
            .skills
            .iter()
            .filter(|skill| exists(&skill.path))
            .collect::<Vec<_>>();
        if let Some(skill) = skills.iter().find(|skill| !skill_matches(skill)) {
            return Err(Error::Validation(format!(
                "managed Skill has local changes: {}",
                skill.path.display()
            )));
        }
        skills.sort_by_key(|skill| !is_symlink(&skill.path));
        for skill in skills {
            ops.push(Op::Remove {
                path: skill.path.clone(),
            });
        }
        let mut coordinator = self.load_coordinator()?;
        for lease in &receipt.leases {
            if !coordinator.leases.contains(lease) {
                return Err(Error::Validation(format!(
                    "shared Agent ownership changed for {} at {}; disconnect or repair the owning Connector first",
                    lease.agent,
                    lease.root.display()
                )));
            }
        }
        coordinator
            .leases
            .retain(|lease| !receipt.leases.iter().any(|owned| owned == lease));
        ops.push(Op::File {
            path: self.ownership_path(),
            bytes: serde_json::to_vec_pretty(&coordinator)
                .map_err(|error| Error::Transaction(error.to_string()))?,
        });
        // Removing the authenticated receipt is the final transactional step.
        // Any earlier failure rolls every projection back and leaves ownership
        // recoverable with the credential still held by the caller.
        ops.push(Op::Remove { path: rp });
        execute_ops(&self.state_dir, platform, ops)
    }
    pub fn has_receipt(&self, platform: &str) -> bool {
        self.receipt_path(platform).is_file()
    }
    pub fn managed_agents(&self, platform: &str, bearer: &Secret) -> Result<BTreeSet<AgentId>> {
        let Some(receipt) = self.load_receipt(platform, &receipt_key(bearer)?)? else {
            return Ok(BTreeSet::new());
        };
        Ok(receipt
            .leases
            .iter()
            .filter_map(|lease| match lease.agent.as_str() {
                "claude" => Some(AgentId::Claude),
                "codex" => Some(AgentId::Codex),
                "gemini" => Some(AgentId::Gemini),
                "grokbuild" => Some(AgentId::Grokbuild),
                "opencode" => Some(AgentId::Opencode),
                _ => None,
            })
            .collect())
    }
    fn lock(&self, _platform: &str) -> Result<fs::File> {
        let locks = self.coordinator_dir.join("locks");
        fs::create_dir_all(&locks).map_err(|error| io(&locks, error))?;
        // Agent config paths are global even when receipt/keyring state is
        // platform-partitioned, so all platforms share one process lock.
        let path = locks.join("connector.lock");
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|error| io(&path, error))?;
        file.lock_exclusive().map_err(|error| io(&path, error))?;
        Ok(file)
    }
    fn ownership_path(&self) -> PathBuf {
        self.coordinator_dir.join("ownership.json")
    }
    fn load_coordinator(&self) -> Result<ProjectionCoordinator> {
        let path = self.ownership_path();
        match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|error| Error::Config {
                path,
                message: error.to_string(),
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(ProjectionCoordinator::default())
            }
            Err(error) => Err(io(&path, error)),
        }
    }
    fn receipt_path(&self, p: &str) -> PathBuf {
        self.state_dir.join("receipts").join(format!("{p}.json"))
    }
    fn load_receipt(&self, platform: &str, key: &[u8; 32]) -> Result<Option<Receipt>> {
        let path = self.receipt_path(platform);
        if !path.exists() {
            return Ok(None);
        }
        let receipt = open_receipt(&fs::read(&path).map_err(|e| io(&path, e))?, key)?;
        if receipt.platform_id != platform {
            return Err(Error::Transaction(
                "receipt does not belong to the requested platform".into(),
            ));
        }
        Ok(Some(receipt))
    }
}

fn execute_ops(state_dir: &Path, platform: &str, ops: Vec<Op>) -> Result<()> {
    let backup = state_dir.join("backups").join(platform).join(format!(
        "run-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    fs::create_dir_all(&backup).map_err(|e| io(&backup, e))?;
    let mut done: Vec<(PathBuf, Saved)> = Vec::new();
    for (index, op) in ops.iter().enumerate() {
        let path = match op {
            Op::File { path, .. } | Op::Dir { path, .. } | Op::Remove { path } => path,
        };
        let saved = if path.is_file() && !path.is_symlink() {
            match fs::read(path) {
                Ok(bytes) => Saved::Bytes(bytes),
                Err(error) => {
                    let rollback_error = rollback(done).err();
                    let _ = fs::remove_dir_all(&backup);
                    return Err(transaction_error(io(path, error), rollback_error));
                }
            }
        } else if exists(path) {
            let saved = backup.join(index.to_string());
            if let Err(error) = copy_any(path, &saved) {
                let rollback_error = rollback(done).err();
                let _ = fs::remove_dir_all(&backup);
                return Err(transaction_error(error, rollback_error));
            }
            Saved::Disk(saved)
        } else {
            Saved::Missing
        };
        let result = match op {
            Op::File { path, bytes } => atomic(path, bytes),
            Op::Dir {
                path,
                source,
                marker,
            } => {
                if exists(path) {
                    remove_any(path)
                        .and_then(|()| copy_dir(source, path))
                        .and_then(|()| atomic(&path.join(SKILL_OWNER_FILE), marker))
                } else {
                    copy_dir(source, path)
                        .and_then(|()| atomic(&path.join(SKILL_OWNER_FILE), marker))
                }
            }
            Op::Remove { path } => remove_any(path),
        };
        if let Err(error) = result {
            done.push((path.clone(), saved));
            let rollback_error = rollback(done).err();
            let _ = fs::remove_dir_all(&backup);
            return Err(transaction_error(error, rollback_error));
        }
        done.push((path.clone(), saved));
    }
    // Directory backups contain only synchronized Skills or links. Secret-bearing
    // files and the encrypted receipt are kept in memory for rollback.
    let _ = fs::remove_dir_all(&backup);
    Ok(())
}

fn project(
    i: &AgentInstall,
    m: &ConnectionManifest,
    p: &Provisioning,
    b: &Secret,
    model: &str,
    provider: &str,
    projection_bases: &BTreeMap<PathBuf, Vec<u8>>,
) -> Result<Vec<FileProjection>> {
    let base = m.gateway.base_url.as_str().trim_end_matches('/');
    let openai_base = openai_api_base(&m.gateway.base_url);
    let mut out = Vec::new();
    let mcps: Vec<_> = p
        .mcp_servers
        .iter()
        .map(|x| (owned(&m.platform.id, "mcp", &x.id), x))
        .collect();
    match i.agent {
        AgentId::Claude => {
            let current_settings = i.root.join("settings.json");
            let legacy_settings = i.root.join("claude.json");
            let settings = if !current_settings.exists() && legacy_settings.exists() {
                legacy_settings
            } else {
                current_settings
            };
            let mut v = read_json_projection(&settings, false, projection_bases)?;
            let env = obj(&mut v, "env")?;
            for (k, val) in [
                ("ANTHROPIC_BASE_URL", base),
                ("ANTHROPIC_AUTH_TOKEN", b.expose()),
                ("ANTHROPIC_MODEL", model),
            ] {
                env.insert(k.into(), json!(val));
            }
            out.push(file(settings, v, vec!["env.ANTHROPIC_*".into()])?);
            let path = if i.root.file_name().and_then(|name| name.to_str()) == Some(".claude") {
                i.root.parent().unwrap_or(&i.root).join(".claude.json")
            } else {
                i.root.join(".claude.json")
            };
            let mut v = read_json_projection(&path, false, projection_bases)?;
            let map = obj(&mut v, "mcpServers")?;
            for (id, x) in mcps {
                insert_json_owned(
                    map,
                    id,
                    json!({"type":"http","url":x.url,"headers":{"Authorization":format!("Bearer {}",b.expose())}}),
                    &path,
                )?;
            }
            out.push(file(path, v, vec!["mcpServers".into()])?)
        }
        AgentId::Gemini => {
            let ep = i.root.join(".env");
            let text = read_text_projection(&ep, projection_bases)?;
            let env = merge_env(
                &text,
                &[
                    ("GOOGLE_GEMINI_BASE_URL", base),
                    ("GEMINI_API_KEY", b.expose()),
                    ("GEMINI_MODEL", model),
                ],
            );
            out.push((ep, env.into_bytes(), vec!["managed Gemini env keys".into()]));
            let path = i.root.join("settings.json");
            let mut v = read_json_projection(&path, false, projection_bases)?;
            obj(&mut v, "security")?
                .insert("auth".into(), json!({"selectedType":"gemini-api-key"}));
            if !v.get("model").is_some_and(Value::is_object) {
                v["model"] = json!({});
            }
            obj(&mut v, "model")?.insert("name".into(), json!(model));
            let map = obj(&mut v, "mcpServers")?;
            for (id, x) in mcps {
                insert_json_owned(
                    map,
                    id,
                    json!({"httpUrl":x.url,"headers":{"Authorization":format!("Bearer {}",b.expose())}}),
                    &path,
                )?;
            }
            out.push(file(
                path,
                v,
                vec!["security.auth".into(), "mcpServers".into()],
            )?)
        }
        AgentId::Opencode => {
            let json = i.root.join("opencode.json");
            let jsonc = i.root.join("opencode.jsonc");
            let path = if !json.exists() && jsonc.exists() {
                jsonc
            } else {
                json
            };
            let mut v = read_json_projection(&path, true, projection_bases)?;
            let catalog: Map<String, Value> = p
                .models
                .iter()
                .filter(|model| model.chat_capable)
                .map(|x| (x.id.clone(), json!({"name":x.id})))
                .collect();
            v["model"] = json!(format!("{provider}/{model}"));
            insert_json_owned(
                obj(&mut v, "provider")?,
                provider.into(),
                json!({"npm":"@ai-sdk/openai-compatible","options":{"baseURL":openai_base.as_str(),"apiKey":b.expose()},"models":catalog}),
                &path,
            )?;
            let map = obj(&mut v, "mcp")?;
            for (id, x) in mcps {
                insert_json_owned(
                    map,
                    id,
                    json!({"type":"remote","url":x.url,"headers":{"Authorization":format!("Bearer {}",b.expose())}}),
                    &path,
                )?;
            }
            out.push(file(path, v, vec![provider.into(), "mcp".into()])?)
        }
        AgentId::Codex | AgentId::Grokbuild => {
            let path = i.root.join("config.toml");
            let mut d = read_toml_projection(&path, projection_bases)?;
            if i.agent == AgentId::Codex {
                d["model"] = value(model);
                d["model_provider"] = value(provider);
                ensure_table(&mut d, "model_providers");
                reject_toml_collision(&d, "model_providers", provider, &path)?;
                let mut t = Table::new();
                t["name"] = value(&m.platform.name);
                t["base_url"] = value(openai_base.as_str());
                t["wire_api"] = value("responses");
                t["experimental_bearer_token"] = value(b.expose());
                d["model_providers"][provider] = Item::Table(t);
            } else {
                ensure_table(&mut d, "models");
                d["models"]["default"] = value(provider);
                ensure_table(&mut d, "model");
                reject_toml_collision(&d, "model", provider, &path)?;
                let mut t = Table::new();
                t["model"] = value(model);
                t["base_url"] = value(openai_base.as_str());
                t["name"] = value(&m.platform.name);
                t["api_key"] = value(b.expose());
                t["api_backend"] = value("responses");
                d["model"][provider] = Item::Table(t);
            }
            ensure_table(&mut d, "mcp_servers");
            for (id, x) in mcps {
                reject_toml_collision(&d, "mcp_servers", &id, &path)?;
                let mut t = Table::new();
                t["url"] = value(x.url.as_str());
                let mut h = Table::new();
                h["Authorization"] = value(format!("Bearer {}", b.expose()));
                t[if i.agent == AgentId::Codex {
                    "http_headers"
                } else {
                    "headers"
                }] = Item::Table(h);
                d["mcp_servers"][&id] = Item::Table(t);
            }
            out.push((
                path,
                d.to_string().into_bytes(),
                vec![provider.into(), "mcp_servers".into()],
            ));
        }
    }
    Ok(out)
}

fn openai_api_base(gateway: &url::Url) -> String {
    let mut base = gateway.clone();
    let path = base.path().trim_end_matches('/');
    let path = if path.ends_with("/v1/models") {
        path.strip_suffix("/models")
            .expect("suffix checked")
            .to_owned()
    } else if path.ends_with("/v1") {
        path.to_owned()
    } else {
        format!("{path}/v1")
    };
    base.set_path(&path);
    base.to_string().trim_end_matches('/').to_owned()
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::openai_api_base;

    #[test]
    fn normalizes_openai_api_base_without_duplicate_v1() {
        for (input, expected) in [
            ("https://gateway.example", "https://gateway.example/v1"),
            (
                "https://gateway.example/nested",
                "https://gateway.example/nested/v1",
            ),
            ("https://gateway.example/v1", "https://gateway.example/v1"),
            (
                "https://gateway.example/v1/models",
                "https://gateway.example/v1",
            ),
        ] {
            assert_eq!(
                openai_api_base(&input.parse().expect("test URL must parse")),
                expected
            );
        }
    }
}
fn receipt_key(secret: &Secret) -> Result<[u8; 32]> {
    let mut key = [0; 32];
    Hkdf::<Sha256>::new(
        Some(b"Gateway Connector receipt v2"),
        secret.expose().as_bytes(),
    )
    .expand(b"authenticated receipt", &mut key)
    .map_err(|_| Error::Transaction("could not derive receipt key".into()))?;
    Ok(key)
}
fn seal_receipt(receipt: &Receipt, key: &[u8; 32]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let plain = serde_json::to_vec(receipt).map_err(|e| Error::Transaction(e.to_string()))?;
    let ciphertext = cipher
        .encrypt(&nonce, plain.as_ref())
        .map_err(|_| Error::Transaction("receipt encryption failed".into()))?;
    serde_json::to_vec(&SealedReceipt {
        nonce: nonce.to_vec(),
        ciphertext,
    })
    .map_err(|e| Error::Transaction(e.to_string()))
}
fn ownership_marker() -> Vec<u8> {
    Aes256Gcm::generate_nonce(&mut OsRng).to_vec()
}
fn open_receipt(bytes: &[u8], key: &[u8; 32]) -> Result<Receipt> {
    let sealed: SealedReceipt = serde_json::from_slice(bytes)
        .map_err(|e| Error::Transaction(format!("invalid sealed receipt: {e}")))?;
    if sealed.nonce.len() != 12 {
        return Err(Error::Transaction("invalid receipt nonce".into()));
    }
    let cipher = Aes256Gcm::new(key.into());
    let nonce = aes_gcm::Nonce::from_slice(&sealed.nonce);
    let plain = cipher
        .decrypt(nonce, sealed.ciphertext.as_ref())
        .map_err(|_| Error::Transaction("receipt authentication failed".into()))?;
    serde_json::from_slice(&plain).map_err(|e| Error::Transaction(e.to_string()))
}
fn skill_matches(skill: &SkillReceipt) -> bool {
    matches!(skill.kind, SkillKind::Directory)
        && skill.path.is_dir()
        && !is_symlink(&skill.path)
        && fs::read(skill.path.join(SKILL_OWNER_FILE)).ok().as_deref()
            == Some(skill.marker.as_slice())
        && hash_skill_content(&skill.path).is_ok_and(|hash| hash == skill.applied_hash)
}
fn reconciled_file(file: &FileReceipt) -> Result<Option<Vec<u8>>> {
    let current = match fs::read(&file.path) {
        Ok(v) => v,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io(&file.path, error)),
    };
    if current == file.applied {
        return Ok(file.original.clone());
    }
    if file.original.as_deref() == Some(current.as_slice()) {
        return Ok(Some(current));
    }
    let original = file.original.as_deref().unwrap_or(b"{}");
    if matches!(
        file.path.extension().and_then(|x| x.to_str()),
        Some("json" | "jsonc")
    ) {
        let mut cur: Value =
            json5::from_str(std::str::from_utf8(&current).unwrap_or("")).map_err(|e| {
                Error::Config {
                    path: file.path.clone(),
                    message: e.to_string(),
                }
            })?;
        let old: Value = json5::from_str(std::str::from_utf8(original).unwrap_or("{}"))
            .unwrap_or_else(|_| json!({}));
        let applied: Value =
            serde_json::from_slice(&file.applied).map_err(|e| Error::Transaction(e.to_string()))?;
        if json_managed_drift(&cur, Some(&old), &applied) {
            return Err(Error::Validation(format!(
                "managed configuration has local changes: {}",
                file.path.display()
            )));
        }
        reconcile_json(&mut cur, Some(&old), &applied);
        return serde_json::to_vec_pretty(&cur)
            .map(Some)
            .map_err(|e| Error::Transaction(e.to_string()));
    }
    // Text, env, and TOML projections cannot be three-way merged without
    // risking an old bearer. Keep the receipt and credential recoverable until
    // the user restores or removes the managed values.
    Err(Error::Validation(format!(
        "managed configuration has local changes: {}",
        file.path.display()
    )))
}
fn json_managed_drift(current: &Value, original: Option<&Value>, applied: &Value) -> bool {
    let (Some(cur), Some(app)) = (current.as_object(), applied.as_object()) else {
        return current != applied && Some(current) != original;
    };
    let old = original.and_then(Value::as_object);
    app.iter().any(|(key, applied_value)| {
        let current_value = cur.get(key);
        let old_value = old.and_then(|value| value.get(key));
        if old_value == Some(applied_value)
            || current_value == Some(applied_value)
            || current_value == old_value
        {
            false
        } else {
            match (current_value, old_value) {
                (Some(current), Some(original)) => {
                    json_managed_drift(current, Some(original), applied_value)
                }
                (Some(current), None) => json_managed_drift(current, None, applied_value),
                (None, _) => false,
            }
        }
    })
}
fn reconcile_json(current: &mut Value, original: Option<&Value>, applied: &Value) {
    let (Some(cur), Some(app)) = (current.as_object_mut(), applied.as_object()) else {
        return;
    };
    let old = original.and_then(Value::as_object);
    for (key, applied_value) in app {
        let old_value = old.and_then(|o| o.get(key));
        if old_value == Some(applied_value) {
            continue;
        }
        if cur.get(key) == Some(applied_value) {
            match old_value {
                Some(v) => {
                    cur.insert(key.clone(), v.clone());
                }
                None => {
                    cur.remove(key);
                }
            }
        } else if let Some(value) = cur.get_mut(key) {
            reconcile_json(value, old_value, applied_value);
        }
    }
}
fn transaction_error(error: Error, rollback: Option<Error>) -> Error {
    match rollback {
        Some(r) => Error::Transaction(format!("{error}; rollback also failed: {r}")),
        None => Error::Transaction(error.to_string()),
    }
}
fn rollback(done: Vec<(PathBuf, Saved)>) -> Result<()> {
    let mut failures = Vec::new();
    for (path, saved) in done.into_iter().rev() {
        if let Err(e) = remove_any(&path) {
            failures.push(e.to_string());
        }
        let result = match saved {
            Saved::Missing => Ok(()),
            Saved::Bytes(bytes) => atomic(&path, &bytes),
            Saved::Disk(saved) => copy_any(&saved, &path),
        };
        if let Err(e) = result {
            failures.push(e.to_string());
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(Error::Transaction(failures.join("; ")))
    }
}
fn owned(platform: &str, kind: &str, id: &str) -> String {
    let mut hash = Sha256::new();
    for value in [platform, kind, id] {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value.as_bytes());
    }
    format!("connector-{kind}-{:x}", hash.finalize())
}
fn lease_key(lease: &ProjectionLease) -> String {
    format!(
        "{}:{}",
        lease.agent,
        lease
            .root
            .to_string_lossy()
            .replace('\\', "/")
            .to_lowercase()
    )
}
fn claim_path(paths: &mut BTreeSet<String>, path: &Path) -> Result<()> {
    // Conservatively case-fold on every platform so a plan prepared on Linux
    // cannot become colliding when the same roots are used on Windows/macOS.
    let key = path.to_string_lossy().to_lowercase();
    if paths.insert(key) {
        Ok(())
    } else {
        Err(Error::Validation(format!(
            "multiple Agent projections resolve to the same path: {}",
            path.display()
        )))
    }
}
fn snapshot_file(path: &Path) -> Result<Option<String>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(hash_bytes(&bytes))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(io(path, error)),
    }
}
fn snapshot_skill(path: &Path) -> Result<Option<Vec<u8>>> {
    if exists(path) {
        hash_dir(path).map(Some)
    } else {
        Ok(None)
    }
}
fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink())
}
fn read_text_projection(path: &Path, bases: &BTreeMap<PathBuf, Vec<u8>>) -> Result<String> {
    match bases.get(path) {
        Some(bytes) => String::from_utf8(bytes.clone()).map_err(|error| Error::Config {
            path: path.into(),
            message: error.to_string(),
        }),
        None if path.exists() => fs::read_to_string(path).map_err(|error| io(path, error)),
        None => Ok(String::new()),
    }
}
fn read_json_projection(
    path: &Path,
    json5_ok: bool,
    bases: &BTreeMap<PathBuf, Vec<u8>>,
) -> Result<Value> {
    let s = read_text_projection(path, bases)?;
    if s.trim().is_empty() {
        return Ok(json!({}));
    }
    if json5_ok {
        json5::from_str(&s).map_err(|e| Error::Config {
            path: path.into(),
            message: e.to_string(),
        })
    } else {
        serde_json::from_str(&s).map_err(|e| Error::Config {
            path: path.into(),
            message: e.to_string(),
        })
    }
}
fn read_toml_projection(path: &Path, bases: &BTreeMap<PathBuf, Vec<u8>>) -> Result<DocumentMut> {
    let s = read_text_projection(path, bases)?;
    if s.trim().is_empty() {
        Ok(DocumentMut::new())
    } else {
        s.parse::<DocumentMut>().map_err(|e| Error::Config {
            path: path.into(),
            message: e.to_string(),
        })
    }
}
fn ensure_table(doc: &mut DocumentMut, key: &str) {
    if !doc.get(key).is_some_and(Item::is_table) {
        doc[key] = Item::Table(Table::new());
    }
}
fn obj<'a>(v: &'a mut Value, key: &str) -> Result<&'a mut Map<String, Value>> {
    if v.get(key).is_none() {
        v[key] = json!({});
    }
    v.get_mut(key)
        .and_then(Value::as_object_mut)
        .ok_or_else(|| Error::Validation(format!("{key} must be an object")))
}
fn insert_json_owned(
    map: &mut Map<String, Value>,
    key: String,
    value: Value,
    path: &Path,
) -> Result<()> {
    if map.contains_key(&key) {
        return Err(Error::Validation(format!(
            "managed entry collides with unknown configuration in {}",
            path.display()
        )));
    }
    map.insert(key, value);
    Ok(())
}
fn reject_toml_collision(
    document: &DocumentMut,
    table: &str,
    key: &str,
    path: &Path,
) -> Result<()> {
    if document
        .get(table)
        .and_then(Item::as_table)
        .is_some_and(|value| value.contains_key(key))
    {
        Err(Error::Validation(format!(
            "managed entry collides with unknown configuration in {}",
            path.display()
        )))
    } else {
        Ok(())
    }
}
fn file(path: PathBuf, v: Value, e: Vec<String>) -> Result<(PathBuf, Vec<u8>, Vec<String>)> {
    Ok((
        path,
        serde_json::to_vec_pretty(&v).map_err(|x| Error::Transaction(x.to_string()))?,
        e,
    ))
}
fn merge_env(old: &str, items: &[(&str, &str)]) -> String {
    let mut lines: Vec<String> = old
        .lines()
        .filter(|l| !items.iter().any(|(k, _)| l.starts_with(&format!("{k}="))))
        .map(str::to_owned)
        .collect();
    lines.extend(
        items
            .iter()
            .map(|(key, value)| format!("{key}={}", dotenv_value(value))),
    );
    lines.join("\n") + "\n"
}
fn dotenv_value(value: &str) -> String {
    format!(
        "\"{}\"",
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('$', "\\$")
    )
}
#[cfg_attr(windows, allow(unsafe_code))]
fn atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| Error::Transaction("path has no parent".into()))?;
    fs::create_dir_all(parent).map_err(|e| io(parent, e))?;
    let temp = parent.join(format!(
        ".connector-{}-{}.tmp",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let write = (|| -> std::io::Result<()> {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temp)?;
            file.write_all(bytes)?;
            file.sync_all()
        })();
        if let Err(error) = write {
            let _ = fs::remove_file(&temp);
            return Err(io(&temp, error));
        }
    }
    #[cfg(not(unix))]
    {
        if let Err(error) = fs::write(&temp, bytes) {
            let _ = fs::remove_file(&temp);
            return Err(io(&temp, error));
        }
    }
    #[cfg(not(windows))]
    {
        match fs::rename(&temp, path) {
            Ok(()) => Ok(()),
            Err(error) => {
                let _ = fs::remove_file(&temp);
                Err(io(path, error))
            }
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::{
            MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
        };
        let from: Vec<u16> = temp.as_os_str().encode_wide().chain(Some(0)).collect();
        let to: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        // MoveFileExW replaces in-place without a remove/rename visibility gap.
        if unsafe {
            MoveFileExW(
                from.as_ptr(),
                to.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            let error = std::io::Error::last_os_error();
            let _ = fs::remove_file(&temp);
            Err(io(path, error))
        } else {
            Ok(())
        }
    }
}
fn remove_any(p: &Path) -> Result<()> {
    if !exists(p) {
        return Ok(());
    }
    if fs::symlink_metadata(p)
        .map_err(|e| io(p, e))?
        .file_type()
        .is_symlink()
    {
        remove_symlink(p)
    } else if p.is_dir() {
        fs::remove_dir_all(p)
    } else {
        fs::remove_file(p)
    }
    .map_err(|e| io(p, e))
}

#[cfg(unix)]
fn remove_symlink(path: &Path) -> std::io::Result<()> {
    fs::remove_file(path)
}

#[cfg(windows)]
fn remove_symlink(path: &Path) -> std::io::Result<()> {
    if path.is_dir() {
        fs::remove_dir(path)
    } else {
        fs::remove_file(path)
    }
}
fn copy_any(a: &Path, b: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(a).map_err(|e| io(a, e))?;
    if metadata.file_type().is_symlink() {
        let target = fs::read_link(a).map_err(|e| io(a, e))?;
        create_symlink(&target, b)
    } else if a.is_dir() {
        copy_dir(a, b)
    } else {
        if let Some(p) = b.parent() {
            fs::create_dir_all(p).map_err(|e| io(p, e))?;
        }
        fs::copy(a, b).map(|_| ()).map_err(|e| io(b, e))
    }
}
fn exists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

#[cfg(unix)]
fn create_symlink(source: &Path, target: &Path) -> Result<()> {
    std::os::unix::fs::symlink(source, target).map_err(|e| io(target, e))
}
#[cfg(windows)]
fn create_symlink(source: &Path, target: &Path) -> Result<()> {
    std::os::windows::fs::symlink_dir(source, target).map_err(|e| io(target, e))
}
fn hash_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn copy_dir(a: &Path, b: &Path) -> Result<()> {
    fs::create_dir_all(b).map_err(|e| io(b, e))?;
    for x in fs::read_dir(a).map_err(|e| io(a, e))? {
        let x = x.map_err(|e| io(a, e))?;
        copy_any(&x.path(), &b.join(x.file_name()))?;
    }
    Ok(())
}
fn hash_dir(path: &Path) -> Result<Vec<u8>> {
    hash_tree(path, false)
}
fn hash_skill_content(path: &Path) -> Result<Vec<u8>> {
    hash_tree(path, true)
}
fn hash_tree(p: &Path, skip_owner: bool) -> Result<Vec<u8>> {
    type Entry = (Vec<u8>, u8, bool, Vec<u8>);
    let mut entries = Vec::new();
    fn walk(base: &Path, directory: &Path, skip_owner: bool, out: &mut Vec<Entry>) -> Result<()> {
        for entry in fs::read_dir(directory).map_err(|error| io(directory, error))? {
            let entry = entry.map_err(|error| io(directory, error))?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(|error| io(&path, error))?;
            let relative = path
                .strip_prefix(base)
                .map_err(|_| Error::Transaction("invalid Skill tree path".into()))?;
            if skip_owner && relative == Path::new(SKILL_OWNER_FILE) {
                continue;
            }
            let name = os_bytes(relative.as_os_str());
            if metadata.file_type().is_symlink() {
                let target = fs::read_link(&path).map_err(|error| io(&path, error))?;
                out.push((name, b'L', false, os_bytes(target.as_os_str())));
            } else if metadata.is_dir() {
                out.push((name, b'D', false, Vec::new()));
                walk(base, &path, skip_owner, out)?;
            } else if metadata.is_file() {
                out.push((
                    name,
                    b'F',
                    executable(&metadata),
                    fs::read(&path).map_err(|error| io(&path, error))?,
                ));
            } else {
                return Err(Error::Validation(format!(
                    "unsupported entry in synchronized Skill: {}",
                    path.display()
                )));
            }
        }
        Ok(())
    }
    walk(p, p, skip_owner, &mut entries)?;
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let mut h = Sha256::new();
    h.update((entries.len() as u64).to_be_bytes());
    for (path, kind, executable, payload) in entries {
        h.update([kind]);
        h.update([u8::from(executable)]);
        h.update((path.len() as u64).to_be_bytes());
        h.update(path);
        h.update((payload.len() as u64).to_be_bytes());
        h.update(payload);
    }
    Ok(h.finalize().to_vec())
}

#[cfg(unix)]
fn executable(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(windows)]
fn executable(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(unix)]
fn os_bytes(value: &std::ffi::OsStr) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    value.as_bytes().to_vec()
}

#[cfg(windows)]
fn os_bytes(value: &std::ffi::OsStr) -> Vec<u8> {
    use std::os::windows::ffi::OsStrExt;
    value
        .encode_wide()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>()
}
