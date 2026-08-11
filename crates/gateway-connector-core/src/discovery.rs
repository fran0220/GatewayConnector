use crate::AgentId;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone)]
pub struct AgentInstall {
    pub agent: AgentId,
    pub root: PathBuf,
    pub detected: bool,
}
#[derive(Debug, Default, Clone)]
pub struct Discovery {
    pub overrides: BTreeMap<AgentId, PathBuf>,
}

/// Complete fixed roots for portable acceptance and embedded fixture layouts.
/// Unlike [`Discovery`], this type has no environment or home-directory fallback.
#[derive(Debug, Clone)]
pub struct FixedAgentRoots {
    roots: BTreeMap<AgentId, PathBuf>,
}

impl FixedAgentRoots {
    pub fn new(roots: [PathBuf; 5]) -> Self {
        Self {
            roots: AgentId::ALL.into_iter().zip(roots).collect(),
        }
    }

    pub fn discover(&self) -> Vec<AgentInstall> {
        AgentId::ALL
            .into_iter()
            .map(|agent| {
                let root = self
                    .roots
                    .get(&agent)
                    .expect("fixed roots contain every supported Agent")
                    .clone();
                let detected = fs::symlink_metadata(&root)
                    .is_ok_and(|metadata| metadata.is_dir() && !is_reparse(&metadata));
                AgentInstall {
                    detected,
                    agent,
                    root,
                }
            })
            .collect()
    }

    pub fn root(&self, agent: AgentId) -> &Path {
        self.roots
            .get(&agent)
            .expect("fixed roots contain every supported Agent")
    }
}

impl Discovery {
    pub fn discover(&self, home: &Path) -> Vec<AgentInstall> {
        self.discover_with(home, |key| std::env::var_os(key).map(PathBuf::from))
    }

    /// Environment lookup is injectable so discovery can be tested without
    /// mutating process-global environment variables.
    pub fn discover_with(
        &self,
        home: &Path,
        env: impl Fn(&str) -> Option<PathBuf>,
    ) -> Vec<AgentInstall> {
        [
            AgentId::Claude,
            AgentId::Codex,
            AgentId::Gemini,
            AgentId::Grokbuild,
            AgentId::Opencode,
        ]
        .into_iter()
        .map(|agent| {
            let root = self
                .overrides
                .get(&agent)
                .cloned()
                .or_else(|| env_path(agent, &env))
                .unwrap_or_else(|| standard(agent, home));
            AgentInstall {
                agent,
                detected: root.exists(),
                root,
            }
        })
        .collect()
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

fn env_path(agent: AgentId, env: &impl Fn(&str) -> Option<PathBuf>) -> Option<PathBuf> {
    let key = match agent {
        AgentId::Codex => Some("CODEX_HOME"),
        AgentId::Grokbuild => Some("GROK_HOME"),
        AgentId::Opencode => Some("XDG_CONFIG_HOME"),
        _ => None,
    };
    key.and_then(env)
        .filter(|v| !v.as_os_str().is_empty())
        .map(|p| {
            if agent == AgentId::Opencode {
                p.join("opencode")
            } else {
                p
            }
        })
}
fn standard(agent: AgentId, home: &Path) -> PathBuf {
    match agent {
        AgentId::Claude => home.join(".claude"),
        AgentId::Codex => home.join(".codex"),
        AgentId::Gemini => home.join(".gemini"),
        AgentId::Grokbuild => home.join(".grok"),
        AgentId::Opencode => home.join(".config/opencode"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_roots_have_no_environment_or_home_fallback() {
        let temporary = tempfile::tempdir().expect("temporary root");
        let roots = AgentId::ALL.map(|agent| temporary.path().join(agent.as_str()));
        let discovery = FixedAgentRoots::new(roots.clone());
        let installs = discovery.discover();
        assert_eq!(installs.len(), AgentId::ALL.len());
        for (install, expected) in installs.iter().zip(roots) {
            assert_eq!(install.root, expected);
        }
    }
}
