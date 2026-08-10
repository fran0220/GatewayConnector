use crate::AgentId;
use std::{
    collections::BTreeMap,
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
