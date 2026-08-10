//! Testable application state kept independent from GPUI rendering.

use gateway_connector_backend::{ConnectionResult, ModelDescriptor};
use gateway_connector_core::{AgentId, ConnectionProfile, Protocol};

#[derive(Debug, Clone, Default)]
pub enum AppState {
    #[default]
    Loading,
    FirstRun,
    Connecting,
    Connected {
        profile: Box<ConnectionProfile>,
        models: Vec<ModelDescriptor>,
        preview: Option<Vec<String>>,
    },
    Failed(String),
}

impl AppState {
    pub fn connected(result: ConnectionResult) -> Self {
        Self::Connected {
            profile: Box::new(result.profile),
            models: result.models,
            preview: None,
        }
    }

    pub fn update_protocol(&mut self, agent: AgentId, protocol: Protocol) {
        if let Self::Connected {
            profile, preview, ..
        } = self
            && let Some(selection) = profile.agents.get_mut(&agent)
        {
            selection.protocol = protocol;
            *preview = None;
        }
    }

    pub fn update_model(&mut self, agent: AgentId, model: String) {
        if let Self::Connected {
            profile, preview, ..
        } = self
            && let Some(selection) = profile.agents.get_mut(&agent)
        {
            selection.default_model = Some(model);
            *preview = None;
        }
    }

    pub fn preview(&mut self) -> Option<&[String]> {
        let Self::Connected {
            profile, preview, ..
        } = self
        else {
            return None;
        };
        *preview = Some(
            AgentId::ALL
                .into_iter()
                .map(|agent| {
                    let selection = &profile.agents[&agent];
                    format!(
                        "{}: {} / {}",
                        agent.display_name(),
                        selection.protocol.display_name(),
                        selection
                            .default_model
                            .as_deref()
                            .unwrap_or("No model selected")
                    )
                })
                .collect(),
        );
        preview.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gateway_connector_core::CanonicalBaseUrl;

    #[test]
    fn selection_invalidates_preview() {
        let profile = ConnectionProfile::new(
            "Test",
            CanonicalBaseUrl::parse("https://example.com").expect("URL"),
            Protocol::Auto,
        )
        .expect("profile");
        let mut state = AppState::Connected {
            profile: Box::new(profile),
            models: Vec::new(),
            preview: None,
        };
        assert_eq!(state.preview().expect("preview").len(), 5);
        state.update_protocol(AgentId::Codex, Protocol::OpenaiResponses);
        state.update_model(AgentId::Codex, "model-a".to_owned());
        let AppState::Connected { preview, .. } = state else {
            panic!("connected state")
        };
        assert!(preview.is_none());
    }
}
