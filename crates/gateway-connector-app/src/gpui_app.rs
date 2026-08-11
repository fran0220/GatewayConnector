use std::sync::Arc;

use crate::{
    AppState, Page, QueryStatus,
    preferences::{Locale, PreferenceStore, Preferences, ThemePreference},
};
use directories::{ProjectDirs, UserDirs};
use gateway_connector_backend::{
    ApiKey, BackendError, BrowserLoginOffer, ConnectRequest, ConnectRequestWithoutCredential,
    ConnectionResult, ConnectorBackend, Distribution, JsonProfileStore, ModelCapability,
    OsCredentialStore, ProbeResult, SystemBrowser,
};
use gateway_connector_core::{AgentId, CanonicalBaseUrl, ChangeKind, ConnectionProfile, Protocol};
use gpui::{
    App, AssetSource, Bounds, Context, Entity, FontWeight, IntoElement, ParentElement, Render,
    Styled, TitlebarOptions, Window, WindowAppearance, WindowBounds, WindowOptions, div,
    prelude::*, px, size,
};
use gpui_kit::{assets::Icon, prelude::*};
use zeroize::Zeroize;

enum ConnectOutcome {
    Connected(Box<ConnectionResult>),
    Browser(Box<BrowserLoginOffer>),
    Failed(String),
}

struct ConnectorView {
    backend: Arc<ConnectorBackend>,
    distribution: &'static Distribution,
    state: AppState,
    page: Page,
    preference_store: PreferenceStore,
    preferences: Preferences,
    language_select: Entity<Select>,
    theme_select: Entity<Select>,
    gateway_url: Entity<TextInput>,
    api_key: Entity<TextInput>,
    model_search: Entity<TextInput>,
    model_query: String,
    plaza_search: Entity<TextInput>,
    plaza_query: String,
    initial_protocol: Entity<Select>,
    all_model: Entity<Select>,
    all_protocol: Entity<Select>,
    model_selects: Vec<(AgentId, Entity<Select>)>,
    protocol_selects: Vec<(AgentId, Entity<Select>)>,
    save_in_flight: bool,
    pending_save: Option<ConnectionProfile>,
    save_error: Option<String>,
    projection_busy: bool,
    action_error: Option<String>,
}

impl ConnectorView {
    fn new(
        backend: Arc<ConnectorBackend>,
        distribution: &'static Distribution,
        preference_store: PreferenceStore,
        preferences: Preferences,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let locale = preferences.locale;
        let language_select = cx.new(|cx| {
            Select::new("connector.language", window, cx)
                .name(locale.text("Language"))
                .options(locale_options(distribution))
                .selected(locale.id())
        });
        let theme_select = cx.new(|cx| {
            Select::new("connector.theme", window, cx)
                .name(locale.text("Theme"))
                .options(
                    ThemePreference::ALL
                        .map(|value| SelectOption::new(value.id(), value.display_name(locale))),
                )
                .selected(preferences.theme.id())
        });
        let gateway_url = cx.new(|cx| {
            let mut input = TextInput::new("connector.gateway-url", window, cx)
                .name(locale.text("Gateway base URL"))
                .placeholder("https://gateway.example.com or https://gateway.example.com/v1")
                .required(true);
            input.set_text_quietly(distribution.default_gateway_url.unwrap_or_default(), cx);
            input.set_disabled(!distribution.allow_custom_urls, cx);
            input
        });
        let api_key = cx.new(|cx| {
            TextInput::new("connector.api-key", window, cx)
                .name(locale.text("API key"))
                .placeholder("API key, or leave blank for advertised browser login")
                .secret(true)
        });
        let initial_protocol =
            cx.new(|cx| protocol_select("connector.initial-protocol", window, cx));
        let model_search = cx.new(|cx| {
            TextInput::new("connector.model-search", window, cx)
                .name(locale.text("Search model catalog"))
                .placeholder("Filter by model ID or provider")
        });
        let plaza_search = cx.new(|cx| {
            TextInput::new("connector.model-plaza.search", window, cx)
                .name(locale.text("Search model catalog"))
                .placeholder("Filter by model ID, provider, or tag")
        });
        let all_model = cx.new(|cx| {
            Select::new("connector.all.model", window, cx)
                .name("All Agent models")
                .placeholder("Choose one model for all Agents")
        });
        let all_protocol = cx.new(|cx| protocol_select("connector.all.protocol", window, cx));
        let mut model_selects = Vec::new();
        let mut protocol_selects = Vec::new();
        for agent in AgentId::ALL {
            let model_id = format!("connector.{}.model", agent.as_str());
            model_selects.push((
                agent,
                cx.new(|cx| {
                    Select::new(model_id, window, cx)
                        .name(format!("{} model", agent.display_name()))
                        .placeholder("Choose a model")
                }),
            ));
            let protocol_id = format!("connector.{}.protocol", agent.as_str());
            protocol_selects.push((agent, cx.new(|cx| protocol_select(protocol_id, window, cx))));
        }

        for (agent, select) in &model_selects {
            let agent = *agent;
            cx.subscribe(select, move |this, select, event, cx| {
                if let SelectEvent::Selected(id) = event {
                    select.update(cx, |select, cx| select.set_selected(Some(id.clone()), cx));
                    this.commit_selection(agent, cx);
                }
            })
            .detach();
        }
        for (agent, select) in &protocol_selects {
            let agent = *agent;
            cx.subscribe(select, move |this, select, event, cx| {
                if let SelectEvent::Selected(id) = event {
                    select.update(cx, |select, cx| select.set_selected(Some(id.clone()), cx));
                    if let Ok(protocol) = id.parse() {
                        this.commit_protocol(agent, protocol, cx);
                    }
                }
            })
            .detach();
        }
        cx.subscribe(&initial_protocol, |_this, select, event, cx| {
            if let SelectEvent::Selected(id) = event {
                select.update(cx, |select, cx| select.set_selected(Some(id.clone()), cx));
            }
        })
        .detach();
        cx.subscribe(&model_search, |this, _, event: &TextInputEvent, cx| {
            if let TextInputEvent::Change(value) = event {
                this.model_query = value.to_string();
                this.sync_model_selects(cx);
                cx.notify();
            }
        })
        .detach();
        cx.subscribe(&plaza_search, |this, _, event: &TextInputEvent, cx| {
            if let TextInputEvent::Change(value) = event {
                this.plaza_query = value.to_string();
                cx.notify();
            }
        })
        .detach();
        cx.subscribe(&all_model, |this, select, event, cx| {
            if let SelectEvent::Selected(id) = event {
                select.update(cx, |select, cx| select.set_selected(Some(id.clone()), cx));
                this.use_model_for_all(id.to_string(), cx);
            }
        })
        .detach();
        cx.subscribe(&all_protocol, |this, select, event, cx| {
            if let SelectEvent::Selected(id) = event {
                select.update(cx, |select, cx| select.set_selected(Some(id.clone()), cx));
                if let Ok(protocol) = id.parse() {
                    this.use_protocol_for_all(protocol, cx);
                }
            }
        })
        .detach();
        cx.subscribe(&language_select, |this, _, event, cx| {
            let SelectEvent::Selected(id) = event else {
                return;
            };
            let Some(locale) = Locale::from_id(id) else {
                return;
            };
            let mut preferences = this.preferences.clone();
            preferences.locale = locale;
            if let Err(error) = this.preference_store.save(&preferences) {
                this.action_error = Some(format!(
                    "{}: {error}",
                    this.preferences
                        .locale
                        .text("Preference could not be saved")
                ));
                cx.notify();
                return;
            }
            this.preferences = preferences;
            this.sync_localized_controls(cx);
            cx.notify();
        })
        .detach();
        cx.subscribe(&theme_select, |this, _, event, cx| {
            let SelectEvent::Selected(id) = event else {
                return;
            };
            let Some(theme) = ThemePreference::from_id(id) else {
                return;
            };
            let mut preferences = this.preferences.clone();
            preferences.theme = theme;
            if let Err(error) = this.preference_store.save(&preferences) {
                this.action_error = Some(format!(
                    "{}: {error}",
                    this.preferences
                        .locale
                        .text("Preference could not be saved")
                ));
                cx.notify();
                return;
            }
            this.preferences = preferences;
            apply_theme(theme, cx);
            cx.notify();
        })
        .detach();

        let mut view = Self {
            backend,
            distribution,
            state: AppState::Loading,
            page: Page::Overview,
            preference_store,
            preferences,
            language_select,
            theme_select,
            gateway_url,
            api_key,
            model_search,
            model_query: String::new(),
            plaza_search,
            plaza_query: String::new(),
            initial_protocol,
            all_model,
            all_protocol,
            model_selects,
            protocol_selects,
            save_in_flight: false,
            pending_save: None,
            save_error: None,
            projection_busy: false,
            action_error: None,
        };
        cx.observe_window_appearance(window, |this, window, cx| {
            if this.preferences.theme == ThemePreference::System {
                activate_theme_for(window.appearance(), cx);
            }
        })
        .detach();
        view.begin_resume(cx);
        view
    }

    fn text(&self, english: &'static str) -> &'static str {
        self.preferences.locale.text(english)
    }

    fn sync_localized_controls(&self, cx: &mut Context<Self>) {
        let locale = self.preferences.locale;
        self.language_select.update(cx, |select, cx| {
            select.set_name(locale.text("Language"), cx);
            select.set_options(locale_options(self.distribution), cx);
            select.set_selected(Some(locale.id().into()), cx);
        });
        self.theme_select.update(cx, |select, cx| {
            select.set_name(locale.text("Theme"), cx);
            select.set_options(
                ThemePreference::ALL
                    .map(|value| SelectOption::new(value.id(), value.display_name(locale)))
                    .to_vec(),
                cx,
            );
            select.set_selected(Some(self.preferences.theme.id().into()), cx);
        });
        self.gateway_url.update(cx, |input, cx| {
            input.set_name(locale.text("Gateway base URL"), cx)
        });
        self.api_key
            .update(cx, |input, cx| input.set_name(locale.text("API key"), cx));
        self.model_search.update(cx, |input, cx| {
            input.set_name(locale.text("Search model catalog"), cx)
        });
        self.plaza_search.update(cx, |input, cx| {
            input.set_name(locale.text("Search model catalog"), cx)
        });
    }

    fn begin_resume(&mut self, cx: &mut Context<Self>) {
        let backend = Arc::clone(&self.backend);
        cx.spawn(async move |this, cx| {
            let result = cx
                .background_executor()
                .spawn(async move { backend.resume_saved() })
                .await;
            this.update(cx, |this, cx| {
                match result {
                    Ok(Some(result)) => this.complete_connection(result, cx),
                    Ok(None) => this.state = AppState::FirstRun,
                    Err(error) => this.state = AppState::Failed(error.to_string()),
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn begin_connect(&mut self, cx: &mut Context<Self>) {
        if matches!(self.state, AppState::Connecting) {
            return;
        }
        let base_url = self.gateway_url.read(cx).value().to_string();
        let raw_key = self.api_key.read(cx).value().to_string();
        let protocol = self
            .initial_protocol
            .read(cx)
            .selected_id()
            .and_then(|id| id.parse().ok())
            .unwrap_or(Protocol::Auto);
        let display_name = display_name(&base_url);
        let backend = Arc::clone(&self.backend);
        self.state = AppState::Connecting;
        self.action_error = None;
        cx.notify();
        cx.spawn(async move |this, cx| {
            let result = cx
                .background_executor()
                .spawn(async move {
                    let mut raw_key = raw_key;
                    if raw_key.trim().is_empty() {
                        return match backend.probe(&base_url) {
                            Ok(ProbeResult::Provisioned {
                                manifest_url,
                                manifest,
                                ..
                            }) if manifest.authentication.is_some() => {
                                ConnectOutcome::Browser(Box::new(BrowserLoginOffer {
                                    request: ConnectRequestWithoutCredential {
                                        display_name,
                                        base_url,
                                        protocol,
                                    },
                                    manifest_url,
                                    manifest: *manifest,
                                }))
                            }
                            Ok(_) => ConnectOutcome::Failed(
                                "This Gateway requires an API key; enter it and try again.".into(),
                            ),
                            Err(error) => ConnectOutcome::Failed(error.to_string()),
                        };
                    }
                    let api_key = match ApiKey::new(raw_key.clone()) {
                        Ok(api_key) => api_key,
                        Err(error) => {
                            raw_key.zeroize();
                            return ConnectOutcome::Failed(error.to_string());
                        }
                    };
                    raw_key.zeroize();
                    match backend.connect(ConnectRequest {
                        display_name,
                        base_url,
                        api_key,
                        protocol,
                    }) {
                        Ok(result) => ConnectOutcome::Connected(Box::new(result)),
                        Err(BackendError::BrowserLoginRequired(offer)) => {
                            ConnectOutcome::Browser(offer)
                        }
                        Err(error) => ConnectOutcome::Failed(error.to_string()),
                    }
                })
                .await;
            this.update(cx, |this, cx| {
                this.api_key.update(cx, |input, cx| input.set_value("", cx));
                match result {
                    ConnectOutcome::Connected(result) => this.complete_connection(*result, cx),
                    ConnectOutcome::Browser(offer) => this.state = AppState::BrowserLogin(offer),
                    ConnectOutcome::Failed(error) => this.state = AppState::Failed(error),
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn begin_browser_login(&mut self, cx: &mut Context<Self>) {
        let AppState::BrowserLogin(offer) = &self.state else {
            return;
        };
        let offer = offer.as_ref().clone();
        let retry = offer.clone();
        let backend = Arc::clone(&self.backend);
        self.state = AppState::Connecting;
        self.action_error = None;
        cx.notify();
        cx.spawn(async move |this, cx| {
            let result = cx
                .background_executor()
                .spawn(async move { backend.browser_login(offer) })
                .await;
            this.update(cx, |this, cx| {
                match result {
                    Ok(result) => this.complete_connection(result, cx),
                    Err(error) => {
                        this.state = AppState::BrowserLogin(Box::new(retry));
                        this.action_error = Some(error.to_string());
                    }
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn complete_connection(&mut self, result: ConnectionResult, cx: &mut Context<Self>) {
        for (agent, select) in &self.protocol_selects {
            let selected = result.profile.agents[agent].protocol.as_str();
            select.update(cx, |select, cx| {
                select.set_selected(Some(selected.into()), cx)
            });
        }
        self.api_key.update(cx, |input, cx| input.set_value("", cx));
        self.save_error = None;
        self.action_error = None;
        if !self.page.available(result.provisioning.as_ref()) {
            self.page = Page::Overview;
        }
        self.state = AppState::connected(result);
        self.sync_model_selects(cx);
        self.sync_all_protocol(cx);
        self.begin_projection_status(cx);
    }

    fn sync_model_selects(&self, cx: &mut Context<Self>) {
        let AppState::Connected { connection, .. } = &self.state else {
            return;
        };
        let query = self.model_query.trim().to_ascii_lowercase();
        let options = connection
            .models
            .iter()
            .filter(|model| {
                connection.profile.mode != gateway_connector_core::ConnectionMode::Direct
                    || model.capability != ModelCapability::NonChat
            })
            .filter(|model| {
                query.is_empty()
                    || model.id.to_ascii_lowercase().contains(&query)
                    || model
                        .owned_by
                        .as_ref()
                        .is_some_and(|owner| owner.to_ascii_lowercase().contains(&query))
            })
            .map(|model| {
                let mut option = SelectOption::new(model.id.clone(), model.id.clone());
                let description = match model.capability {
                    ModelCapability::Unknown => {
                        "Unknown chat capability — choosing this model confirms its use".to_owned()
                    }
                    _ => model.owned_by.clone().unwrap_or_default(),
                };
                if !description.is_empty() {
                    option = option.description(description);
                }
                option
            })
            .collect::<Vec<_>>();
        let options_with_selection = |selected: Option<String>| {
            let mut selected_options = options.clone();
            if let Some(selected) = &selected
                && !selected_options
                    .iter()
                    .any(|option| option.id.as_ref() == selected)
            {
                let in_catalog = connection.models.iter().any(|model| &model.id == selected);
                let option = if in_catalog {
                    SelectOption::new(selected.clone(), format!("{selected} (selected)"))
                        .description("Selected model is hidden by the current filter")
                } else {
                    SelectOption::new(selected.clone(), format!("{selected} (unavailable)"))
                        .description("Saved choice is not in the current model catalog")
                        .disabled(true)
                };
                selected_options.push(option);
            }
            (selected_options, selected)
        };
        for (agent, select) in &self.model_selects {
            let selected = connection.profile.agents[agent].default_model.clone();
            let (agent_options, selected) = options_with_selection(selected);
            let disabled = self.projection_busy || agent_options.is_empty();
            select.update(cx, move |select, cx| {
                select.set_options(agent_options, cx);
                select.set_selected(selected.map(Into::into), cx);
                select.set_disabled(disabled, cx);
            });
        }
        let first = connection.profile.agents[&AgentId::Claude]
            .default_model
            .clone();
        let common = AgentId::ALL
            .iter()
            .all(|agent| connection.profile.agents[agent].default_model == first)
            .then_some(first)
            .flatten();
        let (all_options, common) = options_with_selection(common);
        let disabled = self.projection_busy || all_options.is_empty();
        self.all_model.update(cx, move |select, cx| {
            select.set_options(all_options, cx);
            select.set_selected(common.map(Into::into), cx);
            select.set_disabled(disabled, cx);
        });
    }

    fn commit_selection(&mut self, agent: AgentId, cx: &mut Context<Self>) {
        let model = self
            .model_selects
            .iter()
            .find(|(candidate, _)| *candidate == agent)
            .and_then(|(_, select)| select.read(cx).selected_id().cloned())
            .map(|id| id.to_string());
        if let Some(model) = model
            && let Err(error) = self.state.select_model(agent, model)
        {
            self.action_error = Some(error);
            return;
        }
        self.sync_model_selects(cx);
        self.sync_all_protocol(cx);
        self.queue_profile_save(cx);
        cx.notify();
    }

    fn commit_protocol(&mut self, agent: AgentId, protocol: Protocol, cx: &mut Context<Self>) {
        self.state.update_protocol(agent, protocol);
        self.sync_all_protocol(cx);
        self.queue_profile_save(cx);
        cx.notify();
    }

    fn use_model_for_all(&mut self, model: String, cx: &mut Context<Self>) {
        for agent in AgentId::ALL {
            if let Err(error) = self.state.select_model(agent, model.clone()) {
                self.action_error = Some(error);
                return;
            }
        }
        self.sync_model_selects(cx);
        self.queue_profile_save(cx);
        cx.notify();
    }

    fn use_protocol_for_all(&mut self, protocol: Protocol, cx: &mut Context<Self>) {
        for (agent, select) in &self.protocol_selects {
            self.state.update_protocol(*agent, protocol);
            select.update(cx, |select, cx| {
                select.set_selected(Some(protocol.as_str().into()), cx)
            });
        }
        self.sync_all_protocol(cx);
        self.queue_profile_save(cx);
        cx.notify();
    }

    fn sync_all_protocol(&self, cx: &mut Context<Self>) {
        let AppState::Connected { connection, .. } = &self.state else {
            return;
        };
        let first = connection.profile.agents[&AgentId::Claude].protocol;
        let common = AgentId::ALL
            .iter()
            .all(|agent| connection.profile.agents[agent].protocol == first)
            .then_some(first.as_str());
        self.all_protocol.update(cx, |select, cx| {
            select.set_selected(common.map(Into::into), cx)
        });
    }

    fn queue_profile_save(&mut self, cx: &mut Context<Self>) {
        if let AppState::Connected { connection, .. } = &self.state {
            self.pending_save = Some(connection.profile.clone());
            self.start_profile_save(cx);
        }
    }

    fn begin_projection_status(&mut self, cx: &mut Context<Self>) {
        let AppState::Connected { connection, .. } = &self.state else {
            return;
        };
        let profile = connection.profile.clone();
        let backend = Arc::clone(&self.backend);
        cx.spawn(async move |this, cx| {
            let result = cx
                .background_executor()
                .spawn(async move {
                    let installs = backend
                        .discover_agents()
                        .map(QueryStatus::Known)
                        .unwrap_or_else(|error| QueryStatus::Error(error.to_string()));
                    let managed = backend
                        .managed_agents(&profile)
                        .map(QueryStatus::Known)
                        .unwrap_or_else(|error| QueryStatus::Error(error.to_string()));
                    (profile, installs, managed)
                })
                .await;
            this.update(cx, |this, cx| {
                match result {
                    (profile, installs, managed) => {
                        if matches!(
                            &this.state,
                            AppState::Connected { connection, .. }
                                if connection.profile.id == profile.id
                        ) {
                            this.state.set_projection_status(installs, managed);
                        }
                    }
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn set_projection_busy(&mut self, busy: bool, cx: &mut Context<Self>) {
        self.projection_busy = busy;
        for (_, select) in &self.protocol_selects {
            select.update(cx, |select, cx| select.set_disabled(busy, cx));
        }
        self.all_protocol
            .update(cx, |select, cx| select.set_disabled(busy, cx));
        self.sync_model_selects(cx);
    }

    fn begin_refresh(&mut self, cx: &mut Context<Self>) {
        if self.projection_busy {
            return;
        }
        let AppState::Connected { connection, .. } = &self.state else {
            return;
        };
        let profile = connection.profile.clone();
        let backend = Arc::clone(&self.backend);
        self.action_error = None;
        self.set_projection_busy(true, cx);
        cx.spawn(async move |this, cx| {
            let result = cx
                .background_executor()
                .spawn(async move { backend.refresh(profile) })
                .await;
            this.update(cx, |this, cx| {
                this.set_projection_busy(false, cx);
                match result {
                    Ok(connection) => this.complete_connection(connection, cx),
                    Err(error) => this.action_error = Some(error.to_string()),
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn begin_preview(&mut self, cx: &mut Context<Self>) {
        if self.projection_busy {
            return;
        }
        let AppState::Connected { connection, .. } = &self.state else {
            return;
        };
        let connection = connection.as_ref().clone();
        let expected_profile = connection.profile.clone();
        let backend = Arc::clone(&self.backend);
        self.action_error = None;
        self.set_projection_busy(true, cx);
        cx.spawn(async move |this, cx| {
            let result = cx
                .background_executor()
                .spawn(async move { backend.plan_projection(&connection) })
                .await;
            this.update(cx, |this, cx| {
                this.set_projection_busy(false, cx);
                match result {
                    Ok(plan)
                        if matches!(
                            &this.state,
                            AppState::Connected { connection, .. }
                                if connection.profile == expected_profile
                        ) =>
                    {
                        this.state.set_preview(plan);
                    }
                    Ok(_) => {
                        this.action_error =
                            Some("Agent choices changed while previewing; preview again.".into());
                    }
                    Err(error) => this.action_error = Some(error.to_string()),
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn begin_apply(&mut self, cx: &mut Context<Self>) {
        if self.projection_busy {
            return;
        }
        let AppState::Connected {
            connection,
            preview: Some(plan),
            verification: None,
            ..
        } = &self.state
        else {
            return;
        };
        let profile = connection.profile.clone();
        let plan = plan.as_ref().clone();
        let backend = Arc::clone(&self.backend);
        self.action_error = None;
        self.set_projection_busy(true, cx);
        cx.spawn(async move |this, cx| {
            let result = cx
                .background_executor()
                .spawn(async move {
                    backend.apply_projection(&profile, &plan)?;
                    let verification = backend.verify_projection(&plan)?;
                    let managed = backend.managed_agents(&profile)?;
                    Ok::<_, gateway_connector_backend::BackendError>((
                        profile,
                        verification,
                        managed,
                    ))
                })
                .await;
            this.update(cx, |this, cx| {
                this.set_projection_busy(false, cx);
                match result {
                    Ok((profile, verification, managed)) => {
                        if let AppState::Connected {
                            connection,
                            managed_agents,
                            ..
                        } = &mut this.state
                            && connection.profile.id == profile.id
                        {
                            *managed_agents = QueryStatus::Known(managed);
                            this.state.set_verification(verification);
                        }
                    }
                    Err(error) => {
                        this.state.clear_preview();
                        this.action_error = Some(error.to_string());
                    }
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn begin_verify(&mut self, cx: &mut Context<Self>) {
        if self.projection_busy {
            return;
        }
        let AppState::Connected {
            preview: Some(plan),
            verification: Some(_),
            ..
        } = &self.state
        else {
            return;
        };
        let plan = plan.as_ref().clone();
        let backend = Arc::clone(&self.backend);
        self.action_error = None;
        self.set_projection_busy(true, cx);
        cx.spawn(async move |this, cx| {
            let result = cx
                .background_executor()
                .spawn(async move { backend.verify_projection(&plan) })
                .await;
            this.update(cx, |this, cx| {
                this.set_projection_busy(false, cx);
                match result {
                    Ok(verification) => this.state.set_verification(verification),
                    Err(error) => this.action_error = Some(error.to_string()),
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn begin_disconnect(&mut self, cx: &mut Context<Self>) {
        if self.projection_busy || self.save_in_flight {
            return;
        }
        let AppState::Connected { connection, .. } = &self.state else {
            return;
        };
        let profile = connection.profile.clone();
        let backend = Arc::clone(&self.backend);
        self.action_error = None;
        self.set_projection_busy(true, cx);
        cx.spawn(async move |this, cx| {
            let result = cx
                .background_executor()
                .spawn(async move {
                    backend.disconnect(&profile)?;
                    Ok::<_, gateway_connector_backend::BackendError>(profile)
                })
                .await;
            this.update(cx, |this, cx| {
                this.set_projection_busy(false, cx);
                match result {
                    Ok(profile) => {
                        this.gateway_url.update(cx, |input, cx| {
                            input.set_value(profile.base_url.to_string(), cx)
                        });
                        let protocol = profile.agents[&AgentId::Claude].protocol.as_str();
                        this.initial_protocol.update(cx, |select, cx| {
                            select.set_selected(Some(protocol.into()), cx)
                        });
                        this.pending_save = None;
                        this.save_error = None;
                        this.action_error = None;
                        this.page = Page::Overview;
                        this.state = AppState::FirstRun;
                    }
                    Err(error) => this.action_error = Some(error.to_string()),
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn start_profile_save(&mut self, cx: &mut Context<Self>) {
        if self.save_in_flight {
            return;
        }
        let Some(profile) = self.pending_save.take() else {
            return;
        };
        self.save_in_flight = true;
        let backend = Arc::clone(&self.backend);
        cx.spawn(async move |this, cx| {
            let result = cx
                .background_executor()
                .spawn(async move { backend.save_profile(&profile) })
                .await;
            this.update(cx, |this, cx| {
                this.save_in_flight = false;
                this.save_error = result.err().map(|error| error.to_string());
                this.start_profile_save(cx);
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn render_first_run(
        &self,
        connecting: bool,
        error: Option<&str>,
        cx: &mut Context<Self>,
    ) -> gpui::AnyElement {
        let locale = self.preferences.locale;
        let this = cx.entity().downgrade();
        Card::new()
            .id("connector.first-run")
            .padded(true)
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap(px(16.0))
                    .child(
                        div()
                            .text_size(px(24.0))
                            .child(locale.text("Connect a Gateway")),
                    )
                    .child(div().text_color(cx.theme().colors.text_muted).child(
                        locale.text(
                            "Enter any OpenAI-compatible Gateway. A platform manifest is optional.",
                        ),
                    ))
                    .child(
                        FormField::new(
                            "connector.gateway-url.field",
                            locale.text("Gateway base URL"),
                        )
                            .control("connector.gateway-url")
                            .required(true)
                            .description(
                                locale.text("Root or nested prefix; /v1 and /v1/models forms are also accepted. HTTPS except loopback."),
                            )
                            .child(self.gateway_url.clone()),
                    )
                    .child(
                        FormField::new(
                            "connector.api-key.field",
                            locale.text("API key"),
                        )
                            .control("connector.api-key")
                            .description(
                                locale.text("Stored in the operating-system credential vault. Leave blank when the platform advertises browser login."),
                            )
                            .child(self.api_key.clone()),
                    )
                    .child(
                        FormField::new(
                            "connector.initial-protocol.field",
                            locale.text("Default protocol"),
                        )
                            .control("connector.initial-protocol")
                            .required(true)
                            .child(self.initial_protocol.clone()),
                    )
                    .children(error.map(|message| {
                        Callout::new(message.to_owned(), Tone::Danger)
                            .id("connector.connection-error")
                    }))
                    .child(
                        Button::new("connector.connect")
                            .label(if connecting {
                                locale.text("Testing connection")
                            } else {
                                locale.text("Connect / Test")
                            })
                            .primary()
                            .full_width(true)
                            .loading(connecting)
                            .on_click(move |_window, cx| {
                                let _ = this.update(cx, |this, cx| this.begin_connect(cx));
                            }),
                    ),
            )
            .into_any_element()
    }

    fn render_browser_login(
        &self,
        offer: &BrowserLoginOffer,
        cx: &mut Context<Self>,
    ) -> gpui::AnyElement {
        let locale = self.preferences.locale;
        let continue_view = cx.entity().downgrade();
        let back_view = cx.entity().downgrade();
        let clear_error_view = cx.entity().downgrade();
        Card::new()
            .id("connector.browser-login")
            .padded(true)
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap(px(16.0))
                    .child(
                        div()
                            .text_size(px(24.0))
                            .child(locale.text("Browser login available")),
                    )
                    .child(
                        div()
                            .text_color(cx.theme().colors.text_muted)
                            .child(format!(
                                "{} advertises standard browser PKCE. GatewayConnector will keep only the returned access token in the OS vault.",
                                offer.manifest.platform.name
                            )),
                    )
                    .child(
                        DescriptionList::new("connector.browser-login.summary")
                            .item(DescriptionItem::new(
                                "connector.browser-login.platform",
                                locale.text("Platform"),
                                offer.manifest.platform.name.clone(),
                            ))
                            .item(DescriptionItem::new(
                                "connector.browser-login.gateway",
                                locale.text("Gateway"),
                                offer.request.base_url.clone(),
                            ))
                            .item(DescriptionItem::new(
                                "connector.browser-login.security",
                                locale.text("Security"),
                                "S256 PKCE · loopback callback · access_token only",
                            )),
                    )
                    .children(self.action_error.as_ref().map(|error| {
                        Callout::new(error.clone(), Tone::Danger)
                            .id("connector.browser-login.error")
                    }))
                    .children(self.action_error.is_some().then(|| {
                        Button::new("connector.browser-login.clear-error")
                            .label(locale.text("Clear error"))
                            .secondary()
                            .on_click(move |_window, cx| {
                                let _ = clear_error_view.update(cx, |this, cx| {
                                    this.action_error = None;
                                    cx.notify();
                                });
                            })
                    }))
                    .child(
                        Button::new("connector.browser-login.continue")
                            .label(locale.text("Continue in browser"))
                            .primary()
                            .full_width(true)
                            .on_click(move |_window, cx| {
                                let _ = continue_view
                                    .update(cx, |this, cx| this.begin_browser_login(cx));
                            }),
                    )
                    .child(
                        Button::new("connector.browser-login.back")
                            .label(locale.text("Back"))
                            .secondary()
                            .full_width(true)
                            .on_click(move |_window, cx| {
                                let _ = back_view.update(cx, |this, cx| {
                                    this.action_error = None;
                                    this.state = AppState::FirstRun;
                                    cx.notify();
                                });
                            }),
                    ),
            )
            .into_any_element()
    }

    fn navigation(&self, cx: &mut Context<Self>) -> Sidebar {
        let AppState::Connected { connection, .. } = &self.state else {
            unreachable!("navigation requires connected state")
        };
        let locale = self.preferences.locale;
        let mut platform_items = Vec::new();
        for (page, label, icon) in [
            (Page::Services, "Online services", Icon::Widget),
            (Page::Account, "Account", Icon::Global),
            (Page::Usage, "Usage", Icon::List),
            (Page::Billing, "Billing", Icon::Document),
            (Page::ModelPlaza, "Model Plaza", Icon::Magnifier),
        ] {
            if page.available(connection.provisioning.as_ref()) {
                platform_items.push(SidebarItem::new(page.id(), locale.text(label)).icon(icon));
            }
        }
        let handle = cx.entity().downgrade();
        Sidebar::new("connector.sidebar")
            .active(self.page.id())
            .header(
                div()
                    .flex()
                    .items_center()
                    .gap(px(10.0))
                    .p(px(8.0))
                    .child(gpui_kit::assets::icon(Icon::Global).size(px(18.0)))
                    .child(
                        div()
                            .font_weight(FontWeight::SEMIBOLD)
                            .child(self.distribution.product_name),
                    ),
            )
            .section(
                SidebarSection::new("connection")
                    .item(
                        SidebarItem::new("overview", locale.text("Connection")).icon(Icon::Global),
                    )
                    .item(
                        SidebarItem::new("agents", locale.text("Agents"))
                            .icon(Icon::Terminal)
                            .children(AgentId::ALL.map(|agent| {
                                SidebarItem::new(Page::Agent(agent).id(), agent.display_name())
                                    .icon(agent_icon(agent))
                            })),
                    ),
            )
            .section(SidebarSection::new("platform").items(platform_items))
            .section(
                SidebarSection::new("preferences").item(
                    SidebarItem::new("settings", locale.text("Settings")).icon(Icon::Settings),
                ),
            )
            .footer(StatusLine::new(locale.text("Connected"), Tone::Success))
            .on_select(move |id, _, cx| {
                let Some(page) = Page::from_id(id.as_ref()) else {
                    return;
                };
                let _ = handle.update(cx, |this, cx| {
                    this.page = page;
                    cx.notify();
                });
            })
    }

    fn render_services(&self, cx: &mut Context<Self>) -> gpui::AnyElement {
        let AppState::Connected { connection, .. } = &self.state else {
            unreachable!("services require connected state")
        };
        let locale = self.preferences.locale;
        let Some(provisioning) = connection.provisioning.as_ref() else {
            return EmptyState::new(
                "connector.services.empty",
                locale.text("No online services were provisioned."),
            )
            .kind(EmptyKind::Empty)
            .into_any_element();
        };
        let mut content = div()
            .flex()
            .flex_col()
            .gap(px(16.0))
            .child(page_title(locale.text("Online services")))
            .child(
                div()
                    .text_color(cx.theme().colors.text_muted)
                    .child(locale.text("Direct connections do not invent MCP servers or Skills.")),
            );
        if !provisioning.mcp_servers.is_empty() {
            let mut servers = Card::new()
                .id("connector.services.mcp")
                .padded(true)
                .child(div().text_size(px(18.0)).child(locale.text("MCP servers")));
            for server in &provisioning.mcp_servers {
                servers = servers.child(
                    ListRow::new()
                        .id(format!("connector.service.mcp.{}", server.id))
                        .child(div().flex_1().child(server.name.clone()))
                        .child(Badge::new("online").success()),
                );
            }
            content = content.child(servers);
        }
        if !provisioning.skills.is_empty() {
            let mut skills = Card::new()
                .id("connector.services.skills")
                .padded(true)
                .child(div().text_size(px(18.0)).child(locale.text("Skills")));
            for skill in &provisioning.skills {
                let synchronized = connection.synchronized_skills.contains_key(&skill.id);
                skills = skills.child(
                    ListRow::new()
                        .id(format!("connector.service.skill.{}", skill.id))
                        .child(div().flex_1().child(skill.name.clone()))
                        .child(Badge::new(skill.version.clone()).neutral())
                        .child(Badge::new(if synchronized {
                            "synchronized"
                        } else {
                            "pending"
                        })),
                );
            }
            content = content.child(skills);
        }
        content.into_any_element()
    }

    fn render_account(&self) -> gpui::AnyElement {
        let AppState::Connected { connection, .. } = &self.state else {
            unreachable!("account requires connected state")
        };
        let account = connection
            .provisioning
            .as_ref()
            .and_then(|value| value.account.as_ref())
            .expect("account page is conditional");
        let locale = self.preferences.locale;
        div()
            .flex()
            .flex_col()
            .gap(px(16.0))
            .child(page_title(locale.text("Account")))
            .child(
                DescriptionList::new("connector.account")
                    .item(DescriptionItem::new(
                        "connector.account.display-name",
                        locale.text("Display name"),
                        account.display_name.clone(),
                    ))
                    .item(DescriptionItem::new(
                        "connector.account.username",
                        locale.text("Username"),
                        account.username.clone(),
                    ))
                    .item(DescriptionItem::new(
                        "connector.account.email",
                        locale.text("Email"),
                        account.email.clone(),
                    ))
                    .item(DescriptionItem::new(
                        "connector.account.group",
                        locale.text("Group"),
                        account.group.clone(),
                    )),
            )
            .into_any_element()
    }

    fn render_usage(&self) -> gpui::AnyElement {
        let AppState::Connected { connection, .. } = &self.state else {
            unreachable!("usage requires connected state")
        };
        let usage = connection
            .provisioning
            .as_ref()
            .and_then(|value| value.usage.as_ref())
            .expect("usage page is conditional");
        let locale = self.preferences.locale;
        div()
            .flex()
            .flex_col()
            .gap(px(16.0))
            .child(page_title(locale.text("Usage")))
            .child(
                DescriptionList::new("connector.usage")
                    .item(DescriptionItem::new(
                        "connector.usage.remaining",
                        locale.text("Wallet remaining"),
                        usage.wallet_quota_remaining.to_string(),
                    ))
                    .item(DescriptionItem::new(
                        "connector.usage.used",
                        locale.text("Lifetime used"),
                        usage.lifetime_quota_used.to_string(),
                    ))
                    .item(DescriptionItem::new(
                        "connector.usage.requests",
                        locale.text("Lifetime requests"),
                        usage.lifetime_request_count.to_string(),
                    )),
            )
            .into_any_element()
    }

    fn render_billing(&self) -> gpui::AnyElement {
        let AppState::Connected { connection, .. } = &self.state else {
            unreachable!("billing requires connected state")
        };
        let billing = connection
            .provisioning
            .as_ref()
            .and_then(|value| value.billing.as_ref())
            .expect("billing page is conditional");
        let locale = self.preferences.locale;
        let mut content = div()
            .flex()
            .flex_col()
            .gap(px(16.0))
            .child(page_title(locale.text("Billing")))
            .child(
                DescriptionList::new("connector.billing")
                    .item(DescriptionItem::new(
                        "connector.billing.portal",
                        locale.text("Portal"),
                        billing.portal_url.to_string(),
                    ))
                    .item(DescriptionItem::new(
                        "connector.billing.fallback",
                        locale.text("Wallet fallback allowed"),
                        locale.text(if billing.wallet_fallback_allowed {
                            "Yes"
                        } else {
                            "No"
                        }),
                    )),
            )
            .child(
                div()
                    .text_size(px(18.0))
                    .child(locale.text("Subscriptions")),
            );
        if billing.subscriptions.is_empty() {
            content = content.child(locale.text("No active subscriptions."));
        }
        for subscription in &billing.subscriptions {
            content = content.child(
                ListRow::new()
                    .id(format!("connector.subscription.{}", subscription.id))
                    .child(format!("Plan {}", subscription.plan_id))
                    .child(Badge::new(subscription.status.clone()).neutral()),
            );
        }
        content.into_any_element()
    }

    fn render_model_plaza(&self) -> gpui::AnyElement {
        let AppState::Connected { connection, .. } = &self.state else {
            unreachable!("Model Plaza requires connected state")
        };
        let plaza = connection
            .provisioning
            .as_ref()
            .and_then(|value| value.model_plaza.as_ref())
            .expect("Model Plaza page is conditional");
        let locale = self.preferences.locale;
        let query = self.plaza_query.trim().to_ascii_lowercase();
        let matches = plaza.models.iter().filter(|model| {
            query.is_empty()
                || model.id.to_ascii_lowercase().contains(&query)
                || model
                    .description
                    .as_ref()
                    .is_some_and(|value| value.to_ascii_lowercase().contains(&query))
                || model
                    .vendor
                    .as_ref()
                    .is_some_and(|value| value.name.to_ascii_lowercase().contains(&query))
                || model
                    .tags
                    .iter()
                    .any(|value| value.to_ascii_lowercase().contains(&query))
        });
        let mut models = Card::new().id("connector.model-plaza.models");
        let mut count = 0usize;
        for model in matches.take(200) {
            count += 1;
            let provider = model
                .vendor
                .as_ref()
                .map(|value| value.name.clone())
                .unwrap_or_else(|| locale.text("Provider").to_owned());
            models = models.child(
                ListRow::new()
                    .id(format!("connector.model-plaza.{}", model.id))
                    .child(div().flex_1().min_w_0().child(model.id.clone()))
                    .child(Badge::new(provider).neutral())
                    .child(Badge::new(locale.text(if model.chat_capable {
                        "Chat capable"
                    } else {
                        "Other model"
                    }))),
            );
        }
        if count == 0 {
            models = models.child(locale.text("No models match this search."));
        }
        div()
            .flex()
            .flex_col()
            .gap(px(16.0))
            .child(page_title(locale.text("Model Plaza")))
            .child(DescriptionList::new("connector.model-plaza.summary").item(
                DescriptionItem::new(
                    "connector.model-plaza.portal",
                    locale.text("Portal"),
                    plaza.portal_url.to_string(),
                ),
            ))
            .child(self.plaza_search.clone())
            .child(models)
            .into_any_element()
    }

    fn render_settings(&self, cx: &mut Context<Self>) -> gpui::AnyElement {
        let locale = self.preferences.locale;
        let disconnect_view = cx.entity().downgrade();
        div()
            .flex()
            .flex_col()
            .gap(px(16.0))
            .child(page_title(locale.text("Settings")))
            .child(
                SettingsSection::new("connector.settings.preferences", locale.text("Settings"))
                    .row(
                        SettingsRow::new("connector.settings.language", locale.text("Language"))
                            .control(self.language_select.clone()),
                    )
                    .row(
                        SettingsRow::new("connector.settings.theme", locale.text("Theme"))
                            .control(self.theme_select.clone()),
                    ),
            )
            .child(page_title(locale.text("Security facts")))
            .child(
                Callout::new(
                    locale.text("Credentials stay in the OS vault. Bearers are sent only to exact allowlisted origins. Agent changes require a fresh preview."),
                    Tone::Info,
                )
                .id("connector.security-facts"),
            )
            .child(
                Button::new("connector.disconnect")
                    .label(locale.text("Disconnect Gateway and remove managed configuration"))
                    .danger()
                    .full_width(true)
                    .disabled(self.projection_busy || self.save_in_flight)
                    .on_click(move |_window, cx| {
                        let _ = disconnect_view.update(cx, |this, cx| this.begin_disconnect(cx));
                    }),
            )
            .into_any_element()
    }

    fn render_connected(&self, cx: &mut Context<Self>) -> gpui::AnyElement {
        let AppState::Connected {
            connection,
            installs,
            managed_agents,
            preview,
            verification,
        } = &self.state
        else {
            unreachable!("connected renderer requires connected state")
        };
        match self.page {
            Page::Services => return self.render_services(cx),
            Page::Account => return self.render_account(),
            Page::Usage => return self.render_usage(),
            Page::Billing => return self.render_billing(),
            Page::ModelPlaza => return self.render_model_plaza(),
            Page::Settings => return self.render_settings(cx),
            Page::Overview | Page::Agent(_) => {}
        }
        let profile = &connection.profile;
        let models = &connection.models;
        let known_installs = match installs {
            QueryStatus::Known(value) => Some(value),
            _ => None,
        };
        let detected =
            known_installs.map(|values| values.iter().filter(|install| install.detected).count());
        let supported_detected = known_installs
            .into_iter()
            .flatten()
            .filter(|install| {
                install.detected
                    && connection
                        .manifest
                        .as_ref()
                        .is_none_or(|manifest| manifest.supported_agents.contains(&install.agent))
            })
            .count();
        let refresh_view = cx.entity().downgrade();
        let clear_error_view = cx.entity().downgrade();
        let locale = self.preferences.locale;
        let selected_agent = match self.page {
            Page::Agent(agent) => Some(agent),
            _ => None,
        };
        let mut content = div()
            .flex()
            .flex_col()
            .gap(px(16.0))
            .child(page_title(match selected_agent {
                Some(agent) => agent.display_name(),
                None => locale.text("Connection overview"),
            }))
            .child(StatusLine::new(locale.text("Connected"), Tone::Success).id("connector.status"))
            .children(self.save_error.as_ref().map(|error| {
                Callout::new(
                    format!("Could not persist the latest Agent choices: {error}"),
                    Tone::Warning,
                )
                .id("connector.save-error")
            }))
            .children(self.action_error.as_ref().map(|error| {
                Callout::new(error.clone(), Tone::Danger).id("connector.action-error")
            }))
            .children(self.action_error.is_some().then(|| {
                Button::new("connector.clear-error")
                    .label(locale.text("Clear error"))
                    .secondary()
                    .on_click(move |_window, cx| {
                        let _ = clear_error_view.update(cx, |this, cx| {
                            this.action_error = None;
                            cx.notify();
                        });
                    })
            }));

        if selected_agent.is_none() {
            content = content
                .child(
                DescriptionList::new("connector.summary")
                    .item(DescriptionItem::new(
                        "connector.summary.gateway",
                        locale.text("Gateway"),
                        profile.base_url.to_string(),
                    ))
                    .item(DescriptionItem::new(
                        "connector.summary.models",
                        locale.text("Models"),
                        models.len().to_string(),
                    ))
                    .item(DescriptionItem::new(
                        "connector.summary.profile",
                        locale.text("Profile"),
                        profile.display_name.clone(),
                    ))
                    .item(DescriptionItem::new(
                        "connector.summary.agents",
                        locale.text("Detected Agents"),
                        match installs {
                            QueryStatus::Known(_) => format!("{} / {}", detected.unwrap_or_default(), AgentId::ALL.len()),
                            QueryStatus::Unknown => locale.text("Unknown").into(),
                            QueryStatus::Error(error) => format!("Error: {error}"),
                        },
                    )),
                )
                .child(
                Button::new("connector.refresh")
                    .label(locale.text("Refresh models and online services"))
                    .secondary()
                    .disabled(self.projection_busy)
                    .on_click(move |_window, cx| {
                        let _ = refresh_view.update(cx, |this, cx| this.begin_refresh(cx));
                    }),
                )
                .child(
                FormField::new(
                    "connector.model-search.field",
                    locale.text("Search model catalog"),
                )
                    .control("connector.model-search")
                    .description(
                        locale.text("Filters every Agent picker by model ID or provider; saved unavailable choices remain visible."),
                    )
                    .child(self.model_search.clone()),
                )
                .child(
                Card::new()
                    .id("connector.all.settings")
                    .padded(true)
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap(px(10.0))
                            .child(
                                div()
                                    .text_size(px(18.0))
                                    .child(locale.text("Use for all Agents")),
                            )
                            .child(
                                div()
                                    .text_color(cx.theme().colors.text_muted)
                                    .child(locale.text("Choose a shared default, then override any Agent on its page.")),
                            )
                            .child(self.all_protocol.clone())
                            .child(self.all_model.clone()),
                    ),
                );
        }

        for agent in AgentId::ALL {
            if selected_agent != Some(agent) {
                continue;
            }
            let install = match installs {
                QueryStatus::Known(values) => values.iter().find(|install| install.agent == agent),
                _ => None,
            };
            let detected = install.is_some_and(|install| install.detected);
            let supported = connection
                .manifest
                .as_ref()
                .is_none_or(|manifest| manifest.supported_agents.contains(&agent));
            let ownership = match managed_agents {
                QueryStatus::Known(values) if values.contains(&agent) => {
                    locale.text("Managed by this connection").into()
                }
                QueryStatus::Known(_) => locale.text("Not managed").into(),
                QueryStatus::Unknown => locale.text("Unknown").into(),
                QueryStatus::Error(error) => format!("Error: {error}"),
            };
            let location = install
                .map(|install| install.root.display().to_string())
                .unwrap_or_else(|| "Checking standard root…".into());
            let availability = match installs {
                QueryStatus::Unknown => locale.text("Unknown").into(),
                QueryStatus::Error(error) => format!("Error: {error}"),
                QueryStatus::Known(_) => match (detected, supported) {
                    (true, true) => locale.text("Detected").into(),
                    (false, true) => locale.text("Not detected").into(),
                    (_, false) => locale.text("Not advertised by this platform").into(),
                },
            };
            let protocol = self
                .protocol_selects
                .iter()
                .find(|(candidate, _)| *candidate == agent)
                .expect("all Agent protocol selects exist")
                .1
                .clone();
            let model = self
                .model_selects
                .iter()
                .find(|(candidate, _)| *candidate == agent)
                .expect("all Agent model selects exist")
                .1
                .clone();
            content = content.child(
                Card::new()
                    .id(format!("connector.{}.settings", agent.as_str()))
                    .padded(true)
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap(px(10.0))
                            .child(
                                DescriptionList::new(format!(
                                    "connector.{}.details",
                                    agent.as_str()
                                ))
                                .item(DescriptionItem::new(
                                    format!("connector.{}.detected", agent.as_str()),
                                    locale.text("Detected"),
                                    availability,
                                ))
                                .item(DescriptionItem::new(
                                    format!("connector.{}.ownership", agent.as_str()),
                                    locale.text("Connection"),
                                    ownership,
                                ))
                                .item(DescriptionItem::new(
                                    format!("connector.{}.root", agent.as_str()),
                                    locale.text("Root"),
                                    location,
                                )),
                            )
                            .child(protocol)
                            .child(model),
                    ),
            );
        }

        let preview_view = cx.entity().downgrade();
        let apply_view = cx.entity().downgrade();
        let verify_view = cx.entity().downgrade();
        content = content
            .child(
                div()
                    .flex()
                    .gap(px(10.0))
                    .child(
                        Button::new("connector.preview")
                            .label(if self.projection_busy {
                                locale.text("Working…")
                            } else {
                                locale.text("Preview changes")
                            })
                            .secondary()
                            .disabled(
                                self.projection_busy
                                    || supported_detected == 0
                                    || models.is_empty(),
                            )
                            .on_click(move |_window, cx| {
                                let _ = preview_view.update(cx, |this, cx| this.begin_preview(cx));
                            }),
                    )
                    .child(
                        Button::new("connector.apply")
                            .label(locale.text("Apply"))
                            .primary()
                            .disabled(
                                self.projection_busy || preview.is_none() || verification.is_some(),
                            )
                            .on_click(move |_window, cx| {
                                let _ = apply_view.update(cx, |this, cx| this.begin_apply(cx));
                            }),
                    )
                    .child(
                        Button::new("connector.verify")
                            .label(locale.text("Verify"))
                            .secondary()
                            .disabled(self.projection_busy || verification.is_none())
                            .on_click(move |_window, cx| {
                                let _ = verify_view.update(cx, |this, cx| this.begin_verify(cx));
                            }),
                    ),
            )
            .children((supported_detected == 0).then(|| {
                Callout::new(
                    locale
                        .text("Install a supported Agent before previewing configuration changes."),
                    Tone::Info,
                )
                .id("connector.no-agents")
            }))
            .children(models.is_empty().then(|| {
                Callout::new(
                    locale.text("The Gateway currently offers no chat-capable models."),
                    Tone::Warning,
                )
                .id("connector.no-models")
            }))
            .children(
                (supported_detected > 0 && !models.is_empty() && preview.is_none()).then(|| {
                    Callout::new(
                        locale.text("Preview again after changing any Agent protocol or model."),
                        Tone::Info,
                    )
                    .id("connector.preview-required")
                }),
            );

        if let Some(plan) = preview {
            let mut changes = Card::new().id("connector.preview-changes");
            for (index, change) in plan.changes.iter().enumerate() {
                changes = changes.child(
                    ListRow::new()
                        .id(format!("connector.preview.{index}"))
                        .child(Badge::new(change_kind(&change.kind)).neutral())
                        .child(div().min_w_0().child(change.path.display().to_string())),
                );
            }
            if plan.changes.is_empty() {
                changes = changes.child(
                    ListRow::new()
                        .id("connector.preview.empty")
                        .child(locale.text("No Agent file changes are needed.")),
                );
            }
            content = content.child(
                Callout::new(
                    locale.text("Fresh preview ready. No Agent files have been changed yet."),
                    Tone::Info,
                )
                .id("connector.preview-summary"),
            );
            content = content.child(changes);
        }

        if let Some(verification) = verification {
            let message = if verification.ok {
                locale
                    .text("Applied configuration matches the preview.")
                    .to_owned()
            } else {
                format!(
                    "Verification found drift:\n{}",
                    verification
                        .mismatches
                        .iter()
                        .map(|path| path.display().to_string())
                        .collect::<Vec<_>>()
                        .join("\n")
                )
            };
            content = content.child(
                Callout::new(
                    message,
                    if verification.ok {
                        Tone::Success
                    } else {
                        Tone::Danger
                    },
                )
                .id("connector.verification"),
            );
        }
        Card::new()
            .id("connector.connected")
            .padded(true)
            .child(content)
            .into_any_element()
    }
}

impl Render for ConnectorView {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = cx.theme().clone();
        let connected = matches!(self.state, AppState::Connected { .. });
        let content = match &self.state {
            AppState::Loading => Card::new()
                .id("connector.loading")
                .padded(true)
                .child(StatusLine::new(
                    self.text("Loading saved connection"),
                    Tone::Info,
                ))
                .into_any_element(),
            AppState::FirstRun => self.render_first_run(false, None, cx),
            AppState::Connecting => self.render_first_run(true, None, cx),
            AppState::BrowserLogin(offer) => self.render_browser_login(offer, cx),
            AppState::Failed(error) => self.render_first_run(false, Some(error), cx),
            AppState::Connected { .. } => self.render_connected(cx),
        };
        let root = div()
            .id("connector.root")
            .size_full()
            .bg(theme.colors.canvas)
            .font_family(theme.typography.sans.clone())
            .text_color(theme.colors.text);
        if connected {
            root.flex().child(self.navigation(cx)).child(
                div()
                    .id("connector.shell.content")
                    .flex_1()
                    .min_w_0()
                    .h_full()
                    .overflow_y_scroll()
                    .child(
                        div()
                            .w_full()
                            .max_w(px(800.0))
                            .mx_auto()
                            .p(px(32.0))
                            .child(content),
                    ),
            )
        } else {
            root.overflow_y_scroll().child(
                div()
                    .w_full()
                    .max_w(px(680.0))
                    .mx_auto()
                    .p(px(32.0))
                    .child(content),
            )
        }
    }
}

fn page_title(title: &str) -> impl IntoElement {
    div()
        .text_size(px(24.0))
        .font_weight(FontWeight::SEMIBOLD)
        .child(title.to_owned())
}

fn agent_icon(agent: AgentId) -> Icon {
    match agent {
        AgentId::Claude => Icon::Chat,
        AgentId::Codex => Icon::Terminal,
        AgentId::Gemini => Icon::Global,
        AgentId::Grokbuild => Icon::Command,
        AgentId::Opencode => Icon::Document,
    }
}

fn activate_theme_for(appearance: WindowAppearance, cx: &mut App) {
    let theme = match appearance {
        WindowAppearance::Light | WindowAppearance::VibrantLight => "studio-light",
        WindowAppearance::Dark | WindowAppearance::VibrantDark => "studio-dark",
    };
    gpui_kit::theme::activate_theme(theme, cx);
}

fn apply_theme(preference: ThemePreference, cx: &mut App) {
    let appearance = match preference {
        ThemePreference::System => {
            cx.set_window_appearance(None);
            cx.window_appearance()
        }
        ThemePreference::Light => {
            cx.set_window_appearance(Some(WindowAppearance::Light));
            WindowAppearance::Light
        }
        ThemePreference::Dark => {
            cx.set_window_appearance(Some(WindowAppearance::Dark));
            WindowAppearance::Dark
        }
    };
    activate_theme_for(appearance, cx);
}

fn protocol_select(
    id: impl Into<gpui_kit::foundation::Ident>,
    window: &mut Window,
    cx: &mut Context<Select>,
) -> Select {
    Select::new(id, window, cx)
        .name("Protocol")
        .options(
            Protocol::ALL
                .map(|protocol| SelectOption::new(protocol.as_str(), protocol.display_name())),
        )
        .selected(Protocol::Auto.as_str())
}

fn display_name(base_url: &str) -> String {
    CanonicalBaseUrl::parse(base_url)
        .map(|url| url.suggested_display_name())
        .unwrap_or_else(|_| "Gateway".to_owned())
}

fn change_kind(kind: &ChangeKind) -> &'static str {
    match kind {
        ChangeKind::Create => "Create",
        ChangeKind::Update => "Update",
        ChangeKind::Remove => "Remove",
        ChangeKind::ProjectSkill => "Skill",
    }
}

/// Runs the GPUI client with a compile-time neutral or downstream identity.
///
/// The distribution is validated before any state, vault, or network access.
pub fn run(distribution: &'static Distribution) {
    run_with_assets(distribution, gpui_kit::assets::Assets);
}

/// Runs a distribution with a wrapper-owned asset source. Downstream sources
/// should delegate unknown neutral icon/font paths to `gpui_kit::assets::Assets`.
pub fn run_with_assets(distribution: &'static Distribution, assets: impl AssetSource) {
    distribution
        .validate()
        .expect("validate GatewayConnector distribution");
    let directories = ProjectDirs::from(
        distribution.qualifier,
        distribution.organization,
        distribution.application,
    )
    .expect("the operating system provides a user data directory");
    let coordinator = ProjectDirs::from("dev", "GatewayConnector", "ProjectionCoordinator")
        .expect("the operating system provides a shared projection coordinator directory");
    let home = UserDirs::new()
        .expect("the operating system provides a home directory")
        .home_dir()
        .to_owned();
    let backend = Arc::new(
        ConnectorBackend::with_dependencies(
            Arc::new(OsCredentialStore::new(distribution.keyring_service)),
            Arc::new(JsonProfileStore::new(
                directories.data_local_dir().join("profiles.json"),
            )),
            distribution,
            Arc::new(SystemBrowser),
        )
        .and_then(|backend| {
            backend.with_runtime_directories(
                directories.data_local_dir(),
                coordinator.data_local_dir(),
                home,
            )
        })
        .expect("initialize GatewayConnector backend"),
    );
    let preference_store =
        PreferenceStore::new(directories.data_local_dir().join("ui-preferences.json"));
    let mut preferences = preference_store.load();
    if !distribution
        .supported_locales
        .contains(&preferences.locale.id())
    {
        preferences.locale = distribution
            .supported_locales
            .iter()
            .find_map(|value| Locale::from_id(value))
            .unwrap_or_default();
    }
    let application = gpui_platform::application().with_assets(assets);
    application.run(move |cx: &mut App| {
        gpui_kit::install(cx);
        apply_theme(preferences.theme, cx);
        let bounds = Bounds::centered(None, size(px(1120.0), px(760.0)), cx);
        let backend = Arc::clone(&backend);
        let preference_store = preference_store.clone();
        let preferences = preferences.clone();
        cx.open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                titlebar: Some(TitlebarOptions {
                    title: Some(distribution.product_name.into()),
                    ..Default::default()
                }),
                ..Default::default()
            },
            move |window, cx| {
                let backend = Arc::clone(&backend);
                cx.new(|cx| {
                    ConnectorView::new(
                        backend,
                        distribution,
                        preference_store,
                        preferences,
                        window,
                        cx,
                    )
                })
            },
        )
        .expect("open GatewayConnector window");
        cx.activate(true);
    });
}

fn locale_options(distribution: &Distribution) -> Vec<SelectOption> {
    Locale::ALL
        .into_iter()
        .filter(|locale| distribution.supported_locales.contains(&locale.id()))
        .map(|locale| SelectOption::new(locale.id(), locale.display_name()))
        .collect()
}
