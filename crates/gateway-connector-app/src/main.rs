use std::sync::Arc;

use directories::ProjectDirs;
use gateway_connector_app::AppState;
use gateway_connector_backend::{
    ApiKey, ConnectRequest, ConnectionResult, ConnectorBackend, JsonProfileStore, OsCredentialStore,
};
use gateway_connector_core::{AgentId, CanonicalBaseUrl, ConnectionProfile, Protocol};
use gpui::{
    App, Bounds, Context, Entity, IntoElement, ParentElement, Render, Styled, Window, WindowBounds,
    WindowOptions, div, prelude::*, px, size,
};
use gpui_kit::prelude::*;

struct ConnectorView {
    backend: Arc<ConnectorBackend>,
    state: AppState,
    gateway_url: Entity<TextInput>,
    api_key: Entity<TextInput>,
    initial_protocol: Entity<Select>,
    model_selects: Vec<(AgentId, Entity<Select>)>,
    protocol_selects: Vec<(AgentId, Entity<Select>)>,
    save_in_flight: bool,
    pending_save: Option<ConnectionProfile>,
    save_error: Option<String>,
}

impl ConnectorView {
    fn new(backend: Arc<ConnectorBackend>, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let gateway_url = cx.new(|cx| {
            TextInput::new("connector.gateway-url", window, cx)
                .name("Gateway base URL")
                .placeholder("https://gateway.example.com or https://gateway.example.com/v1")
                .required(true)
        });
        let api_key = cx.new(|cx| {
            TextInput::new("connector.api-key", window, cx)
                .name("API key")
                .placeholder("Enter API key")
                .secret(true)
                .required(true)
        });
        let initial_protocol =
            cx.new(|cx| protocol_select("connector.initial-protocol", window, cx));
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
                    this.commit_selection(agent, cx);
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

        let mut view = Self {
            backend,
            state: AppState::Loading,
            gateway_url,
            api_key,
            initial_protocol,
            model_selects,
            protocol_selects,
            save_in_flight: false,
            pending_save: None,
            save_error: None,
        };
        view.begin_resume(cx);
        view
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
        let api_key = match ApiKey::new(raw_key) {
            Ok(api_key) => api_key,
            Err(error) => {
                self.state = AppState::Failed(error.to_string());
                cx.notify();
                return;
            }
        };
        let display_name = display_name(&base_url);
        let backend = Arc::clone(&self.backend);
        self.state = AppState::Connecting;
        cx.notify();
        cx.spawn(async move |this, cx| {
            let result = cx
                .background_executor()
                .spawn(async move {
                    backend.connect(ConnectRequest {
                        display_name,
                        base_url,
                        api_key,
                        protocol,
                    })
                })
                .await;
            this.update(cx, |this, cx| {
                match result {
                    Ok(result) => this.complete_connection(result, cx),
                    Err(error) => this.state = AppState::Failed(error.to_string()),
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn complete_connection(&mut self, result: ConnectionResult, cx: &mut Context<Self>) {
        let options = result
            .models
            .iter()
            .map(|model| {
                let mut option = SelectOption::new(model.id.clone(), model.id.clone());
                if let Some(owner) = &model.owned_by {
                    option = option.description(owner.clone());
                }
                option
            })
            .collect::<Vec<_>>();
        for (agent, select) in &self.model_selects {
            let selected = result.profile.agents[agent]
                .default_model
                .clone()
                .filter(|id| options.iter().any(|option| option.id.as_ref() == id));
            select.update(cx, |select, cx| {
                select.set_options(options.clone(), cx);
                select.set_selected(selected.clone().map(Into::into), cx);
            });
        }
        for (agent, select) in &self.protocol_selects {
            let selected = result.profile.agents[agent].protocol.as_str();
            select.update(cx, |select, cx| {
                select.set_selected(Some(selected.into()), cx)
            });
        }
        self.api_key.update(cx, |input, cx| input.set_value("", cx));
        self.save_error = None;
        self.state = AppState::connected(result);
    }

    fn commit_selection(&mut self, agent: AgentId, cx: &mut Context<Self>) {
        let protocol = self
            .protocol_selects
            .iter()
            .find(|(candidate, _)| *candidate == agent)
            .and_then(|(_, select)| select.read(cx).selected_id().cloned())
            .and_then(|id| id.parse().ok())
            .unwrap_or(Protocol::Auto);
        let model = self
            .model_selects
            .iter()
            .find(|(candidate, _)| *candidate == agent)
            .and_then(|(_, select)| select.read(cx).selected_id().cloned())
            .map(|id| id.to_string());
        self.state.update_protocol(agent, protocol);
        if let Some(model) = model {
            self.state.update_model(agent, model);
        }
        if let AppState::Connected { profile, .. } = &self.state {
            self.pending_save = Some(profile.as_ref().clone());
            self.start_profile_save(cx);
        }
        cx.notify();
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
        let this = cx.entity().downgrade();
        Card::new()
            .id("connector.first-run")
            .padded(true)
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap(px(16.0))
                    .child(div().text_size(px(24.0)).child("Connect a Gateway"))
                    .child(div().text_color(cx.theme().colors.text_muted).child(
                        "Enter any OpenAI-compatible Gateway. A platform manifest is optional.",
                    ))
                    .child(
                        FormField::new("connector.gateway-url.field", "Gateway base URL")
                            .control("connector.gateway-url")
                            .required(true)
                            .description(
                                "Root or nested prefix; /v1 and /v1/models forms are also accepted. HTTPS except loopback.",
                            )
                            .child(self.gateway_url.clone()),
                    )
                    .child(
                        FormField::new("connector.api-key.field", "API key")
                            .control("connector.api-key")
                            .required(true)
                            .description("Stored in the operating-system credential vault.")
                            .child(self.api_key.clone()),
                    )
                    .child(
                        FormField::new("connector.initial-protocol.field", "Default protocol")
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
                                "Testing connection"
                            } else {
                                "Connect / Test"
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

    fn render_connected(&self, cx: &mut Context<Self>) -> gpui::AnyElement {
        let AppState::Connected {
            profile,
            models,
            preview,
        } = &self.state
        else {
            unreachable!("connected renderer requires connected state")
        };
        let mut content = div()
            .flex()
            .flex_col()
            .gap(px(16.0))
            .child(StatusLine::new("Connected", Tone::Success).id("connector.status"))
            .children(self.save_error.as_ref().map(|error| {
                Callout::new(
                    format!("Could not persist the latest Agent choices: {error}"),
                    Tone::Warning,
                )
                .id("connector.save-error")
            }))
            .child(
                DescriptionList::new("connector.summary")
                    .item(DescriptionItem::new(
                        "connector.summary.gateway",
                        "Gateway",
                        profile.base_url.to_string(),
                    ))
                    .item(DescriptionItem::new(
                        "connector.summary.models",
                        "Models",
                        models.len().to_string(),
                    ))
                    .item(DescriptionItem::new(
                        "connector.summary.profile",
                        "Profile",
                        profile.display_name.clone(),
                    )),
            )
            .child(div().text_size(px(20.0)).child("Agent defaults"));

        for agent in AgentId::ALL {
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
                            .child(div().child(agent.display_name()))
                            .child(protocol)
                            .child(model),
                    ),
            );
        }

        let this = cx.entity().downgrade();
        content = content.child(
            Button::new("connector.preview")
                .label("Preview projection")
                .secondary()
                .full_width(true)
                .on_click(move |_window, cx| {
                    let _ = this.update(cx, |this, cx| {
                        this.state.preview();
                        cx.notify();
                    });
                }),
        );
        if let Some(lines) = preview {
            content = content.child(
                Callout::new(
                    format!(
                        "Preview only — no Agent files were changed.\n{}\nApply arrives with the shared projection engine in phase 2.",
                        lines.join("\n")
                    ),
                    Tone::Info,
                )
                .id("connector.preview-summary"),
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
        let content = match &self.state {
            AppState::Loading => Card::new()
                .id("connector.loading")
                .padded(true)
                .child(StatusLine::new("Loading saved connection", Tone::Info))
                .into_any_element(),
            AppState::FirstRun => self.render_first_run(false, None, cx),
            AppState::Connecting => self.render_first_run(true, None, cx),
            AppState::Failed(error) => self.render_first_run(false, Some(error), cx),
            AppState::Connected { .. } => self.render_connected(cx),
        };
        div()
            .id("connector.root")
            .size_full()
            .overflow_y_scroll()
            .bg(theme.colors.canvas)
            .font_family(theme.typography.sans.clone())
            .text_color(theme.colors.text)
            .child(
                div()
                    .w_full()
                    .max_w(px(680.0))
                    .mx_auto()
                    .p(px(32.0))
                    .child(content),
            )
    }
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

fn main() {
    let directories = ProjectDirs::from("dev", "GatewayConnector", "GatewayConnector")
        .expect("the operating system provides a user data directory");
    let backend = Arc::new(
        ConnectorBackend::new(
            Arc::new(OsCredentialStore::new("dev.gatewayconnector.app")),
            Arc::new(JsonProfileStore::new(
                directories.data_local_dir().join("profiles.json"),
            )),
        )
        .expect("initialize GatewayConnector backend"),
    );
    let application = gpui_platform::application().with_assets(gpui_kit::assets::Assets);
    application.run(move |cx: &mut App| {
        gpui_kit::install(cx);
        let bounds = Bounds::centered(None, size(px(760.0), px(860.0)), cx);
        let backend = Arc::clone(&backend);
        cx.open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                ..Default::default()
            },
            move |window, cx| {
                let backend = Arc::clone(&backend);
                cx.new(|cx| ConnectorView::new(backend, window, cx))
            },
        )
        .expect("open GatewayConnector window");
        cx.activate(true);
    });
}
