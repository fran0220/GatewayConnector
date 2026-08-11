use crate::ApiKey;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    net::{Ipv4Addr, TcpListener},
    time::Duration,
};
use thiserror::Error;
use url::Url;

const CALLBACK_PATH: &str = "/callback";
const MAX_REQUEST_LINE: usize = 8192;
const MAX_TOKEN_RESPONSE_BYTES: u64 = 64 * 1024;

pub trait Browser: Send + Sync + std::fmt::Debug {
    fn open(&self, url: &Url) -> Result<(), PkceError>;
}
#[derive(Debug, Default)]
pub struct SystemBrowser;
impl Browser for SystemBrowser {
    fn open(&self, url: &Url) -> Result<(), PkceError> {
        webbrowser::open(url.as_str())
            .map(|_| ())
            .map_err(|_| PkceError::Browser)
    }
}

#[derive(Debug, Clone)]
pub struct PkceFlow {
    pub verifier: String,
    pub challenge: String,
    pub state: String,
}
impl PkceFlow {
    pub fn random() -> Self {
        let mut a = [0u8; 32];
        let mut b = [0u8; 24];
        rand::rng().fill_bytes(&mut a);
        rand::rng().fill_bytes(&mut b);
        Self::from_parts(URL_SAFE_NO_PAD.encode(a), URL_SAFE_NO_PAD.encode(b))
    }
    pub fn from_parts(verifier: String, state: String) -> Self {
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        Self {
            verifier,
            challenge,
            state,
        }
    }

    pub fn login(
        &self,
        authorize_url: &Url,
        token_url: &Url,
        client_id: &str,
        device_name: &str,
        browser: &dyn Browser,
    ) -> Result<ApiKey, PkceError> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        listener.set_nonblocking(false)?;
        let redirect_uri = format!(
            "http://127.0.0.1:{}{CALLBACK_PATH}",
            listener.local_addr()?.port()
        );
        let mut authorization = authorize_url.clone();
        authorization
            .query_pairs_mut()
            .append_pair("client", client_id)
            .append_pair("device_name", device_name)
            .append_pair("redirect_uri", &redirect_uri)
            .append_pair("code_challenge", &self.challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("state", &self.state);
        browser.open(&authorization)?;
        listener.set_nonblocking(true)?;
        let deadline = std::time::Instant::now() + Duration::from_secs(600);
        let code = loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    // A socket accepted from a nonblocking listener may inherit that mode on
                    // some platforms. Callback reads deliberately use the timeout below.
                    stream.set_nonblocking(false)?;
                    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
                    let mut bytes = Vec::new();
                    let mut byte = [0];
                    while bytes.len() <= MAX_REQUEST_LINE && stream.read(&mut byte)? == 1 {
                        bytes.push(byte[0]);
                        if bytes.ends_with(b"\r\n") {
                            break;
                        }
                    }
                    if bytes.len() > MAX_REQUEST_LINE {
                        return Err(PkceError::RequestTooLong);
                    }
                    let line =
                        std::str::from_utf8(&bytes).map_err(|_| PkceError::InvalidCallback)?;
                    let mut request = line.split_whitespace();
                    let method = request.next().unwrap_or("");
                    let target = request.next().unwrap_or("");
                    let valid_get = method == "GET";
                    let callback = Url::parse(&format!("http://127.0.0.1{target}")).ok();
                    let response = |stream: &mut std::net::TcpStream, status: &str, body: &str| {
                        write!(
                            stream,
                            "HTTP/1.1 {status}\r\nCache-Control: no-store\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        )
                    };
                    let Some(callback) =
                        callback.filter(|u| valid_get && u.path() == CALLBACK_PATH)
                    else {
                        response(&mut stream, "404 Not Found", "Ignored callback.")?;
                        continue;
                    };
                    let params: std::collections::HashMap<_, _> =
                        callback.query_pairs().into_owned().collect();
                    if params.get("state") != Some(&self.state) {
                        response(&mut stream, "400 Bad Request", "Ignored callback.")?;
                        continue;
                    }
                    if let Some(error) = params.get("error") {
                        response(&mut stream, "400 Bad Request", "Login denied.")?;
                        return Err(PkceError::Denied(error.clone()));
                    }
                    let code = params
                        .get("code")
                        .filter(|v| !v.is_empty())
                        .cloned()
                        .ok_or(PkceError::InvalidCallback)?;
                    response(&mut stream, "200 OK", "Login complete.")?;
                    break code;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if std::time::Instant::now() >= deadline {
                        return Err(PkceError::Timeout);
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
                Err(e) => return Err(e.into()),
            }
        };
        let client = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(15))
            .build()?;
        let response = client
            .post(token_url.clone())
            .json(&serde_json::json!({
                "code": code,
                "code_verifier": self.verifier,
                "redirect_uri": redirect_uri,
            }))
            .send()?;
        if response.status().is_redirection() {
            return Err(PkceError::TokenRedirect);
        }
        if !response.status().is_success() {
            return Err(PkceError::TokenStatus(response.status().as_u16()));
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_TOKEN_RESPONSE_BYTES)
        {
            return Err(PkceError::InvalidTokenResponse);
        }
        let mut bytes = Vec::new();
        response
            .take(MAX_TOKEN_RESPONSE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(PkceError::TokenRead)?;
        if bytes.len() as u64 > MAX_TOKEN_RESPONSE_BYTES {
            return Err(PkceError::InvalidTokenResponse);
        }
        let token: Token =
            serde_json::from_slice(&bytes).map_err(|_| PkceError::InvalidTokenResponse)?;
        if !token.token_type.eq_ignore_ascii_case("bearer") {
            return Err(PkceError::NotBearer);
        }
        ApiKey::new(token.access_token).map_err(|_| PkceError::NotBearer)
    }
}
#[derive(Deserialize)]
struct Token {
    access_token: String,
    token_type: String,
}
#[derive(Debug, Error)]
pub enum PkceError {
    #[error("could not open browser")]
    Browser,
    #[error("callback I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("sign-in timed out")]
    Timeout,
    #[error("invalid callback")]
    InvalidCallback,
    #[error("callback request line too long")]
    RequestTooLong,
    #[error("callback state mismatch")]
    StateMismatch,
    #[error("sign-in denied: {0}")]
    Denied(String),
    #[error("token request failed: {0}")]
    Network(#[from] reqwest::Error),
    #[error("token endpoint redirected; authorization code was not forwarded")]
    TokenRedirect,
    #[error("token endpoint returned HTTP {0}")]
    TokenStatus(u16),
    #[error("could not read the token response: {0}")]
    TokenRead(std::io::Error),
    #[error("token endpoint returned invalid JSON or omitted required fields")]
    InvalidTokenResponse,
    #[error("token endpoint did not return a bearer access_token")]
    NotBearer,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::BTreeMap, net::TcpStream, sync::Mutex, thread};
    use tiny_http::{Header, Request, Response, Server, StatusCode};

    const MOCK_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

    fn recv_request(server: &Server, context: &str) -> Request {
        server
            .recv_timeout(MOCK_REQUEST_TIMEOUT)
            .unwrap_or_else(|error| panic!("{context}: {error}"))
            .unwrap_or_else(|| panic!("timed out waiting for {context}"))
    }

    #[derive(Debug, Clone, Copy)]
    enum Callback {
        WrongPath,
        WrongState,
        Code,
        DelayedCode,
        Denied,
    }

    #[derive(Debug)]
    struct CallbackBrowser {
        callbacks: Vec<Callback>,
        opened: Mutex<Option<Url>>,
    }

    impl CallbackBrowser {
        fn new(callbacks: impl Into<Vec<Callback>>) -> Self {
            Self {
                callbacks: callbacks.into(),
                opened: Mutex::new(None),
            }
        }

        fn opened(&self) -> Url {
            self.opened
                .lock()
                .expect("browser lock")
                .clone()
                .expect("authorization URL")
        }
    }

    impl Browser for CallbackBrowser {
        fn open(&self, url: &Url) -> Result<(), PkceError> {
            *self.opened.lock().map_err(|_| PkceError::Browser)? = Some(url.clone());
            let values: BTreeMap<_, _> = url.query_pairs().into_owned().collect();
            let redirect = Url::parse(
                values
                    .get("redirect_uri")
                    .ok_or(PkceError::InvalidCallback)?,
            )
            .map_err(|_| PkceError::InvalidCallback)?;
            let state = values
                .get("state")
                .cloned()
                .ok_or(PkceError::InvalidCallback)?;
            let callbacks = self.callbacks.clone();
            thread::spawn(move || {
                for callback in callbacks {
                    let mut stream = TcpStream::connect((
                        Ipv4Addr::LOCALHOST,
                        redirect.port().expect("callback port"),
                    ))
                    .expect("connect callback");
                    if matches!(callback, Callback::DelayedCode) {
                        thread::sleep(Duration::from_millis(100));
                    }
                    let target = match callback {
                        Callback::WrongPath => format!("/other?code=ignored&state={state}"),
                        Callback::WrongState => "/callback?code=ignored&state=wrong".to_owned(),
                        Callback::Code | Callback::DelayedCode => {
                            format!("/callback?code=test-code&state={state}")
                        }
                        Callback::Denied => {
                            format!("/callback?error=access_denied&state={state}")
                        }
                    };
                    write!(stream, "GET {target} HTTP/1.1\r\n").expect("write callback");
                    let mut response = Vec::new();
                    stream
                        .read_to_end(&mut response)
                        .expect("read callback response");
                    assert!(response.starts_with(b"HTTP/1.1"));
                }
            });
            Ok(())
        }
    }

    fn spawn_token_response(
        status: u16,
        body: &'static str,
        location: Option<String>,
    ) -> (Url, thread::JoinHandle<serde_json::Value>) {
        let server = Server::http("127.0.0.1:0").expect("token server");
        let url = Url::parse(&format!("http://{}/token", server.server_addr())).expect("token URL");
        let handle = thread::spawn(move || {
            let mut request = recv_request(&server, "PKCE token request");
            assert_eq!(request.method().as_str(), "POST");
            assert_eq!(request.url(), "/token");
            let mut request_body = String::new();
            request
                .as_reader()
                .read_to_string(&mut request_body)
                .expect("token request body");
            let value = serde_json::from_str(&request_body).expect("token request JSON");
            let mut response = Response::from_string(body).with_status_code(StatusCode(status));
            if let Some(location) = location {
                response
                    .add_header(Header::from_bytes("Location", location).expect("redirect header"));
            }
            request.respond(response).expect("token response");
            value
        });
        (url, handle)
    }

    #[test]
    fn rfc_vector() {
        let f = PkceFlow::from_parts(
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".into(),
            "state".into(),
        );
        assert_eq!(f.challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn browser_login_uses_schema_v2_pkce_and_keeps_only_access_token() {
        let (token_url, token_handle) = spawn_token_response(
            200,
            r#"{"access_token":"durable-access","token_type":"Bearer","refresh_token":"must-ignore","account":{"id":1}}"#,
            None,
        );
        let browser = CallbackBrowser::new(vec![
            Callback::WrongPath,
            Callback::WrongState,
            Callback::Code,
        ]);
        let flow = PkceFlow::from_parts("fixed-verifier".into(), "fixed-state".into());
        let token = flow
            .login(
                &Url::parse("https://platform.example/authorize").expect("authorize URL"),
                &token_url,
                "connector-client",
                "Desktop Connector",
                &browser,
            )
            .expect("browser login");
        assert_eq!(token.expose_secret(), "durable-access");

        let opened = browser.opened();
        let query: BTreeMap<_, _> = opened.query_pairs().into_owned().collect();
        assert_eq!(
            query.get("client").map(String::as_str),
            Some("connector-client")
        );
        assert_eq!(
            query.get("device_name").map(String::as_str),
            Some("Desktop Connector")
        );
        assert_eq!(
            query.get("code_challenge_method").map(String::as_str),
            Some("S256")
        );
        assert_eq!(query.get("state").map(String::as_str), Some("fixed-state"));
        assert!(query.get("redirect_uri").is_some_and(
            |value| value.starts_with("http://127.0.0.1:") && value.ends_with("/callback")
        ));

        let request = token_handle.join().expect("token server");
        assert_eq!(request["code"], "test-code");
        assert_eq!(request["code_verifier"], "fixed-verifier");
        assert_eq!(request["redirect_uri"], query["redirect_uri"]);
        assert_eq!(request.as_object().expect("object").len(), 3);
    }

    #[test]
    fn callback_may_connect_before_writing_request() {
        let (token_url, token_handle) = spawn_token_response(
            200,
            r#"{"access_token":"token","token_type":"Bearer"}"#,
            None,
        );
        let browser = CallbackBrowser::new(vec![Callback::DelayedCode]);
        let token = PkceFlow::from_parts("verifier".into(), "state".into())
            .login(
                &Url::parse("https://platform.example/authorize").expect("authorize URL"),
                &token_url,
                "client",
                "device",
                &browser,
            )
            .expect("delayed callback login");
        assert_eq!(token.expose_secret(), "token");
        token_handle.join().expect("token server");
    }

    #[test]
    fn token_redirect_is_rejected_without_contacting_target() {
        let target = Server::http("127.0.0.1:0").expect("redirect target");
        let target_url = format!("http://{}/stolen", target.server_addr());
        let (token_url, token_handle) = spawn_token_response(302, "", Some(target_url));
        let browser = CallbackBrowser::new(vec![Callback::Code]);
        let error = PkceFlow::from_parts("verifier".into(), "state".into())
            .login(
                &Url::parse("https://platform.example/authorize").expect("authorize URL"),
                &token_url,
                "client",
                "device",
                &browser,
            )
            .expect_err("token redirect");
        token_handle.join().expect("token server");
        assert!(matches!(error, PkceError::TokenRedirect));
        assert!(
            target
                .recv_timeout(Duration::from_millis(250))
                .is_ok_and(|request| request.is_none())
        );
    }

    #[test]
    fn token_response_requires_access_token_and_bearer_type() {
        for (body, expected) in [
            (r#"{"access_token":"value","token_type":"mac"}"#, "bearer"),
            (r#"{"token_type":"Bearer"}"#, "required fields"),
        ] {
            let (token_url, token_handle) = spawn_token_response(200, body, None);
            let browser = CallbackBrowser::new(vec![Callback::Code]);
            let error = PkceFlow::from_parts("verifier".into(), "state".into())
                .login(
                    &Url::parse("https://platform.example/authorize").expect("authorize URL"),
                    &token_url,
                    "client",
                    "device",
                    &browser,
                )
                .expect_err("invalid token response");
            token_handle.join().expect("token server");
            assert!(error.to_string().contains(expected), "{error}");
        }
    }

    #[test]
    fn oauth_denial_is_actionable_and_does_not_call_token_endpoint() {
        let token_server = Server::http("127.0.0.1:0").expect("token server");
        let token_url =
            Url::parse(&format!("http://{}/token", token_server.server_addr())).expect("token URL");
        let browser = CallbackBrowser::new(vec![Callback::Denied]);
        let error = PkceFlow::from_parts("verifier".into(), "state".into())
            .login(
                &Url::parse("https://platform.example/authorize").expect("authorize URL"),
                &token_url,
                "client",
                "device",
                &browser,
            )
            .expect_err("denied login");
        assert!(matches!(error, PkceError::Denied(value) if value == "access_denied"));
        assert!(
            token_server
                .recv_timeout(Duration::from_millis(250))
                .is_ok_and(|request| request.is_none())
        );
    }
}
