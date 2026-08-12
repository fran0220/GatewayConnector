//! Credential-free UI preferences with crash-safe replacement.

use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use fs2::FileExt;
use serde::{Deserialize, Serialize};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Locale {
    #[default]
    En,
    ZhCn,
}

impl Locale {
    pub const ALL: [Self; 2] = [Self::En, Self::ZhCn];

    pub const fn id(self) -> &'static str {
        match self {
            Self::En => "en",
            Self::ZhCn => "zh-CN",
        }
    }

    pub const fn display_name(self) -> &'static str {
        match self {
            Self::En => "English",
            Self::ZhCn => "简体中文",
        }
    }

    pub fn from_id(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "en" => Some(Self::En),
            "zh" | "zh-cn" | "zh_cn" | "zh-hans" | "zh_hans" => Some(Self::ZhCn),
            _ => None,
        }
    }

    pub fn from_os(value: Option<&str>) -> Self {
        value.and_then(Self::from_id).unwrap_or_default()
    }

    /// Translates the generic app's fixed user-facing strings. Dynamic
    /// gateway and operating-system error details intentionally remain intact.
    pub fn text(self, english: &'static str) -> &'static str {
        if matches!(self, Self::En) {
            return english;
        }
        match english {
            "GatewayConnector" => "GatewayConnector",
            "Gateway" => "网关",
            "Connection" => "连接",
            "Agents" => "Agent",
            "Online services" => "在线服务",
            "Settings" => "设置",
            "Account" => "账户",
            "Usage" => "用量",
            "Billing" => "账单",
            "Model Plaza" => "模型广场",
            "Connected" => "已连接",
            "Not connected" => "未连接",
            "Loading saved connection" => "正在加载已保存的连接",
            "Connect a Gateway" => "连接网关",
            "Enter a Gateway URL with OpenAI-style model discovery and the native Agent APIs you intend to use." => {
                "输入支持 OpenAI 风格模型发现及所需 Agent 原生 API 的网关 URL。"
            }
            "Gateway base URL" => "网关基础 URL",
            "Root or nested prefix; /v1 and /v1/models forms are also accepted. HTTPS except loopback." => {
                "可输入根路径或嵌套前缀，也支持 /v1 和 /v1/models。除回环地址外须使用 HTTPS。"
            }
            "API key" => "API 密钥",
            "Stored in this app's local profile config. Leave blank when the platform advertises browser login." => {
                "保存在本应用本地配置中。平台提供浏览器登录时可留空。"
            }
            "Connect / Test" => "连接 / 测试",
            "Testing connection" => "正在测试连接",
            "Browser login available" => "可使用浏览器登录",
            "Platform" => "平台",
            "Security" => "安全性",
            "Continue in browser" => "在浏览器中继续",
            "Back" => "返回",
            "Clear error" => "清除错误",
            "Profile" => "配置档案",
            "Models" => "模型",
            "Detected Agents" => "已检测到的 Agent",
            "Refresh models and online services" => "刷新模型与在线服务",
            "Search model catalog" => "搜索模型目录",
            "Filters every Agent picker by model ID or provider; saved unavailable choices remain visible." => {
                "按模型 ID 或提供方筛选所有 Agent；不可用的已保存选项仍会显示。"
            }
            "Use for all Agents" => "用于所有 Agent",
            "Choose a shared model, then override any Agent on its page. Protocols are configured per Agent." => {
                "先选择共享模型，再到各 Agent 页面单独覆盖。协议须按 Agent 分别配置。"
            }
            "Connection overview" => "连接概览",
            "Agent default" => "Agent 默认值",
            "Detected" => "已检测",
            "Not detected" => "未检测",
            "Not advertised by this platform" => "此平台未声明支持",
            "Managed by this connection" => "由此连接管理",
            "Not managed" => "未管理",
            "Root" => "根目录",
            "Protocol" => "协议",
            "Model" => "模型",
            "Preview changes" => "预览更改",
            "Apply" => "应用",
            "Verify" => "验证",
            "Working…" => "处理中…",
            "Install a supported Agent before previewing configuration changes." => {
                "请先安装受支持的 Agent，再预览配置更改。"
            }
            "The Gateway currently offers no chat-capable models." => "网关目前未提供可对话模型。",
            "Fresh preview ready. No Agent files have been changed yet." => {
                "最新预览已就绪，尚未更改任何 Agent 文件。"
            }
            "Preview is required before Apply." => "应用前必须先预览。",
            "Managed files exist. Preview changes or disconnect this connection." => {
                "已存在托管文件。请预览更改或断开此连接。"
            }
            "Applying managed files…" => "正在应用托管文件…",
            "Changes applied. Verify the managed files before continuing." => {
                "更改已应用。请先验证托管文件再继续。"
            }
            "Verifying managed files…" => "正在验证托管文件…",
            "Managed files verified against the applied changes." => {
                "托管文件已通过已应用更改的验证。"
            }
            "Verification found drift. Preview again before applying." => {
                "验证发现漂移。再次应用前请重新预览。"
            }
            "Apply failed. Preview again before applying." => "应用失败。再次应用前请重新预览。",
            "Verification failed. Preview again before applying." => {
                "验证失败。再次应用前请重新预览。"
            }
            "Disconnecting managed files…" => "正在断开托管文件…",
            "Disconnect failed. Managed files may still be present." => {
                "断开失败。托管文件可能仍然存在。"
            }
            "No Agent file changes are needed." => "无需更改 Agent 文件。",
            "Verification found drift:" => "验证发现漂移：",
            "Direct connections do not invent MCP servers or Skills." => {
                "直连模式不会虚构 MCP 服务器或 Skills。"
            }
            "MCP servers" => "MCP 服务器",
            "Available from platform" => "平台提供",
            "Configured for Agents" => "已为 Agent 配置",
            "Skills" => "Skills",
            "No online services were provisioned." => "未配置在线服务。",
            "Language" => "语言",
            "Theme" => "主题",
            "System" => "跟随系统",
            "Light" => "浅色",
            "Dark" => "深色",
            "Security facts" => "安全说明",
            "Credentials stay in this app's local profile config. Bearers are sent only to exact allowlisted origins. Agent changes require a fresh preview." => {
                "凭据保存在本应用本地配置中。Bearer 仅发送到精确允许的来源。Agent 更改必须先生成最新预览。"
            }
            "Isolated mode" => "隔离模式",
            "Managing fixture Agents under this path; installed Agents are not being modified:" => {
                "仅管理此路径下的测试 Agent；不会修改已安装的 Agent："
            }
            "Disconnect Gateway and remove managed configuration" => "断开网关并移除托管配置",
            "Provider" => "提供方",
            "Chat capable" => "支持对话",
            "Other model" => "其他模型",
            "No models match this search." => "没有匹配此搜索的模型。",
            "Portal" => "门户",
            "Display name" => "显示名称",
            "Username" => "用户名",
            "Email" => "电子邮件",
            "Group" => "组",
            "Wallet remaining" => "钱包余额",
            "Lifetime used" => "累计用量",
            "Lifetime requests" => "累计请求数",
            "Subscriptions" => "订阅",
            "Wallet fallback allowed" => "允许钱包回退",
            "Yes" => "是",
            "No" => "否",
            "No active subscriptions." => "没有有效订阅。",
            "Preference could not be saved" => "无法保存偏好设置",
            _ => english,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ThemePreference {
    #[default]
    System,
    Light,
    Dark,
}

impl ThemePreference {
    pub const ALL: [Self; 3] = [Self::System, Self::Light, Self::Dark];

    pub const fn id(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Light => "light",
            Self::Dark => "dark",
        }
    }

    pub fn from_id(value: &str) -> Option<Self> {
        match value {
            "system" => Some(Self::System),
            "light" => Some(Self::Light),
            "dark" => Some(Self::Dark),
            _ => None,
        }
    }

    pub fn display_name(self, locale: Locale) -> &'static str {
        locale.text(match self {
            Self::System => "System",
            Self::Light => "Light",
            Self::Dark => "Dark",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Preferences {
    pub locale: Locale,
    pub theme: ThemePreference,
}

impl Default for Preferences {
    fn default() -> Self {
        Self {
            locale: Locale::from_os(sys_locale::get_locale().as_deref()),
            theme: ThemePreference::System,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PreferenceStore {
    path: PathBuf,
}

impl PreferenceStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn load(&self) -> Preferences {
        self.load_or_else(Preferences::default)
    }

    pub fn load_or(&self, fallback: Preferences) -> Preferences {
        self.load_or_else(|| fallback)
    }

    fn load_or_else(&self, fallback: impl FnOnce() -> Preferences) -> Preferences {
        self.with_lock(|| fs::read(&self.path))
            .ok()
            .and_then(Result::ok)
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_else(fallback)
    }

    pub fn save(&self, preferences: &Preferences) -> io::Result<()> {
        self.with_lock(|| {
            let suffix = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let temporary = self
                .path
                .with_extension(format!("tmp-{}-{suffix}", std::process::id()));
            let result = (|| {
                let bytes = serde_json::to_vec_pretty(preferences)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&temporary)?;
                file.write_all(&bytes)?;
                file.write_all(b"\n")?;
                file.sync_all()?;
                replace_file(&temporary, &self.path)
            })();
            if result.is_err() {
                let _ = fs::remove_file(&temporary);
            }
            result
        })?
    }

    fn with_lock<T>(&self, operation: impl FnOnce() -> T) -> io::Result<T> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| io::Error::other("preference path has no parent"))?;
        fs::create_dir_all(parent)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(parent.join("preferences.lock"))?;
        lock.lock_exclusive()?;
        let value = operation();
        lock.unlock()?;
        Ok(value)
    }
}

#[cfg(not(windows))]
fn replace_file(from: &Path, to: &Path) -> io::Result<()> {
    fs::rename(from, to)
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn replace_file(from: &Path, to: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };
    let from = from
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let to = to
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    if unsafe {
        MoveFileExW(
            from.as_ptr(),
            to.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simplified_chinese_os_variants_are_supported() {
        assert_eq!(Locale::from_os(Some("zh-CN")), Locale::ZhCn);
        assert_eq!(Locale::from_os(Some("zh_Hans")), Locale::ZhCn);
        assert_eq!(Locale::from_os(Some("fr-FR")), Locale::En);
    }

    #[test]
    fn preferences_round_trip_without_credentials() {
        let directory = tempfile::tempdir().expect("tempdir");
        let store = PreferenceStore::new(directory.path().join("preferences.json"));
        let expected = Preferences {
            locale: Locale::ZhCn,
            theme: ThemePreference::Dark,
        };
        store.save(&expected).expect("save");
        assert_eq!(store.load(), expected);
        let json = fs::read_to_string(directory.path().join("preferences.json")).expect("read");
        assert!(!json.contains("credential"));
        assert!(!json.contains("token"));
    }

    #[test]
    fn malformed_preferences_fall_back_safely() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("preferences.json");
        fs::write(&path, b"not json").expect("write");
        let loaded = PreferenceStore::new(path).load();
        assert_eq!(loaded.theme, ThemePreference::System);
    }
}
