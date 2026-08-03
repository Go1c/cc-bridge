//! 防封体检与调度门禁。
//!
//! 协议指纹对齐之后，封号仍常死在：无代理、身份字段缺失、多号共出口、新号暴打。
//! 本模块提供：
//! - 账号级静态体检（proxy / identity / profile / 同代理密度）
//! - 可选出口 IP 探测（经账号代理）
//! - 调度门禁（硬伤账号不参与选号）
//! - 新号 warm-up 有效并发 / RPM 上限

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use once_cell::sync::Lazy;
use serde::Serialize;
use tokio::sync::RwLock;
use tracing::{debug, warn};

use crate::error::AppError;
use crate::model::account::{Account, AccountAuthType, AccountStatus};
use crate::service::version_profile::{
    DEFAULT_CLAUDE_CODE_VERSION, STAINLESS_RUNTIME_VERSION, normalize_version,
};
use crate::store::settings_store::SettingsStore;
use crate::tlsfp::get_request_client;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// 体检项严重级别。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingSeverity {
    /// 信息：不影响调度。
    Info,
    /// 警告：建议处理，默认不挡调度。
    Warn,
    /// 错误：开启 gate 时排除调度。
    Error,
}

/// 单条体检发现。
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub code: String,
    pub severity: FindingSeverity,
    pub message: String,
}

/// 账号防封体检报告。
#[derive(Debug, Clone, Serialize)]
pub struct AccountHealthReport {
    pub account_id: i64,
    pub email: String,
    pub status: String,
    pub schedulable_by_status: bool,
    pub antifraud_ok: bool,
    pub hard_block: bool,
    pub findings: Vec<Finding>,
    pub proxy_normalized: String,
    pub proxy_cohort_size: usize,
    pub warmup_active: bool,
    pub effective_concurrency: i32,
    pub effective_rpm_limit: i32,
    pub proxy_probe: Option<ProxyProbeResult>,
}

/// 出口 IP 探测结果。
#[derive(Debug, Clone, Serialize)]
pub struct ProxyProbeResult {
    pub ok: bool,
    pub exit_ip: String,
    pub latency_ms: u64,
    pub error: String,
    pub probed_at: String,
}

/// 全局防封策略快照。
#[derive(Debug, Clone)]
pub struct AntifraudPolicy {
    pub gate_enabled: bool,
    pub require_proxy: bool,
    pub require_identity: bool,
    pub max_accounts_per_proxy: usize,
    pub warmup_hours: i64,
    pub warmup_concurrency: i32,
    pub warmup_rpm: i32,
    pub default_auto_telemetry: bool,
    pub proxy_probe_ttl_secs: u64,
}

impl Default for AntifraudPolicy {
    fn default() -> Self {
        Self {
            gate_enabled: true,
            require_proxy: true,
            require_identity: true,
            max_accounts_per_proxy: 3,
            warmup_hours: 24,
            warmup_concurrency: 1,
            warmup_rpm: 12,
            default_auto_telemetry: true,
            proxy_probe_ttl_secs: 600,
        }
    }
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

static PROXY_PROBE_CACHE: Lazy<RwLock<HashMap<String, (Instant, ProxyProbeResult)>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

/// 防封体检与策略服务。
pub struct AntifraudService {
    settings: Arc<SettingsStore>,
    policy: RwLock<AntifraudPolicy>,
}

impl AntifraudService {
    pub fn new(settings: Arc<SettingsStore>) -> Self {
        Self {
            settings,
            policy: RwLock::new(AntifraudPolicy::default()),
        }
    }

    /// 从 settings 刷新内存策略。
    pub async fn reload_policy(&self) -> Result<(), AppError> {
        let all = self.settings.get_all().await.unwrap_or_default();
        let pol = AntifraudPolicy {
            gate_enabled: setting_bool(&all, "antifraud_gate_enabled", true),
            require_proxy: setting_bool(&all, "antifraud_require_proxy", true),
            require_identity: setting_bool(&all, "antifraud_require_identity", true),
            max_accounts_per_proxy: setting_usize(&all, "antifraud_max_accounts_per_proxy", 3),
            warmup_hours: setting_i64(&all, "antifraud_warmup_hours", 24),
            warmup_concurrency: setting_i32(&all, "antifraud_warmup_concurrency", 1).max(1),
            warmup_rpm: setting_i32(&all, "antifraud_warmup_rpm", 12).max(0),
            default_auto_telemetry: setting_bool(&all, "antifraud_default_auto_telemetry", true),
            proxy_probe_ttl_secs: setting_u64(&all, "antifraud_proxy_probe_ttl_secs", 600),
        };
        *self.policy.write().await = pol;
        Ok(())
    }

    /// 当前策略快照。
    pub async fn policy(&self) -> AntifraudPolicy {
        self.policy.read().await.clone()
    }

    /// 判断账号是否因防封硬伤被排除调度。
    pub async fn is_hard_blocked(&self, account: &Account, cohort_size: usize) -> bool {
        let pol = self.policy().await;
        if !pol.gate_enabled {
            return false;
        }
        let report = evaluate_account(account, &pol, cohort_size, None);
        report.hard_block
    }

    /// 生成单账号报告（不含实时探测）。
    pub async fn report_account(
        &self,
        account: &Account,
        cohort_size: usize,
        probe: Option<ProxyProbeResult>,
    ) -> AccountHealthReport {
        let pol = self.policy().await;
        evaluate_account(account, &pol, cohort_size, probe)
    }

    /// 批量报告（用于管理端总览）。
    pub async fn report_accounts(&self, accounts: &[Account]) -> Vec<AccountHealthReport> {
        let pol = self.policy().await;
        let density = proxy_density_map(accounts);
        accounts
            .iter()
            .map(|a| {
                let key = normalize_proxy_url(&a.proxy_url);
                let cohort = if key.is_empty() {
                    0
                } else {
                    *density.get(&key).unwrap_or(&0)
                };
                evaluate_account(a, &pol, cohort, None)
            })
            .collect()
    }

    /// 计算同代理密度表：normalized_proxy → active 账号数。
    pub fn proxy_density(&self, accounts: &[Account]) -> HashMap<String, usize> {
        proxy_density_map(accounts)
    }

    /// 经账号代理探测出口 IP（带缓存）。
    pub async fn probe_proxy_exit_ip(
        &self,
        proxy_url: &str,
    ) -> Result<ProxyProbeResult, AppError> {
        let pol = self.policy().await;
        let key = normalize_proxy_url(proxy_url);
        if key.is_empty() {
            return Ok(ProxyProbeResult {
                ok: false,
                exit_ip: String::new(),
                latency_ms: 0,
                error: "proxy_url 为空".into(),
                probed_at: Utc::now().to_rfc3339(),
            });
        }

        {
            let cache = PROXY_PROBE_CACHE.read().await;
            if let Some((at, hit)) = cache.get(&key) {
                if at.elapsed() < Duration::from_secs(pol.proxy_probe_ttl_secs) {
                    return Ok(hit.clone());
                }
            }
        }

        let result = probe_exit_ip(proxy_url).await;
        PROXY_PROBE_CACHE
            .write()
            .await
            .insert(key, (Instant::now(), result.clone()));
        Ok(result)
    }

    /// warm-up 期间有效并发。
    pub async fn effective_concurrency(&self, account: &Account) -> i32 {
        let pol = self.policy().await;
        effective_concurrency(account, &pol)
    }

    /// warm-up 期间有效 RPM（0 = 不额外限制，沿用账号配置）。
    pub async fn effective_rpm_limit(&self, account: &Account) -> i32 {
        let pol = self.policy().await;
        effective_rpm_limit(account, &pol)
    }
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

fn evaluate_account(
    account: &Account,
    pol: &AntifraudPolicy,
    cohort_size: usize,
    probe: Option<ProxyProbeResult>,
) -> AccountHealthReport {
    let mut findings = Vec::new();
    let proxy_key = normalize_proxy_url(&account.proxy_url);

    // --- proxy ---
    if proxy_key.is_empty() {
        findings.push(Finding {
            code: "proxy_missing".into(),
            severity: if pol.require_proxy {
                FindingSeverity::Error
            } else {
                FindingSeverity::Warn
            },
            message: "未配置 proxy_url：直连机房 IP 是高风险出口".into(),
        });
    } else if cohort_size > pol.max_accounts_per_proxy.max(1) {
        findings.push(Finding {
            code: "proxy_density_high".into(),
            severity: FindingSeverity::Warn,
            message: format!(
                "同一代理上有 {} 个 active 账号（阈值 {}），存在连坐风险",
                cohort_size, pol.max_accounts_per_proxy
            ),
        });
    }

    if let Some(ref p) = probe {
        if !p.ok {
            findings.push(Finding {
                code: "proxy_probe_failed".into(),
                severity: FindingSeverity::Warn,
                message: format!("代理出口探测失败: {}", p.error),
            });
        } else {
            findings.push(Finding {
                code: "proxy_probe_ok".into(),
                severity: FindingSeverity::Info,
                message: format!("出口 IP {}（{}ms）", p.exit_ip, p.latency_ms),
            });
        }
    }

    // --- identity ---
    let has_account_uuid = account
        .account_uuid
        .as_ref()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false);
    let has_org_uuid = account
        .organization_uuid
        .as_ref()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false);
    let has_sub = account
        .subscription_type
        .as_ref()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false);

    if account.auth_type == AccountAuthType::Oauth {
        if !has_account_uuid || !has_org_uuid {
            findings.push(Finding {
                code: "identity_incomplete".into(),
                severity: if pol.require_identity {
                    FindingSeverity::Error
                } else {
                    FindingSeverity::Warn
                },
                message: "OAuth 账号缺少 account_uuid 或 organization_uuid，遥测身份不一致".into(),
            });
        }
        if !has_sub {
            findings.push(Finding {
                code: "subscription_missing".into(),
                severity: FindingSeverity::Warn,
                message: "未填写 subscription_type（max/pro/team/enterprise）".into(),
            });
        }
        if !account.auto_telemetry {
            findings.push(Finding {
                code: "telemetry_off".into(),
                severity: FindingSeverity::Warn,
                message: "auto_telemetry 关闭：真实 Claude Code 会发遥测，长期静默偏异常".into(),
            });
        }
    }

    if account.device_id.trim().is_empty() {
        findings.push(Finding {
            code: "device_id_missing".into(),
            severity: FindingSeverity::Warn,
            message: "device_id 为空，将使用派生值，建议重新生成身份".into(),
        });
    }

    // --- profile consistency ---
    let env_version = account
        .canonical_env
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let env_version = normalize_version(env_version);
    if env_version != DEFAULT_CLAUDE_CODE_VERSION {
        findings.push(Finding {
            code: "profile_version_stale".into(),
            severity: FindingSeverity::Warn,
            message: format!(
                "账号画像 version={}，当前默认伪装版本={}（重启迁移或重建身份）",
                env_version, DEFAULT_CLAUDE_CODE_VERSION
            ),
        });
    }

    let node_version = account
        .canonical_env
        .get("node_version")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if !node_version.is_empty() && node_version != STAINLESS_RUNTIME_VERSION {
        findings.push(Finding {
            code: "node_runtime_mismatch".into(),
            severity: FindingSeverity::Warn,
            message: format!(
                "canonical_env.node_version={} 与 Stainless runtime {} 不一致",
                node_version, STAINLESS_RUNTIME_VERSION
            ),
        });
    }

    let is_bun = account
        .canonical_env
        .get("is_running_with_bun")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if env_version == DEFAULT_CLAUDE_CODE_VERSION && !is_bun {
        findings.push(Finding {
            code: "bun_flag_false".into(),
            severity: FindingSeverity::Info,
            message: format!(
                "{} 本机为 Bun 编译产物，建议 is_running_with_bun=true",
                DEFAULT_CLAUDE_CODE_VERSION
            ),
        });
    }

    // --- warm-up ---
    let warmup_active = is_warmup_active(account, pol.warmup_hours);
    if warmup_active {
        let warm_conc = effective_concurrency(account, pol);
        findings.push(Finding {
            code: "warmup_active".into(),
            severity: FindingSeverity::Info,
            message: format!(
                "新号 warm-up 中（{}h）：有效并发≤{}，RPM≤{}",
                pol.warmup_hours, warm_conc, pol.warmup_rpm
            ),
        });
    }

    let hard_block = findings
        .iter()
        .any(|f| f.severity == FindingSeverity::Error);
    let antifraud_ok = !findings
        .iter()
        .any(|f| matches!(f.severity, FindingSeverity::Error | FindingSeverity::Warn));

    AccountHealthReport {
        account_id: account.id,
        email: account.email.clone(),
        status: account.status.to_string(),
        schedulable_by_status: account.is_schedulable(),
        antifraud_ok,
        hard_block,
        findings,
        proxy_normalized: proxy_key,
        proxy_cohort_size: cohort_size,
        warmup_active,
        effective_concurrency: effective_concurrency(account, pol),
        effective_rpm_limit: effective_rpm_limit(account, pol),
        proxy_probe: probe,
    }
}

fn proxy_density_map(accounts: &[Account]) -> HashMap<String, usize> {
    let mut m = HashMap::new();
    for a in accounts {
        if a.status != AccountStatus::Active {
            continue;
        }
        let key = normalize_proxy_url(&a.proxy_url);
        if key.is_empty() {
            continue;
        }
        *m.entry(key).or_insert(0) += 1;
    }
    m
}

/// 规范化代理 URL 用于密度统计（去空白、小写 scheme/host 粗归一）。
pub fn normalize_proxy_url(raw: &str) -> String {
    let s = raw.trim();
    if s.is_empty() {
        return String::new();
    }
    // 去掉末尾 /
    let s = s.trim_end_matches('/');
    s.to_string()
}

fn is_warmup_active(account: &Account, warmup_hours: i64) -> bool {
    if account.skip_warmup {
        return false;
    }
    if warmup_hours <= 0 {
        return false;
    }
    let age = Utc::now().signed_duration_since(account.created_at);
    age < chrono::Duration::hours(warmup_hours)
}

fn effective_concurrency(account: &Account, pol: &AntifraudPolicy) -> i32 {
    let base = account.concurrency.max(1);
    if is_warmup_active(account, pol.warmup_hours) {
        // 账号级覆盖优先：>0 时用该值作为 warm-up 并发上限；0 跟随全局策略。
        let cap = if account.warmup_concurrency_override > 0 {
            account.warmup_concurrency_override
        } else {
            pol.warmup_concurrency
        };
        base.min(cap.max(1))
    } else {
        base
    }
}

fn effective_rpm_limit(account: &Account, pol: &AntifraudPolicy) -> i32 {
    let base = account.rpm_limit.max(0);
    if !is_warmup_active(account, pol.warmup_hours) || pol.warmup_rpm <= 0 {
        return base;
    }
    if base <= 0 {
        // 账号未设 RPM 时，warm-up 仍施加上限
        pol.warmup_rpm
    } else {
        base.min(pol.warmup_rpm)
    }
}

async fn probe_exit_ip(proxy_url: &str) -> ProxyProbeResult {
    let started = Instant::now();
    let client = get_request_client(proxy_url);
    let probed_at = Utc::now().to_rfc3339();
    // 使用简单 HTTPS 出口探测；失败不致命。
    let resp = client
        .get("https://api.ipify.org?format=json")
        .timeout(Duration::from_secs(12))
        .send()
        .await;
    let latency_ms = started.elapsed().as_millis() as u64;
    match resp {
        Ok(r) => {
            let status = r.status();
            match r.text().await {
                Ok(body) if status.is_success() => {
                    let ip = serde_json::from_str::<serde_json::Value>(&body)
                        .ok()
                        .and_then(|v| v.get("ip").and_then(|x| x.as_str()).map(|s| s.to_string()))
                        .unwrap_or_else(|| body.trim().to_string());
                    debug!(proxy = %proxy_url, ip = %ip, latency_ms, "proxy exit probe ok");
                    ProxyProbeResult {
                        ok: true,
                        exit_ip: ip,
                        latency_ms,
                        error: String::new(),
                        probed_at,
                    }
                }
                Ok(body) => ProxyProbeResult {
                    ok: false,
                    exit_ip: String::new(),
                    latency_ms,
                    error: format!("HTTP {} {}", status, body.chars().take(120).collect::<String>()),
                    probed_at,
                },
                Err(e) => ProxyProbeResult {
                    ok: false,
                    exit_ip: String::new(),
                    latency_ms,
                    error: e.to_string(),
                    probed_at,
                },
            }
        }
        Err(e) => {
            warn!(proxy = %proxy_url, error = %e, "proxy exit probe failed");
            ProxyProbeResult {
                ok: false,
                exit_ip: String::new(),
                latency_ms,
                error: e.to_string(),
                probed_at,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// settings helpers
// ---------------------------------------------------------------------------

fn setting_bool(map: &HashMap<String, String>, key: &str, default: bool) -> bool {
    map.get(key)
        .map(|v| v == "true" || v == "1" || v == "yes")
        .unwrap_or(default)
}

fn setting_usize(map: &HashMap<String, String>, key: &str, default: usize) -> usize {
    map.get(key)
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn setting_i64(map: &HashMap<String, String>, key: &str, default: i64) -> i64 {
    map.get(key)
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn setting_i32(map: &HashMap<String, String>, key: &str, default: i32) -> i32 {
    map.get(key)
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn setting_u64(map: &HashMap<String, String>, key: &str, default: u64) -> u64 {
    map.get(key)
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::account::{BillingMode, CanonicalProcessData, CanonicalPromptEnvData};
    use serde_json::json;

    fn sample_account() -> Account {
        Account {
            id: 1,
            name: "t".into(),
            email: "a@example.com".into(),
            status: AccountStatus::Active,
            auth_type: AccountAuthType::Oauth,
            setup_token: String::new(),
            access_token: "x".into(),
            refresh_token: "y".into(),
            expires_at: None,
            oauth_refreshed_at: None,
            auth_error: String::new(),
            proxy_url: "socks5h://1.2.3.4:1080".into(),
            device_id: "d".repeat(64),
            canonical_env: json!({
                "version": DEFAULT_CLAUDE_CODE_VERSION,
                "node_version": STAINLESS_RUNTIME_VERSION,
                "is_running_with_bun": true,
            }),
            canonical_prompt: serde_json::to_value(CanonicalPromptEnvData::default()).unwrap(),
            canonical_process: serde_json::to_value(CanonicalProcessData::default()).unwrap(),
            billing_mode: BillingMode::Strip,
            account_uuid: Some("acc".into()),
            organization_uuid: Some("org".into()),
            subscription_type: Some("max".into()),
            concurrency: 3,
            warmup_concurrency_override: 0,
            skip_warmup: false,
            priority: 50,
            rpm_limit: 0,
            rate_limited_at: None,
            rate_limit_reset_at: None,
            disable_reason: String::new(),
            auto_telemetry: true,
            auto_poll_usage: false,
            allow_1m_models: "opus,fable".into(),
            telemetry_count: 0,
            usage_data: json!({}),
            usage_fetched_at: None,
            created_at: Utc::now() - chrono::Duration::hours(48),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn healthy_oauth_account_is_ok() {
        let a = sample_account();
        let pol = AntifraudPolicy::default();
        let r = evaluate_account(&a, &pol, 1, None);
        assert!(!r.hard_block);
        assert!(r.antifraud_ok || r.findings.iter().all(|f| f.severity != FindingSeverity::Error));
    }

    #[test]
    fn missing_proxy_is_hard_block_when_required() {
        let mut a = sample_account();
        a.proxy_url.clear();
        let pol = AntifraudPolicy::default();
        let r = evaluate_account(&a, &pol, 0, None);
        assert!(r.hard_block);
        assert!(r.findings.iter().any(|f| f.code == "proxy_missing"));
    }

    #[test]
    fn missing_oauth_identity_is_hard_block() {
        let mut a = sample_account();
        a.account_uuid = None;
        a.organization_uuid = None;
        let pol = AntifraudPolicy::default();
        let r = evaluate_account(&a, &pol, 1, None);
        assert!(r.hard_block);
        assert!(r.findings.iter().any(|f| f.code == "identity_incomplete"));
    }

    #[test]
    fn warmup_reduces_concurrency() {
        let mut a = sample_account();
        a.created_at = Utc::now();
        a.concurrency = 5;
        let pol = AntifraudPolicy {
            warmup_hours: 24,
            warmup_concurrency: 1,
            ..AntifraudPolicy::default()
        };
        assert_eq!(effective_concurrency(&a, &pol), 1);
        a.created_at = Utc::now() - chrono::Duration::hours(48);
        assert_eq!(effective_concurrency(&a, &pol), 5);
    }

    #[test]
    fn skip_warmup_bypasses_warmup_limits() {
        let mut a = sample_account();
        a.created_at = Utc::now();
        a.concurrency = 8;
        a.skip_warmup = true;
        a.warmup_concurrency_override = 2; // 跳过时应忽略
        let pol = AntifraudPolicy {
            warmup_hours: 24,
            warmup_concurrency: 1,
            warmup_rpm: 12,
            ..AntifraudPolicy::default()
        };
        assert!(!is_warmup_active(&a, pol.warmup_hours));
        assert_eq!(effective_concurrency(&a, &pol), 8);
        // RPM 也不再被 warm-up 限制
        a.rpm_limit = 0;
        assert_eq!(effective_rpm_limit(&a, &pol), 0);
        a.skip_warmup = false;
        assert!(is_warmup_active(&a, pol.warmup_hours));
        assert_eq!(effective_concurrency(&a, &pol), 2);
    }

    #[test]
    fn account_warmup_concurrency_override_takes_priority() {
        let mut a = sample_account();
        a.created_at = Utc::now();
        a.concurrency = 10;
        a.warmup_concurrency_override = 5;
        let pol = AntifraudPolicy {
            warmup_hours: 24,
            warmup_concurrency: 1,
            ..AntifraudPolicy::default()
        };
        // 覆盖 5 < 账号并发 10 → 有效 5
        assert_eq!(effective_concurrency(&a, &pol), 5);
        // 覆盖高于账号并发时仍取 min
        a.warmup_concurrency_override = 20;
        assert_eq!(effective_concurrency(&a, &pol), 10);
        // 0 = 跟随全局
        a.warmup_concurrency_override = 0;
        assert_eq!(effective_concurrency(&a, &pol), 1);
        // warm-up 结束后忽略覆盖
        a.warmup_concurrency_override = 5;
        a.created_at = Utc::now() - chrono::Duration::hours(48);
        assert_eq!(effective_concurrency(&a, &pol), 10);
    }

    #[test]
    fn density_map_counts_active_only() {
        let mut a1 = sample_account();
        a1.id = 1;
        let mut a2 = sample_account();
        a2.id = 2;
        let mut a3 = sample_account();
        a3.id = 3;
        a3.status = AccountStatus::Disabled;
        let m = proxy_density_map(&[a1, a2, a3]);
        assert_eq!(m.get("socks5h://1.2.3.4:1080"), Some(&2));
    }
}
