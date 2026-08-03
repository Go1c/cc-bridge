use std::env;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

#[derive(Clone)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub redis: Option<RedisConfig>,
    pub admin: AdminConfig,
    pub log_level: String,
    pub usage_poll_interval: Duration,
    /// 上游 TTFB / connect 超时与同账号安全重试（见 `UpstreamTimeoutConfig`）。
    pub upstream_timeouts: UpstreamTimeoutConfig,
}

/// 上游传输超时与 TTFB 安全重试配置。
///
/// 设计动机（生产事故结论）：
/// - 同一账号可一边正常服务其他请求（TTFB 1–4s），一边有单请求挂满 120s；
/// - 因此 **不能** 把 TTFB 当 429 去隔离/换号；
/// - 用户痛点是静默等满 120s + 不可归因错误；归因 + connect 快失败 + 预响应安全重试更有效。
///
/// 默认：
/// - `UPSTREAM_TTFB_TIMEOUT_SECS=120`：合法慢 Opus/长上下文首 token 仍可能接近该值。
/// - `UPSTREAM_CONNECT_TIMEOUT_SECS=15`：TCP/代理/TLS 握手卡死应快失败，不占满 TTFB 预算。
/// - `UPSTREAM_TTFB_RETRY_ENABLED=true` + `UPSTREAM_TTFB_RETRY_MAX=1`：仅在尚未向客户端写任何
///   响应字节时允许同账号再试一次（非流式，或流式但 headers 尚未发出）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UpstreamTimeoutConfig {
    pub ttfb_timeout: Duration,
    pub connect_timeout: Duration,
    pub ttfb_retry_enabled: bool,
    pub ttfb_retry_max: u32,
}

impl Default for UpstreamTimeoutConfig {
    fn default() -> Self {
        Self {
            ttfb_timeout: Duration::from_secs(120),
            connect_timeout: Duration::from_secs(15),
            // 默认开启：仅 pre-response 安全重试，不会无限循环（max=1）。
            ttfb_retry_enabled: true,
            ttfb_retry_max: 1,
        }
    }
}

impl UpstreamTimeoutConfig {
    /// 从环境变量加载；非法值回退默认。
    pub fn from_env() -> Self {
        let defaults = Self::default();
        Self {
            ttfb_timeout: Duration::from_secs(parse_env_u64(
                "UPSTREAM_TTFB_TIMEOUT_SECS",
                defaults.ttfb_timeout.as_secs(),
            )),
            connect_timeout: Duration::from_secs(parse_env_u64(
                "UPSTREAM_CONNECT_TIMEOUT_SECS",
                defaults.connect_timeout.as_secs(),
            )),
            ttfb_retry_enabled: parse_env_bool(
                "UPSTREAM_TTFB_RETRY_ENABLED",
                defaults.ttfb_retry_enabled,
            ),
            ttfb_retry_max: parse_env_u64(
                "UPSTREAM_TTFB_RETRY_MAX",
                defaults.ttfb_retry_max as u64,
            )
            .min(u32::MAX as u64) as u32,
        }
    }
}

// 进程级原子：启动时由 Config::load 写入；gateway/tlsfp 读取；测试可覆盖。
static UPSTREAM_TTFB_TIMEOUT_SECS: AtomicU64 = AtomicU64::new(120);
static UPSTREAM_CONNECT_TIMEOUT_SECS: AtomicU64 = AtomicU64::new(15);
static UPSTREAM_TTFB_RETRY_ENABLED: AtomicBool = AtomicBool::new(true);
static UPSTREAM_TTFB_RETRY_MAX: AtomicU64 = AtomicU64::new(1);

/// 将上游超时配置写入进程级原子（启动时调用一次即可）。
pub fn apply_upstream_timeout_config(cfg: UpstreamTimeoutConfig) {
    UPSTREAM_TTFB_TIMEOUT_SECS.store(cfg.ttfb_timeout.as_secs().max(1), Ordering::Relaxed);
    UPSTREAM_CONNECT_TIMEOUT_SECS.store(cfg.connect_timeout.as_secs().max(1), Ordering::Relaxed);
    UPSTREAM_TTFB_RETRY_ENABLED.store(cfg.ttfb_retry_enabled, Ordering::Relaxed);
    UPSTREAM_TTFB_RETRY_MAX.store(cfg.ttfb_retry_max as u64, Ordering::Relaxed);
}

/// 读取当前进程级上游超时配置。
pub fn upstream_timeout_config() -> UpstreamTimeoutConfig {
    UpstreamTimeoutConfig {
        ttfb_timeout: Duration::from_secs(UPSTREAM_TTFB_TIMEOUT_SECS.load(Ordering::Relaxed).max(1)),
        connect_timeout: Duration::from_secs(
            UPSTREAM_CONNECT_TIMEOUT_SECS.load(Ordering::Relaxed).max(1),
        ),
        ttfb_retry_enabled: UPSTREAM_TTFB_RETRY_ENABLED.load(Ordering::Relaxed),
        ttfb_retry_max: UPSTREAM_TTFB_RETRY_MAX.load(Ordering::Relaxed) as u32,
    }
}

fn parse_env_u64(key: &str, default: u64) -> u64 {
    env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|n| *n > 0)
        .unwrap_or(default)
}

fn parse_env_bool(key: &str, default: bool) -> bool {
    match env::var(key) {
        Ok(raw) => match raw.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => true,
            "0" | "false" | "no" | "off" => false,
            _ => default,
        },
        Err(_) => default,
    }
}

#[derive(Clone)]
pub struct ServerConfig {
    pub port: u16,
    pub host: String,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
}

#[derive(Clone)]
pub struct DatabaseConfig {
    pub driver: Option<String>,
    pub dsn: Option<String>,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: String,
    pub dbname: String,
}

#[derive(Clone)]
pub struct RedisConfig {
    pub host: String,
    pub port: u16,
    pub password: String,
    pub db: i64,
}

#[derive(Clone)]
pub struct AdminConfig {
    pub password: String,
}

impl DatabaseConfig {
    pub fn driver(&self) -> String {
        self.driver.clone().unwrap_or_else(|| "sqlite".into())
    }

    pub fn dsn(&self) -> String {
        if let Some(dsn) = &self.dsn {
            return dsn.clone();
        }
        if self.driver() == "sqlite" {
            return "data/claude-code-gateway.db".into();
        }
        format!(
            "postgres://{}:{}@{}:{}/{}?sslmode=disable",
            self.user, self.password, self.host, self.port, self.dbname
        )
    }
}

impl Config {
    pub fn load() -> Self {
        dotenvy::dotenv().ok();

        let redis = env::var("REDIS_HOST").ok().map(|host| RedisConfig {
            host,
            port: env::var("REDIS_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(6379),
            password: env::var("REDIS_PASSWORD").unwrap_or_default(),
            db: env::var("REDIS_DB")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
        });

        let upstream_timeouts = UpstreamTimeoutConfig::from_env();
        // 启动时同步到进程级原子，供 gateway/tlsfp 读取。
        apply_upstream_timeout_config(upstream_timeouts);

        Config {
            server: ServerConfig {
                port: env::var("SERVER_PORT")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(5674),
                host: env::var("SERVER_HOST").unwrap_or_else(|_| "0.0.0.0".into()),
                tls_cert: env::var("TLS_CERT_FILE").ok(),
                tls_key: env::var("TLS_KEY_FILE").ok(),
            },
            database: DatabaseConfig {
                driver: env::var("DATABASE_DRIVER").ok(),
                dsn: env::var("DATABASE_DSN").ok(),
                host: env::var("DATABASE_HOST").unwrap_or_else(|_| "localhost".into()),
                port: env::var("DATABASE_PORT")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(5432),
                user: env::var("DATABASE_USER").unwrap_or_else(|_| "postgres".into()),
                password: env::var("DATABASE_PASSWORD").unwrap_or_default(),
                dbname: env::var("DATABASE_DBNAME")
                    .unwrap_or_else(|_| "claude_code_gateway".into()),
            },
            redis,
            admin: AdminConfig {
                password: env::var("ADMIN_PASSWORD").unwrap_or_else(|_| "admin".into()),
            },
            log_level: env::var("LOG_LEVEL").unwrap_or_else(|_| "info".into()),
            usage_poll_interval: Duration::from_secs(
                env::var("USAGE_POLL_INTERVAL_SECS")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(300),
            ),
            upstream_timeouts,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_timeout_defaults_are_conservative() {
        let d = UpstreamTimeoutConfig::default();
        assert_eq!(d.ttfb_timeout, Duration::from_secs(120));
        assert_eq!(d.connect_timeout, Duration::from_secs(15));
        assert!(d.ttfb_retry_enabled);
        assert_eq!(d.ttfb_retry_max, 1);
    }

    #[test]
    fn apply_upstream_timeout_config_is_readable() {
        let cfg = UpstreamTimeoutConfig {
            ttfb_timeout: Duration::from_secs(3),
            connect_timeout: Duration::from_secs(2),
            ttfb_retry_enabled: false,
            ttfb_retry_max: 0,
        };
        apply_upstream_timeout_config(cfg);
        let got = upstream_timeout_config();
        assert_eq!(got, cfg);
        // restore defaults so other tests are not flaky
        apply_upstream_timeout_config(UpstreamTimeoutConfig::default());
    }
}
