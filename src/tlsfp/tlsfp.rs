use once_cell::sync::Lazy;
use rustls::craft::{
    CraftExtension, ExtensionSpec, Fingerprint, GreaseOrCipher, GreaseOrCurve, GreaseOrVersion,
    KeepExtension,
};
use rustls::crypto::{ActiveKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::internal::msgs::base::Payload;
use rustls::internal::msgs::enums::{ECPointFormat, ExtensionType, PSKKeyExchangeMode};
use rustls::internal::msgs::handshake::ClientExtension;
use rustls::{CipherSuite, Error, NamedGroup, ProtocolVersion, RootCertStore, SignatureScheme};
use static_init::dynamic;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

// ---------------------------------------------------------------------------
// X25519MLKEM768 混合密钥交换（真实实现）
// 按 draft-ietf-tls-ecdhe-mlkem：
//   client key_share = ML-KEM encaps key (1184) || X25519 pub (32) = 1216 bytes
//   server key_share = ML-KEM ciphertext (1088) || X25519 pub (32) = 1120 bytes
//   shared_secret    = ML-KEM shared secret (32) || X25519 shared (32) = 64 bytes
// ---------------------------------------------------------------------------
const X25519MLKEM768_GROUP: NamedGroup = NamedGroup::Unknown(0x11EC);

#[derive(Debug)]
struct X25519Mlkem768KxGroup;

impl SupportedKxGroup for X25519Mlkem768KxGroup {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        use ml_kem::{EncodedSizeUser, KemCore, MlKem768};

        let mut rng = rand::thread_rng();

        // ML-KEM-768 keypair
        let (dk, ek) = MlKem768::generate(&mut rng);
        let ek_bytes = &ek.as_bytes();

        // X25519 keypair
        let x25519_secret = x25519_dalek::StaticSecret::random_from_rng(&mut rng);
        let x25519_public = x25519_dalek::PublicKey::from(&x25519_secret);

        // client key_share = ek (1184) || x25519_pub (32)
        let mut pub_key = Vec::with_capacity(1216);
        pub_key.extend_from_slice(ek_bytes);
        pub_key.extend_from_slice(x25519_public.as_bytes());

        Ok(Box::new(X25519Mlkem768ActiveKx {
            dk,
            x25519_secret,
            pub_key,
        }))
    }

    fn name(&self) -> NamedGroup {
        X25519MLKEM768_GROUP
    }
}

struct X25519Mlkem768ActiveKx {
    dk: ml_kem::kem::DecapsulationKey<ml_kem::MlKem768Params>,
    x25519_secret: x25519_dalek::StaticSecret,
    pub_key: Vec<u8>,
}

impl std::fmt::Debug for X25519Mlkem768ActiveKx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X25519Mlkem768ActiveKx").finish()
    }
}

impl ActiveKeyExchange for X25519Mlkem768ActiveKx {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        use ml_kem::kem::Decapsulate as _;

        // server key_share = ciphertext (1088) || x25519_pub (32) = 1120 bytes
        if peer_pub_key.len() != 1120 {
            return Err(Error::General(format!(
                "X25519MLKEM768: invalid server key_share length {}",
                peer_pub_key.len()
            )));
        }

        let (ct_bytes, x25519_peer) = peer_pub_key.split_at(1088);

        // ML-KEM decapsulation
        let ct: ml_kem::Ciphertext<ml_kem::MlKem768> = ct_bytes
            .try_into()
            .map_err(|_| Error::General("ML-KEM: invalid ciphertext".into()))?;
        let mlkem_ss = self
            .dk
            .decapsulate(&ct)
            .map_err(|_| Error::General("ML-KEM decapsulation failed".into()))?;

        // X25519 DH
        let x25519_peer_key: [u8; 32] = x25519_peer
            .try_into()
            .map_err(|_| Error::General("X25519: invalid peer key".into()))?;
        let x25519_peer_pub = x25519_dalek::PublicKey::from(x25519_peer_key);
        let x25519_ss = self.x25519_secret.diffie_hellman(&x25519_peer_pub);

        // shared_secret = mlkem_ss (32) || x25519_ss (32)
        let mut shared = Vec::with_capacity(64);
        shared.extend_from_slice(mlkem_ss.as_ref());
        shared.extend_from_slice(x25519_ss.as_bytes());

        Ok(SharedSecret::from(&shared[..]))
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }

    fn group(&self) -> NamedGroup {
        X25519MLKEM768_GROUP
    }
}

// X448 fake group（ring 不支持，只声明不使用）
#[derive(Debug)]
struct FakeKxGroup(NamedGroup);

impl SupportedKxGroup for FakeKxGroup {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        Err(Error::General(format!(
            "key exchange not supported for {:?}",
            self.0
        )))
    }
    fn name(&self) -> NamedGroup {
        self.0
    }
}

static X25519MLKEM768_KX: X25519Mlkem768KxGroup = X25519Mlkem768KxGroup;
static FAKE_X448: FakeKxGroup = FakeKxGroup(NamedGroup::Unknown(0x001E));
static REQUEST_CLIENT_POOL_ENABLED: AtomicBool = AtomicBool::new(true);
static REQUEST_CLIENT_CACHE: Lazy<RwLock<HashMap<String, reqwest::Client>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

macro_rules! static_ref {
    ($val:expr, $type:ty) => {{
        static X: $type = $val;
        X
    }};
}

// ---------------------------------------------------------------------------
// Node.js 密码套件（17 个，对齐真实 claude-cli/2.1.183 抓取的 JA3）
// 顺序：TLS1.3(1301,1302,1303) → ECDHE-GCM → ChaCha20 → ECDHE-CBC → RSA-GCM → RSA-CBC
// ---------------------------------------------------------------------------
#[dynamic]
pub static NODEJS_CIPHER: Vec<GreaseOrCipher> = vec![
    GreaseOrCipher::T(CipherSuite::TLS13_AES_128_GCM_SHA256), // 0x1301
    GreaseOrCipher::T(CipherSuite::TLS13_AES_256_GCM_SHA384), // 0x1302
    GreaseOrCipher::T(CipherSuite::TLS13_CHACHA20_POLY1305_SHA256), // 0x1303
    GreaseOrCipher::T(CipherSuite::Unknown(0xC02B)),
    GreaseOrCipher::T(CipherSuite::Unknown(0xC02F)),
    GreaseOrCipher::T(CipherSuite::Unknown(0xC02C)),
    GreaseOrCipher::T(CipherSuite::Unknown(0xC030)),
    GreaseOrCipher::T(CipherSuite::Unknown(0xCCA9)),
    GreaseOrCipher::T(CipherSuite::Unknown(0xCCA8)),
    GreaseOrCipher::T(CipherSuite::Unknown(0xC009)),
    GreaseOrCipher::T(CipherSuite::Unknown(0xC013)),
    GreaseOrCipher::T(CipherSuite::Unknown(0xC00A)),
    GreaseOrCipher::T(CipherSuite::Unknown(0xC014)),
    GreaseOrCipher::T(CipherSuite::Unknown(0x009C)),
    GreaseOrCipher::T(CipherSuite::Unknown(0x009D)),
    GreaseOrCipher::T(CipherSuite::Unknown(0x002F)),
    GreaseOrCipher::T(CipherSuite::Unknown(0x0035)),
];

// ---------------------------------------------------------------------------
// Node.js 扩展列表（14 个，精确顺序对齐真实 claude-cli/2.1.183 抓取的 JA3）
// ---------------------------------------------------------------------------
#[dynamic]
pub static NODEJS_EXTENSION: Vec<ExtensionSpec> = {
    use ExtensionSpec::*;
    use KeepExtension::*;
    vec![
        // 1. server_name (0)
        Keep(Must(ExtensionType::ServerName)),
        // 2. extended_master_secret (23)
        Rustls(ClientExtension::ExtendedMasterSecretRequest),
        // 3. renegotiation_info (65281)
        Craft(CraftExtension::RenegotiationInfo),
        // 4. supported_groups (10) — 仅 3 条经典曲线，无后量子/无 X448/无 FFDHE
        Rustls(ClientExtension::NamedGroups(vec![
            NamedGroup::X25519,    // 29
            NamedGroup::secp256r1, // 23
            NamedGroup::secp384r1, // 24
        ])),
        // 5. ec_point_formats (11) — 仅 uncompressed
        Rustls(ClientExtension::EcPointFormats(vec![
            ECPointFormat::Uncompressed,
        ])),
        // 6. session_ticket (35)
        Keep(OrDefault(
            ExtensionType::SessionTicket,
            ClientExtension::SessionTicket(
                rustls::internal::msgs::handshake::ClientSessionTicket::Offer(Payload(vec![])),
            ),
        )),
        // 7. ALPN (16)
        Craft(CraftExtension::Protocols(&[b"http/1.1"])),
        // 8. status_request (5) — OCSP: status_type=1，空 responder/extensions
        Rustls(ClientExtension::Unknown(
            rustls::internal::msgs::handshake::UnknownExtension {
                typ: ExtensionType::Unknown(5),
                payload: Payload(vec![0x01, 0x00, 0x00, 0x00, 0x00]),
            },
        )),
        // 9. signature_algorithms (13) — 9 项，对齐真实 claude-cli/2.1.183
        Rustls(ClientExtension::SignatureAlgorithms(vec![
            SignatureScheme::ECDSA_NISTP256_SHA256, // 0x0403
            SignatureScheme::RSA_PSS_SHA256,        // 0x0804
            SignatureScheme::RSA_PKCS1_SHA256,      // 0x0401
            SignatureScheme::ECDSA_NISTP384_SHA384, // 0x0503
            SignatureScheme::RSA_PSS_SHA384,        // 0x0805
            SignatureScheme::RSA_PKCS1_SHA384,      // 0x0501
            SignatureScheme::RSA_PSS_SHA512,        // 0x0806
            SignatureScheme::RSA_PKCS1_SHA512,      // 0x0601
            SignatureScheme::RSA_PKCS1_SHA1,        // 0x0201
        ])),
        // 10. signed_certificate_timestamp (18)
        Craft(CraftExtension::SignedCertificateTimestamp),
        // 11. key_share (51) — X25519
        Craft(CraftExtension::KeyShare(&[GreaseOrCurve::T(
            NamedGroup::X25519,
        )])),
        // 12. psk_key_exchange_modes (45)
        Rustls(ClientExtension::PresharedKeyModes(vec![
            PSKKeyExchangeMode::PSK_DHE_KE,
        ])),
        // 13. supported_versions (43) — TLS 1.3, 1.2
        Craft(CraftExtension::SupportedVersions(static_ref!(
            &[
                GreaseOrVersion::T(ProtocolVersion::TLSv1_3),
                GreaseOrVersion::T(ProtocolVersion::TLSv1_2),
            ],
            &[GreaseOrVersion]
        ))),
        // 14. padding (21)
        Craft(CraftExtension::Padding),
    ]
};

#[dynamic]
pub static NODEJS_FINGERPRINT: Fingerprint = Fingerprint {
    extensions: &NODEJS_EXTENSION,
    cipher: &NODEJS_CIPHER,
    shuffle_extensions: false,
};

/// 构建带 Node.js TLS 指纹的 rustls ClientConfig。
fn build_tls_config() -> rustls::ClientConfig {
    let root_store = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };

    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth()
        .with_fingerprint(NODEJS_FINGERPRINT.builder());

    // 将 supported_groups 中声明但 ring 不支持的 group 注册为 fake KxGroup，
    // 确保 HRR 验证时 find_kx_group() 能找到它们。
    let mut provider = config.provider.as_ref().clone();
    provider.kx_groups.insert(0, &X25519MLKEM768_KX);
    provider.kx_groups.push(&FAKE_X448);
    config.provider = Arc::new(provider);

    config
}

/// 设置带代理的 reqwest 客户端连接池是否启用。
///
/// # 参数
/// - `enabled`: `true` 表示复用同一代理的缓存客户端,`false` 表示每次请求新建客户端。
pub fn set_request_client_pool_enabled(enabled: bool) {
    REQUEST_CLIENT_POOL_ENABLED.store(enabled, Ordering::Relaxed);
    if !enabled {
        REQUEST_CLIENT_CACHE
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
    }
}

/// 读取当前 reqwest 客户端连接池开关状态。
///
/// # 返回
/// 返回 `true` 表示当前会复用缓存客户端,返回 `false` 表示每次请求新建客户端。
pub fn request_client_pool_enabled() -> bool {
    REQUEST_CLIENT_POOL_ENABLED.load(Ordering::Relaxed)
}

/// 获取带 TLS 指纹伪装的缓存 reqwest 客户端。
///
/// 相同代理地址返回同一个内部连接池的 clone；不同代理地址使用独立客户端，避免代理配置串用。
///
/// # 参数
/// - `proxy_url`: 代理地址。空字符串表示直连，非空时沿用 reqwest 支持的 HTTP/SOCKS 代理格式。
///
/// # 返回
/// 返回可直接发起请求的 `reqwest::Client` clone。
pub fn get_request_client(proxy_url: &str) -> reqwest::Client {
    if !request_client_pool_enabled() {
        return make_request_client(proxy_url);
    }

    let cache_key = proxy_url.to_string();
    {
        let cache = REQUEST_CLIENT_CACHE
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(client) = cache.get(&cache_key) {
            return client.clone();
        }
    }

    let client = make_request_client(proxy_url);
    let mut cache = REQUEST_CLIENT_CACHE
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(existing) = cache.get(&cache_key) {
        return existing.clone();
    }
    cache.insert(cache_key, client.clone());
    client
}

/// 创建带 TLS 指纹伪装的 reqwest 客户端。
///
/// 支持直连和代理（HTTP/SOCKS5）。
///
/// # 参数
/// - `proxy_url`: 代理地址。空字符串表示直连，非空时沿用 reqwest 支持的 HTTP/SOCKS 代理格式。
///
/// # 返回
/// 返回新建的 `reqwest::Client`。
pub fn make_request_client(proxy_url: &str) -> reqwest::Client {
    let tls_config = build_tls_config();

    // 不设整体 timeout，也不用 read_timeout（reqwest 0.12.4 不支持该 API）：
    // 整体超时会误杀健康长流（Opus 扩展思考可持续数十分钟）；
    // 卡死连接的检测统一放到 gateway 层（tokio::time::timeout 包 send() 与 bytes_stream()）。
    //
    // 保活: tcp_keepalive OS 层 SO_KEEPALIVE + KEEPIDLE=30s,idle 30s 后发 TCP 探测包。
    // HTTP/2 PING 因 craftls 指纹 ALPN 只声明 http/1.1,永远协商不出 h2,故不配置。
    let mut builder = reqwest::Client::builder()
        .use_preconfigured_tls(tls_config)
        .connect_timeout(Duration::from_secs(30))
        .tcp_keepalive(Duration::from_secs(30))
        .no_proxy();

    if !proxy_url.is_empty() {
        if let Ok(proxy) = reqwest::Proxy::all(proxy_url) {
            builder = builder.proxy(proxy);
        }
    }

    builder.build().unwrap_or_else(|_| reqwest::Client::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn clear_request_client_cache_for_test() {
        REQUEST_CLIENT_CACHE
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
    }

    fn request_client_cache_len_for_test() -> usize {
        REQUEST_CLIENT_CACHE
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    struct RequestClientPoolStateGuard;

    impl RequestClientPoolStateGuard {
        fn new() -> Self {
            set_request_client_pool_enabled(true);
            clear_request_client_cache_for_test();
            Self
        }
    }

    impl Drop for RequestClientPoolStateGuard {
        fn drop(&mut self) {
            set_request_client_pool_enabled(true);
            clear_request_client_cache_for_test();
        }
    }

    #[test]
    fn same_proxy_reuses_cached_client_entry() {
        let _guard = TEST_LOCK.lock().unwrap();
        let _state_guard = RequestClientPoolStateGuard::new();

        let proxy_url = "socks5h://127.0.0.1:65530";

        let _first = get_request_client(proxy_url);
        assert_eq!(request_client_cache_len_for_test(), 1);

        let _second = get_request_client(proxy_url);
        assert_eq!(request_client_cache_len_for_test(), 1);
    }

    #[test]
    fn different_proxy_uses_different_cached_client_entry() {
        let _guard = TEST_LOCK.lock().unwrap();
        let _state_guard = RequestClientPoolStateGuard::new();

        let _first = get_request_client("socks5h://127.0.0.1:65530");
        let _second = get_request_client("socks5h://127.0.0.1:65531");

        assert_eq!(request_client_cache_len_for_test(), 2);
    }

    #[test]
    fn disabled_pool_bypasses_cached_client_entry() {
        let _guard = TEST_LOCK.lock().unwrap();
        let _state_guard = RequestClientPoolStateGuard::new();

        set_request_client_pool_enabled(false);
        assert!(!request_client_pool_enabled());

        let proxy_url = "socks5h://127.0.0.1:65530";

        let _first = get_request_client(proxy_url);
        assert_eq!(request_client_cache_len_for_test(), 0);

        let _second = get_request_client(proxy_url);
        assert_eq!(request_client_cache_len_for_test(), 0);
    }
}
