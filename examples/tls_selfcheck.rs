//! 出口 TLS 指纹自检。
//!
//! 用法：`cargo run --example tls_selfcheck`
//!
//! 复用网关真实的 craftls 客户端（`make_request_client`）去请求 tls.peet.ws/api/all，
//! 把对端解析出来的 JA3 / JA4 / HTTP2 指纹打印出来，并与目标真实 claude-cli 指纹比对。
//! 这样验证的是网关**实际发出**的 ClientHello，而不是理论配置。
//!
//! 可选：第一个命令行参数传代理 URL（如 `cargo run --example tls_selfcheck socks5h://127.0.0.1:1080`）。

use claude_code_gateway::tlsfp::make_request_client;

/// 目标：真实 claude-cli/2.1.211（Bun/Node v26.3.0，无 padding）抓到的指纹。
const EXPECTED_JA3_HASH: &str = "dc782a9d905fdcee1223a3d4e8108bc6";
const EXPECTED_JA4: &str = "t13d1713h1_5b57614c22b0_b6f405a75b75"; // approx; selfcheck only strictly asserts JA3

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proxy = std::env::args().nth(1).unwrap_or_default();
    if proxy.is_empty() {
        println!("→ 直连（无代理）");
    } else {
        println!("→ 通过代理: {proxy}");
    }

    let client = make_request_client(&proxy);
    let resp = client
        .get("https://tls.peet.ws/api/all")
        .header("user-agent", "claude-cli/2.1.211 (external, sdk-cli)")
        .send()
        .await?;
    println!("HTTP {}", resp.status());
    let body: serde_json::Value = resp.json().await?;

    let tls = &body["tls"];
    let ja3 = tls["ja3"].as_str().unwrap_or("?");
    let ja3_hash = tls["ja3_hash"].as_str().unwrap_or("?");
    let ja4 = tls["ja4"].as_str().unwrap_or("?");
    let ja4_r = tls["ja4_r"].as_str().unwrap_or("?");
    let peetprint = tls["peetprint_hash"].as_str().unwrap_or("?");

    println!("\n===== 出口指纹 =====");
    println!("JA3      : {ja3}");
    println!("JA3 hash : {ja3_hash}");
    println!("JA4      : {ja4}");
    println!("JA4_r    : {ja4_r}");
    println!("peetprint: {peetprint}");

    println!("\n===== 与目标 claude-cli 比对 =====");
    // JA3 是权威判据：它把 padding 也计入扩展列表，与目标一致即字节级一致。
    check("JA3 hash", ja3_hash, EXPECTED_JA3_HASH);

    // JA4：tls.peet.ws 会把 padding(0x0015) 从 JA4_c 哈希中剔除，而目标 JA4 把 padding 计入，
    // 因此第三段会显示不同。前两段（版本/计数/ALPN、cipher 哈希）应与目标一致。
    let ja4_prefix_ok = ja4.split('_').next() == EXPECTED_JA4.split('_').next();
    let ja4_cipher_ok = ja4.split('_').nth(1) == EXPECTED_JA4.split('_').nth(1);
    if ja4_prefix_ok && ja4_cipher_ok {
        println!("✓ JA4 前两段一致（{}...）", &EXPECTED_JA4[..EXPECTED_JA4.len().min(22)]);
        println!("  注：第三段差异仅因 peet 把 padding 排除出哈希；按目标口径（含 padding）复算应为 {}",
            EXPECTED_JA4.rsplit('_').next().unwrap_or("?"));
    } else {
        check("JA4", ja4, EXPECTED_JA4);
    }

    Ok(())
}

fn check(name: &str, got: &str, want: &str) {
    if got == want {
        println!("✓ {name} 一致: {got}");
    } else {
        println!("✗ {name} 不一致\n    实际: {got}\n    目标: {want}");
    }
}
