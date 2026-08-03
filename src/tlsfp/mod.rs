pub mod tlsfp;

pub use tlsfp::get_request_client;
pub use tlsfp::make_request_client;
pub use tlsfp::request_client_pool_enabled;
pub use tlsfp::set_request_client_pool_enabled;

/// 清空按 proxy_url 缓存的 reqwest 客户端（测试或 connect_timeout 配置变更后使用）。
pub fn clear_request_client_cache() {
    // 通过禁用再启用来清空缓存；与 set_request_client_pool_enabled(false) 的 clear 路径一致。
    let was_enabled = request_client_pool_enabled();
    set_request_client_pool_enabled(false);
    set_request_client_pool_enabled(was_enabled);
}
