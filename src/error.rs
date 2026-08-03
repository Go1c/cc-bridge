use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use tracing::error;

/// 上游传输失败的可归因细节（TTFB / send）。
///
/// 仅包含排障所需、且不含密钥的字段；完整归因日志在 gateway 侧单独打 WARN。
#[derive(Debug, Clone)]
pub struct UpstreamTransportDetail {
    /// 稳定机器可读错误码，例如 `upstream_ttfb_timeout`。
    pub error_code: &'static str,
    pub account_id: i64,
    pub elapsed_ms: u64,
    pub model: String,
    pub stream: bool,
    pub path: String,
    pub body_bytes: usize,
    pub attempt_index: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("not found")]
    NotFound,
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("unauthorized")]
    Unauthorized,
    #[error("too many requests: {0}")]
    TooManyRequests(String),
    #[error("bad gateway: {0}")]
    BadGateway(String),
    /// 带归因字段的 502。`Display` / `error` 字符串保持 `bad gateway: {message}`，
    /// 额外 `error_code` + `details` 供排障；旧客户端只读 `error` 字符串仍兼容。
    #[error("bad gateway: {message}")]
    BadGatewayAttributed {
        message: String,
        detail: UpstreamTransportDetail,
    },
    #[error("service unavailable: {0}")]
    ServiceUnavailable(String),
    #[error("internal: {0}")]
    Internal(String),
}

impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        match e {
            sqlx::Error::RowNotFound => AppError::NotFound,
            _ => AppError::Internal(e.to_string()),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match &self {
            AppError::BadGatewayAttributed { message, detail } => {
                // 兼容：`error` 仍为完整 `bad gateway: ...` 字符串；
                // 新增 error_code / details 不替换旧字段。
                let body = json!({
                    "error": format!("bad gateway: {message}"),
                    "error_code": detail.error_code,
                    "details": {
                        "account_id": detail.account_id,
                        "elapsed_ms": detail.elapsed_ms,
                        "model": detail.model,
                        "stream": detail.stream,
                        "path": detail.path,
                        "body_bytes": detail.body_bytes,
                        "attempt_index": detail.attempt_index,
                    }
                });
                return (StatusCode::BAD_GATEWAY, axum::Json(body)).into_response();
            }
            _ => {}
        }

        let (status, msg) = match &self {
            AppError::NotFound => (StatusCode::NOT_FOUND, "not found"),
            AppError::BadRequest(_) => (StatusCode::BAD_REQUEST, ""),
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            AppError::TooManyRequests(_) => (StatusCode::TOO_MANY_REQUESTS, ""),
            AppError::BadGateway(_) => (StatusCode::BAD_GATEWAY, ""),
            AppError::BadGatewayAttributed { .. } => unreachable!("handled above"),
            AppError::ServiceUnavailable(_) => (StatusCode::SERVICE_UNAVAILABLE, ""),
            AppError::Internal(detail) => {
                error!("internal error: {}", detail);
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
        };
        let body =
            json!({"error": if msg.is_empty() { self.to_string() } else { msg.to_string() }});
        (status, axum::Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    async fn response_json(resp: Response) -> serde_json::Value {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn bad_gateway_string_shape_unchanged() {
        let resp = AppError::BadGateway("upstream TTFB timeout".into()).into_response();
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        let value = response_json(resp).await;
        assert_eq!(
            value.get("error").and_then(|v| v.as_str()),
            Some("bad gateway: upstream TTFB timeout")
        );
        assert!(value.get("error_code").is_none());
    }

    #[tokio::test]
    async fn bad_gateway_attributed_keeps_string_and_adds_details() {
        let resp = AppError::BadGatewayAttributed {
            message: "upstream TTFB timeout".into(),
            detail: UpstreamTransportDetail {
                error_code: "upstream_ttfb_timeout",
                account_id: 21,
                elapsed_ms: 120_001,
                model: "claude-opus-5".into(),
                stream: true,
                path: "/v1/messages".into(),
                body_bytes: 4096,
                attempt_index: 1,
            },
        }
        .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        let value = response_json(resp).await;
        assert_eq!(
            value.get("error").and_then(|v| v.as_str()),
            Some("bad gateway: upstream TTFB timeout")
        );
        assert_eq!(
            value.get("error_code").and_then(|v| v.as_str()),
            Some("upstream_ttfb_timeout")
        );
        assert_eq!(
            value
                .pointer("/details/account_id")
                .and_then(|v| v.as_i64()),
            Some(21)
        );
        assert_eq!(
            value.pointer("/details/model").and_then(|v| v.as_str()),
            Some("claude-opus-5")
        );
        assert_eq!(
            value.pointer("/details/stream").and_then(|v| v.as_bool()),
            Some(true)
        );
    }
}
