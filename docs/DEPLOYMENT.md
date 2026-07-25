# CC-Bridge 完整部署指南

本文覆盖 **整个项目** 从理解架构、本地开发、生产构建，到 Docker / 二进制上线、业务配置、防封策略与运维。

| 文档 | 用途 |
|------|------|
| 本文 `docs/DEPLOYMENT.md` | **部署与运维主文档** |
| [README.md](../README.md) | 功能介绍、HTTP API、内部机制 |
| [CLAUDE.md](../CLAUDE.md) | 开发架构速览 |
| [.env.example](../.env.example) | 环境变量模板 |

当前默认协议画像：**Claude Code 2.1.211**。二进制名：`claude-code-gateway`（镜像/项目名见 `.version`）。

---

## 目录

1. [项目是什么](#1-项目是什么)
2. [仓库结构](#2-仓库结构)
3. [运行时架构](#3-运行时架构)
4. [部署形态选择](#4-部署形态选择)
5. [环境要求](#5-环境要求)
6. [本地开发部署](#6-本地开发部署)
7. [生产构建](#7-生产构建)
8. [Docker 部署](#8-docker-部署)
9. [二进制 / systemd 部署](#9-二进制--systemd-部署)
10. [环境变量配置](#10-环境变量配置)
11. [反向代理](#11-反向代理)
12. [上线后业务配置](#12-上线后业务配置)
13. [防封策略](#13-防封策略)
14. [客户端接入](#14-客户端接入)
15. [上线检查清单](#15-上线检查清单)
16. [升级 / 备份 / 回滚](#16-升级--备份--回滚)
17. [多实例](#17-多实例)
18. [排障](#18-排障)
19. [安全注意](#19-安全注意)

---

## 1. 项目是什么

**CC-Bridge（claude-code-gateway）** 是一个用 Rust 写的 **Claude Code / Anthropic API 反检测网关 + 账号池**：

- 客户端只连你的网关，使用你签发的 **API Token**
- 网关按策略选账号（粘性会话、负载、限流、防封门禁）
- 改写请求头/体、TLS 指纹、可选自动遥测
- 转发到 `api.anthropic.com`
- 管理后台（Vue）与前端静态资源 **编译进同一个二进制**（`rust-embed`）

因此生产部署的核心产物通常是：

```text
claude-code-gateway   # 单文件可执行
.env                  # 环境配置
data/                 # SQLite 等运行数据（或外部 Postgres/Redis）
```

---

## 2. 仓库结构

```text
cc-bridge/
├── src/                      # Rust 后端（网关、调度、改写、防封、存储）
│   ├── main.rs               # 入口：配置、DB 迁移、后台任务、HTTP 监听
│   ├── handler/              # 路由：SPA + /admin/* + 网关透传
│   ├── service/              # gateway / account / antifraud / rewriter / telemetry ...
│   ├── store/                # SQLite/Postgres、Redis/内存缓存
│   ├── tlsfp/ + craftls/     # TLS 指纹伪装
│   └── model/                # Account / Token / Identity
├── web/                      # Vue 3 管理后台（构建后嵌入二进制）
├── docker/
│   ├── Dockerfile            # 多阶段：前端 → Rust → 运行镜像
│   └── docker-compose.yml
├── scripts/
│   ├── dev.sh / dev.bat      # 开发：必要时 build 前端 + cargo run
│   └── build.sh / build.bat  # 生产：前端 build + cargo release → dist/
├── docs/
│   └── DEPLOYMENT.md         # 本文
├── .env.example
├── .version                  # 发布版本 / 镜像名元数据
├── Cargo.toml
└── README.md
```

**请求大致路径：**

```text
Client
  → Auth（API Token）
  → 访问策略（Claude 版本 / UA）
  → 账号选择（粘性 + 评分 + 防封门禁 + RPM/并发）
  → Rewriter（UA/beta/body/identity）
  → craftls TLS → api.anthropic.com
  → 用量头合并 / 响应清洗 → Client
```

管理流量：`/admin/*`（密码鉴权）+ 前端 SPA。

---

## 3. 运行时架构

```text
                    ┌─────────────────────────────────────┐
                    │           反代（可选）                │
                    │     Nginx / Caddy TLS 终止           │
                    └─────────────────┬───────────────────┘
                                      │ :443 → :5674
                    ┌─────────────────▼───────────────────┐
                    │     claude-code-gateway 进程         │
                    │  ┌─────────┐  ┌──────────────────┐  │
                    │  │  Vue SPA│  │ /admin API       │  │
                    │  │ embed   │  │ 账号/令牌/设置   │  │
                    │  └─────────┘  └────────┬─────────┘  │
                    │  ┌─────────────────────▼─────────┐  │
                    │  │ Gateway 透传 *                │  │
                    │  └─────────────┬─────────────────┘  │
                    │                │                     │
                    │  SQLite/PG ◄───┤───► Redis(可选)    │
                    └────────────────┼─────────────────────┘
                                     │ 账号 proxy_url
                                     ▼
                            api.anthropic.com
```

| 组件 | 作用 |
|------|------|
| 单二进制 | HTTP 服务 + 嵌入前端 + 后台 poller（用量 / 峰值预热） |
| SQLite 或 Postgres | 账号、Token、settings、预热日志 |
| Redis 或内存 | 粘性 session、并发/RPM 等运行时状态 |
| 每账号 proxy | 上游出口 IP 隔离（防封关键） |

---

## 4. 部署形态选择

| 场景 | 推荐 | 数据库 | 缓存 |
|------|------|--------|------|
| 本机开发 | `./scripts/dev.sh` | SQLite | 内存 |
| 单机试用 | 二进制 或 Docker | SQLite | 内存 |
| 单机生产 | Docker Compose 或 systemd | SQLite 或 Postgres | 内存即可 |
| 多实例 / 扩容 | 多副本 + 负载均衡 | **Postgres** | **Redis** |
| 公网 | 任意形态 + **反代 HTTPS** | 同上 | 同上 |

---

## 5. 环境要求

### 仅运行（用现成二进制 / 镜像）

| 依赖 | 说明 |
|------|------|
| Linux x86_64 / arm64，或 Windows x64，或 macOS | 与产物匹配 |
| 可写数据目录 | SQLite 时需要 |
| 出网访问 `api.anthropic.com` | 及账号所用代理可达 |
| Docker（可选） | Compose 部署 |

### 从源码构建

| 依赖 | 版本 |
|------|------|
| Rust | ≥ 1.82（见 README；仓库 `edition = "2024"` 需足够新的 toolchain） |
| Node.js | 22 |
| npm | 随 Node |
| 系统库 | Linux 构建常需 `pkg-config`、`libssl-dev` 等（Docker 构建镜像已处理） |

---

## 6. 本地开发部署

适合改代码、联调管理台与网关。

### 6.1 克隆与配置

```bash
git clone https://github.com/MamoWorks/cc-bridge.git
cd cc-bridge
cp .env.example .env
# 开发可暂用默认 ADMIN_PASSWORD=admin
```

### 6.2 一键开发启动（推荐）

```bash
./scripts/dev.sh          # macOS / Linux
# Windows: scripts\dev.bat
```

脚本会：

1. 必要时 `npm ci` / `npm run build` 前端到 `web/dist`（嵌入编译需要 dist 存在）
2. `cargo run` 启动后端（默认 `:5674`）

### 6.3 前后端分离热更新

```bash
# 终端 A：前端 Vite
cd web && npm ci && npm run dev    # 通常 :3000，并代理 API

# 终端 B：后端
cargo run                          # :5674
```

### 6.4 开发自检

| 地址 | 说明 |
|------|------|
| http://127.0.0.1:5674/ | 管理后台 |
| http://127.0.0.1:5674/login | 登录（默认 `admin`） |
| http://127.0.0.1:5674/v1/messages | 网关 API（需 Token） |

TLS 出口指纹自检（可选）：

```bash
cargo run --example tls_selfcheck
cargo run --example tls_selfcheck -- socks5h://127.0.0.1:1080
```

单元测试：

```bash
mkdir -p web/dist && echo '<!doctype html><title>t</title>' > web/dist/index.html
cargo test --lib
```

---

## 7. 生产构建

生产二进制 **内嵌前端**，部署一般只需可执行文件 + `.env` + 数据目录。

### 7.1 官方构建脚本

```bash
# 当前机器架构
./scripts/build.sh

# 交叉编译
./scripts/build.sh linux-amd64
./scripts/build.sh linux-arm64
```

输出目录：`dist/`

```text
dist/claude-code-gateway            # 或 claude-code-gateway-linux-amd64 等
dist/.env.example
```

脚本流程：`cargo clean` → `web` 前端 `npm run build` → `cargo build --release` → 拷贝到 `dist/`。

### 7.2 手动构建

```bash
cd web && npm ci && npm run build && cd ..
cargo build --release
./target/release/claude-code-gateway
```

### 7.3 Windows

```bat
scripts\build.bat
scripts\dev.bat
```

### 7.4 发布元数据

`.version` 示例字段：

- `project_name` / `version` / `image_name`（GHCR 镜像名）

CI 工作流见 `.github/workflows/`（`release.yml`、`docker.yml`）。改版本发版时按仓库既有流程更新 `.version` 并推送。

---

## 8. Docker 部署

### 8.1 使用 Compose（最简单）

```bash
cd cc-bridge
cp .env.example .env
# 修改 ADMIN_PASSWORD 等

cd docker
docker compose up -d
```

`docker-compose.yml` 要点：

- 镜像：`ghcr.io/mamoworks/claude-code-gateway:latest`（以你仓库实际镜像为准；`.version` 里可能是 `ghcr.io/silentflower/...`，部署时与发布方一致）
- 端口：`${SERVER_PORT:-5674}:5674`
- `env_file: ../.env`
- `TZ: Asia/Shanghai`（峰值预热按本地小时）
- 数据卷：`claude-code-gateway-data` → 容器内数据目录

常用命令：

```bash
docker compose ps
docker compose logs -f claude-code-gateway
docker compose pull && docker compose up -d
docker compose down
```

### 8.2 本机构建镜像

```bash
# 在仓库根目录
docker build -f docker/Dockerfile -t claude-code-gateway:local .

docker run -d --name cc-bridge \
  --env-file .env \
  -p 5674:5674 \
  -v cc-bridge-data:/app/data \
  -e TZ=Asia/Shanghai \
  claude-code-gateway:local
```

Dockerfile 三阶段：Node 构建 `web` → Rust release（含 craftls）→ `debian:bookworm-slim` 运行。

### 8.3 Compose + Redis（可选）

取消注释 `docker-compose.yml` 中 redis 服务，并在 `.env` 设置：

```env
REDIS_HOST=redis
REDIS_PORT=6379
```

（服务名以 compose 内网络 DNS 为准。）

---

## 9. 二进制 / systemd 部署

### 9.1 目录布局

```text
/opt/cc-bridge/
├── claude-code-gateway
├── .env
└── data/
    └── claude-code-gateway.db   # SQLite 时自动创建
```

```bash
sudo useradd -r -s /usr/sbin/nologin ccbridge || true
sudo mkdir -p /opt/cc-bridge/data
sudo cp dist/claude-code-gateway /opt/cc-bridge/
sudo cp .env.example /opt/cc-bridge/.env
sudo chown -R ccbridge:ccbridge /opt/cc-bridge
sudo chmod 750 /opt/cc-bridge
sudo chmod 640 /opt/cc-bridge/.env
```

编辑 `/opt/cc-bridge/.env` 至少设置 `ADMIN_PASSWORD`、`DATABASE_DSN=data/claude-code-gateway.db`。

### 9.2 前台试跑

```bash
cd /opt/cc-bridge
sudo -u ccbridge ./claude-code-gateway
```

### 9.3 systemd

```ini
# /etc/systemd/system/cc-bridge.service
[Unit]
Description=CC-Bridge Claude Code Gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=ccbridge
Group=ccbridge
WorkingDirectory=/opt/cc-bridge
EnvironmentFile=/opt/cc-bridge/.env
ExecStart=/opt/cc-bridge/claude-code-gateway
Restart=on-failure
RestartSec=3
LimitNOFILE=65535
# 可选：加固
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now cc-bridge
sudo systemctl status cc-bridge
journalctl -u cc-bridge -f
```

---

## 10. 环境变量配置

优先级：**进程环境变量 > `.env` 文件 > 代码默认值**。

模板：复制 [.env.example](../.env.example)。

### 10.1 最小生产配置

```env
SERVER_HOST=0.0.0.0
SERVER_PORT=5674
DATABASE_DRIVER=sqlite
DATABASE_DSN=data/claude-code-gateway.db
ADMIN_PASSWORD=换成足够长的随机密码
LOG_LEVEL=info
```

### 10.2 全量说明

#### 服务

| 变量 | 默认 | 说明 |
|------|------|------|
| `SERVER_HOST` | `0.0.0.0` | 监听地址 |
| `SERVER_PORT` | `5674` | 监听端口 |
| `TLS_CERT_FILE` | 空 | 进程内证书（多数用反代） |
| `TLS_KEY_FILE` | 空 | 进程内私钥 |
| `ADMIN_PASSWORD` | `admin` | 管理后台密码，**生产必改** |
| `LOG_LEVEL` | `info` | debug/info/warn/error |
| `USAGE_POLL_INTERVAL_SECS` | `300` | OAuth 用量轮询间隔 |

#### 数据库

| 变量 | 默认 | 说明 |
|------|------|------|
| `DATABASE_DRIVER` | `sqlite` | `sqlite` / `postgres` |
| `DATABASE_DSN` | `data/claude-code-gateway.db` | 优先使用的完整 DSN |
| `DATABASE_HOST` | `localhost` | PG 主机 |
| `DATABASE_PORT` | `5432` | PG 端口 |
| `DATABASE_USER` | `postgres` | PG 用户 |
| `DATABASE_PASSWORD` | 空 | PG 密码 |
| `DATABASE_DBNAME` | 见配置 | PG 库名 |

启动时自动 **migrate**（表结构、settings 默认、账号画像版本升级等）。

#### Redis

| 变量 | 默认 | 说明 |
|------|------|------|
| `REDIS_HOST` | 空 | 不设则内存缓存 |
| `REDIS_PORT` | `6379` | |
| `REDIS_PASSWORD` | 空 | |
| `REDIS_DB` | `0` | |

### 10.3 Postgres 示例

```env
DATABASE_DRIVER=postgres
DATABASE_HOST=10.0.0.10
DATABASE_PORT=5432
DATABASE_USER=ccbridge
DATABASE_PASSWORD=***
DATABASE_DBNAME=cc_bridge
```

### 10.4 与「管理后台 settings」的区别

| 类型 | 存在哪里 | 例子 |
|------|----------|------|
| 进程环境 / `.env` | 启动环境 | 端口、库、Redis、管理员密码 |
| 管理后台设置 | 数据库 `settings` 表 | 防封策略、评分权重、客户端版本准入、缓存改写 |

改 `.env` 需重启进程；改管理台设置多数会即时 `reload` 到内存。

---

## 11. 反向代理

进程默认可只提供 HTTP。公网请终止 TLS。

### Caddy

```caddy
gateway.example.com {
    reverse_proxy 127.0.0.1:5674
}
```

### Nginx

```nginx
server {
    listen 443 ssl http2;
    server_name gateway.example.com;

    client_max_body_size 32m;

    location / {
        proxy_pass http://127.0.0.1:5674;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Claude 流式可能很长
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_buffering off;
    }
}
```

建议：管理路径 `/admin`、`/login` 仅内网或额外 ACL。

---

## 12. 上线后业务配置

环境变量只启动服务；**账号池与令牌在 UI 配置**。

### 12.1 标准流程

```text
1. 打开 https://你的域名/login
2. 用 ADMIN_PASSWORD 登录
3. 设置 → 确认防封 / 准入版本等
4. 账号 → 添加 OAuth 或 SetupToken（填代理）
5. 令牌 → 创建 gateway API Token
6. 客户端把 Base URL 指到网关，Key 用 gateway Token
7. 发一条真实请求验证
```

### 12.2 账号字段建议

| 字段 | 说明 |
|------|------|
| `proxy_url` | 每号独立代理（HTTP/SOCKS），防封关键 |
| `account_uuid` / `organization_uuid` | OAuth 强烈建议完整 |
| `subscription_type` | max/pro/team/enterprise |
| `concurrency` / `rpm_limit` | 并发与 RPM；新号还有 warm-up |
| `auto_telemetry` | OAuth 建议开 |
| `billing_mode` | strip / rewrite |
| `auto_poll_usage` | 是否后台拉 OAuth 用量 |

OAuth：用 **授权登录**，授权过程可带同一 `proxy_url`。

### 12.3 管理 API（节选）

均需管理鉴权（与前端相同密码机制）：

| 方法 | 路径 | 说明 |
|------|------|------|
| GET/POST | `/admin/accounts` | 列表 / 创建 |
| PUT/DELETE | `/admin/accounts/:id` | 更新 / 删除 |
| POST | `/admin/accounts/:id/test` | 测号 |
| POST | `/admin/accounts/:id/usage` | 刷新用量 |
| POST | `/admin/accounts/:id/antifraud-probe` | 代理出口探测 |
| GET | `/admin/antifraud/health` | 防封总览 |
| GET/POST | `/admin/tokens` | 令牌 |
| GET/PUT | `/admin/settings` | 全局设置 |
| GET | `/admin/dashboard` | 仪表盘 |

网关业务 API：除保留路径外透传，例如 `POST /v1/messages`，Header：

```http
Authorization: Bearer <gateway-token>
Content-Type: application/json
```

---

## 13. 防封策略

在 **设置 → 防封策略** 配置（写入 DB `settings`）。

### 默认值

| Key | 默认 | 含义 |
|-----|------|------|
| `antifraud_gate_enabled` | `true` | 硬伤是否禁止调度 |
| `antifraud_require_proxy` | `true` | 必须配置 proxy |
| `antifraud_require_identity` | `true` | OAuth 必须 uuid/org |
| `antifraud_max_accounts_per_proxy` | `3` | 同代理账号数告警阈值 |
| `antifraud_warmup_hours` | `24` | 新号 warm-up 时长 |
| `antifraud_warmup_concurrency` | `1` | warm-up 并发上限 |
| `antifraud_warmup_rpm` | `12` | warm-up RPM 上限 |
| `antifraud_default_auto_telemetry` | `true` | 新建 OAuth 默认开遥测 |
| `antifraud_proxy_probe_ttl_secs` | `600` | 出口探测缓存 |

### 硬伤（门禁开启时不选号）

- 无 `proxy_url`
- OAuth 缺 `account_uuid` 或 `organization_uuid`

同代理过密当前为 **警告**，不默认硬拒。

### 准入版本 vs 出口伪装

| 配置 | 层 | 默认 |
|------|----|------|
| `allowed_claude_code_versions` | 客户端能否进网关 | `2.1.89-2.1.999` |
| 账号画像 / `version_profile` | 发给 Anthropic 的伪装 | **2.1.211** |

用户客户端可以是 2.1.212；上游仍按网关改写后的 2.1.211 画像（除非改账号 env）。

### 升级后账号全被拦

补代理与 OAuth 身份，或临时关闭 `require_*` / `gate_enabled`。

---

## 14. 客户端接入

### Claude Code / CLI 类

将 API 基址指到网关，Key 使用 **gateway Token**（名称因客户端而异），例如：

```bash
export ANTHROPIC_BASE_URL="https://gateway.example.com"
export ANTHROPIC_API_KEY="sk-你的网关token"
```

### curl 自检

```bash
curl -sS https://gateway.example.com/v1/messages \
  -H "Authorization: Bearer sk-你的网关token" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "claude-sonnet-4-6",
    "max_tokens": 64,
    "messages": [{"role": "user", "content": "ping"}]
  }'
```

### 客户端版本

若开启 `allowed_claude_code_versions`，UA 中的 Claude Code / CLI 版本必须在范围内，否则本地 403，不打上游。

---

## 15. 上线检查清单

### 基础设施

- [ ] 二进制或容器正常监听
- [ ] `ADMIN_PASSWORD` 非默认
- [ ] SQLite 目录可写，或 Postgres 连通
- [ ] 多实例时 Redis 连通且配置一致
- [ ] 反代 HTTPS + 长超时
- [ ] 主机可访问 Anthropic（或经账号代理）

### 业务

- [ ] 至少一个 **active 且防封通过** 的账号
- [ ] 代理「出口」探测成功（可选）
- [ ] 至少一个 API Token
- [ ] 真实客户端或 curl 打通 `/v1/messages`
- [ ] 管理台账号卡片：评分 / 并发 / 防封徽章正常

### 安全

- [ ] 管理端访问受限
- [ ] 数据文件与 `.env` 权限收紧
- [ ] 生产日志级别非长期 debug

---

## 16. 升级 / 备份 / 回滚

### 备份

| 数据 | 方式 |
|------|------|
| SQLite | 停服复制 `data/*.db`，或使用 SQLite backup API |
| Postgres | `pg_dump` |
| 配置 | `.env` + 库内 `settings` |
| Docker 卷 | `docker volume` 备份策略 |

### 升级（二进制）

```bash
sudo systemctl stop cc-bridge
cp /opt/cc-bridge/claude-code-gateway /opt/cc-bridge/claude-code-gateway.bak
cp new-binary /opt/cc-bridge/claude-code-gateway
sudo systemctl start cc-bridge
journalctl -u cc-bridge -n 100 --no-pager
```

### 升级（Docker）

```bash
cd docker
docker compose pull
docker compose up -d
docker compose logs -f --tail=100
```

### 回滚

换回旧二进制 / 旧镜像 tag，必要时恢复 DB 备份。迁移一般向后兼容增量；若跨大版本，先在 staging 验证。

启动后建议检查：

- 日志无 migrate 错误
- 账号 `canonical_env.version` 是否为目标画像（如 2.1.211）
- 防封徽章是否异常大面积「门禁拦截」

---

## 17. 多实例

1. 所有实例共用 **同一 Postgres**
2. 所有实例共用 **同一 Redis**
3. 负载均衡到各实例的 `:5674`（或反代 upstream）
4. 不要用多实例 + 仅 SQLite 文件共享（易锁与损坏）
5. 粘性会话、并发、RPM 依赖 Redis；无 Redis 则各进程状态隔离

---

## 18. 排障

| 现象 | 排查 |
|------|------|
| 起不来 | `LOG_LEVEL=debug` 看迁移/端口占用；SQLite 路径权限 |
| 登不上管理台 | `ADMIN_PASSWORD`；反代是否剥 Header |
| 403 版本/UA | 设置里 `allowed_claude_code_versions` / `allowed_user_agents` |
| no available accounts / 429 | 账号全限流、门禁全拦、并发/RPM 满 |
| 门禁拦截 | 补 proxy / OAuth uuid，或关 require |
| 流断开 | 反代 timeout / buffering |
| 多实例粘性乱 | Redis 未配或配置不一致 |
| 前端 404 白屏 | 确认生产构建嵌入了 `web/dist`；开发需先有 dist 或走 Vite |

日志关键字：`migrate`、`[RPM]`、`no available`、`telemetry`、`antifraud`、OAuth refresh。

---

## 19. 安全注意

- 网关持有真实 Anthropic 凭证与代理信息，按机密系统保护
- 不要把管理端口裸奔公网
- 遵守 Anthropic 服务条款与当地法律；代理与账号来源需合法
- 客户端旁路遥测（如 Datadog）网关拦不住，需网络策略

---

## 附录 A：常用命令速查

```bash
# 开发
cp .env.example .env && ./scripts/dev.sh

# 生产构建
./scripts/build.sh
./scripts/build.sh linux-amd64

# Docker
cd docker && docker compose up -d

# 测试
cargo test --lib
cargo run --example tls_selfcheck

# 健康
curl -sS -o /dev/null -w "%{http_code}\n" http://127.0.0.1:5674/login
```

## 附录 B：默认端口与路径

| 项 | 值 |
|----|-----|
| 服务端口 | `5674` |
| 管理后台 | `/` `/login` `/tokens` `/settings` |
| 管理 API 前缀 | `/admin/*` |
| 网关 | 其余路径透传上游（如 `/v1/messages`） |
| SQLite 默认 | `data/claude-code-gateway.db` |

## 附录 C：相关源码

| 路径 | 说明 |
|------|------|
| `src/main.rs` | 启动与后台任务 |
| `src/handler/router.rs` | 路由与 admin API |
| `src/service/gateway.rs` | 转发主逻辑 |
| `src/service/account.rs` | 选号 / 并发 / RPM |
| `src/service/antifraud.rs` | 防封体检与门禁 |
| `src/service/version_profile.rs` | 默认伪装版本 |
| `src/tlsfp/` + `craftls/` | TLS 指纹 |
| `web/` | 管理前端 |
| `scripts/build.sh` | 生产构建 |
| `docker/` | 镜像与 Compose |
