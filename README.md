# 鲸云云资源聚合管理系统

鲸云云资源聚合管理系统
（Teivia Cloud）是一个基于 ThinkPHP 8 和 MySQL 的自托管控制台，用于集中管理已授权的云服务与域名服务账号、同步资源目录，并通过服务商官方 API 执行该资源实际支持的操作。

系统不会代替服务商控制台，也不会绕过服务商权限、风控、账单或产品限制。所有操作是否可用以服务商 API、账号权限和具体资源能力为准。

## 功能概览

- 账号管理：保存并加密服务商凭据，管理账号状态、区域和同步频率。
- 资源清单：将云服务和域名资源分开展示，支持资源详情、状态、IP、规格、到期信息和同步记录。
- 资源操作：依据资源与服务商能力目录提供开机、关机、重启、重装、续费、DNS、SSL/TLS 等操作；危险操作要求输入资源名称确认。
- 动态能力发现：魔方财务系统与 IDCsmart V10 会读取产品控制面板；腾讯云会读取可用镜像目录，避免猜测产品操作或系统 ID。
- 域名与 DNS：支持 Cloudflare、西部数码、Spaceship、阿里云万网等已接入服务商的资源与 DNS 相关操作。
- 统一 API：使用权限范围受限、可撤销的 API Key 管理账号、资源、资源操作和同步任务。
- 同步任务：手动创建或按计划调度同步，记录任务状态、重试信息和审计日志。
- 安全能力：服务商凭据与 SMTP 配置加密保存；API Key 仅保存哈希；登录、密码修改和危险操作支持邮件通知。
- 外观与文档：支持站点名称、侧栏名称、浅色/深色模式和内置 API 文档页面。

## 已接入服务商

| 分类 | 服务商 / 系统 |
| --- | --- |
| 云服务 | 阿里云 ECS、腾讯云 CVM 与轻量应用服务器、华为云 ECS、AWS EC2、Google Compute Engine |
| 域名与边缘服务 | Cloudflare、阿里云万网、西部数码、Spaceship |
| 财务与业务系统 | 魔方财务系统、IDCsmart V10 |

魔方财务系统和 IDCsmart V10 是可由不同服务商部署的系统，添加账号时必须填写该实例实际可访问的服务地址。请仅使用你拥有授权的账号与 API 凭据。

服务商 API 文档链接、凭据字段与当前支持范围会显示在系统的“服务商连接”和“服务商 API 文档”页面。服务商更新接口、权限或产品能力后，可能需要同步更新适配器后才能使用新功能。

## 运行要求

- PHP 8.0+，并启用 `pdo_mysql`、`curl`、`openssl`、`mbstring`、`dom`、`xml`、`json` 扩展。
- MySQL 8.0+，使用 InnoDB 与 `utf8mb4`。
- Composer 2。
- Nginx、Apache 或宝塔站点的 Web 根目录必须指向 `public/`。
- 生产环境必须使用 HTTPS。若 `SESSION_NAME` 使用默认值 `__Host-jingyun_session`，站点不能设置 Cookie Domain，且 Cookie Path 必须为 `/`。

应用会话存储在 MySQL 的 `sessions` 表中，不依赖 `runtime/session` 写入权限。`runtime/` 仍应保留给框架缓存和日志，并且不可被 Web 直接访问。

## 快速安装

### 1. 获取代码和依赖

```text
下载源码上传至服务器。
```

将 Web 根目录设置为项目中的 `public/` 目录，并配置 ThinkPHP 伪静态规则。Apache 可使用 [public/.htaccess](public/.htaccess)；Nginx 或宝塔请将不存在的文件和目录转发给 `index.php`。

### 2. 使用 Web 安装器

访问：

```text
https://your-domain.example/install.php
```

安装器会：

1. 验证 MySQL 连接，并可选择创建数据库。
2. 执行数据库迁移和服务商目录初始化。
3. 为本次安装生成独立、随机的 `CREDENTIAL_ENCRYPTION_KEY`。
4. 写入私有 `.env`，并创建首位管理员。

安装后立即删除或在 Web 服务器层禁止访问 `install.php` 和 `public/install.php`。安装状态由数据库中的管理员记录判断，不能重复覆盖已安装系统。

对于宝塔等本机 MySQL 账号，如果连接 `127.0.0.1` 失败，请尝试填写 `localhost`。数据库已经存在时，不要勾选“尝试创建数据库”；该选项要求数据库账号具有 `CREATE` 权限。

### 3. 手动安装

适用于不便开放 Web 安装器的环境。

```bash
cp .env.example .env
php -r "echo base64_encode(random_bytes(32)), PHP_EOL;"
```

将生成的随机值填入 `.env` 的 `CREDENTIAL_ENCRYPTION_KEY`，再填写数据库配置。`.env` 中的账号、密码、密钥必须使用你自己的值，禁止提交到 Git。

```bash
php think migrate:run --no-interaction
php think seed:run --seed ProviderCatalogSeeder --no-interaction
TOWER_CLOUD_ADMIN_PASSWORD='use-a-long-unique-password' php think admin:create admin admin@example.com
```

`admin:create` 仅能在没有用户记录的数据库中执行。管理员密码至少 12 个字符；优先使用环境变量，避免密码进入 Shell 历史记录。

## 环境配置

安装器会生成 `.env`。手动部署可从 `.env.example` 开始：

```ini
APP_DEBUG = false
APP_ORIGIN = https://console.example.com

DB_HOST = localhost
DB_PORT = 3306
DB_NAME = your_database_name
DB_USER = your_database_user
DB_PASS = your_database_password
DB_CHARSET = utf8mb4

CREDENTIAL_ENCRYPTION_KEY = base64-encoded-32-byte-random-key
CREDENTIAL_ENCRYPTION_KEY_VERSION = v1

SESSION_SECURE_COOKIE = true
SESSION_NAME = __Host-jingyun_session
SESSION_EXPIRE = 7200
SESSION_DATABASE_TABLE = sessions
```

注意：

- `CREDENTIAL_ENCRYPTION_KEY` 必须是单独随机生成的 32 字节 Base64 值。不要使用示例值，不要在不同项目间复用。
- 该密钥用于解密已保存的服务商凭据和 SMTP 配置。丢失后无法解密现有密文；更换前应备份并规划凭据轮换。
- `APP_ORIGIN` 必须是完整的 HTTP/HTTPS 来源地址，例如 `https://console.example.com`，不要包含路径、账号或查询参数。
- 生产环境应保持 `APP_DEBUG = false` 与 `SESSION_SECURE_COOKIE = true`。

## 部署与升级

每次更新代码后，在项目根目录执行：

```bash
composer install --no-dev --optimize-autoloader
php think migrate:run --no-interaction
php think seed:run --seed ProviderCatalogSeeder --no-interaction
php think clear
```

若登录成功后马上提示会话失效，确认 MySQL 账号可读写 `sessions` 表，并重新执行迁移：

```bash
php think migrate:run --no-interaction
```

不要通过浏览器或版本库公开 `.env`、`runtime/`、数据库备份、日志、服务商凭据、SMTP 密码、API Key 或截图中的敏感信息。

## 同步 Worker 与计划任务

HTTP 请求只负责将同步任务加入队列；实际调用服务商 API 由 Worker 执行。

执行一轮已排队任务：

```bash
php think sync:run --limit=100
```

先将到期计划加入队列，再执行任务：

```bash
php think sync:run --due --limit=100
```

持续运行模式：

```bash
php think sync:run --due --loop --sleep=5
```

Linux cron 示例：

```cron
* * * * * cd /srv/tower-cloud && /usr/bin/php think sync:run --due --limit=100 >> runtime/log/sync-worker.log 2>&1
```

将 `/srv/tower-cloud` 和 `/usr/bin/php` 换成实际路径。计划任务使用项目根目录作为工作目录，否则会出现 `Could not open input file: think`。

## 统一管理 API

管理员登录后，在“系统设置 - 统一管理 API”创建 API Key。密钥只显示一次，应立即保存至受控的密钥管理工具。

完整网页文档：

```text
https://your-domain.example/docs/unified-management-api
```

API 根地址：

```text
https://your-domain.example/api/v1
```

请求头：

```text
Authorization: Bearer tvr_...
```

| Scope | 用途 |
| --- | --- |
| `accounts.read` | 读取服务商账号 |
| `resources.read` | 读取资源与可用操作目录 |
| `resources.manage` | 执行已授权的资源操作 |
| `sync.read` | 读取同步任务 |
| `sync.manage` | 创建账号同步任务 |

统一 API 不返回服务商凭据，也不提供任意 URL、请求头或凭据透传。自动化程序应先读取资源操作目录，再调用返回的、当前可用的操作；不要假设所有服务商或所有资源支持相同操作。

## 安全建议

- 为每个服务商创建最小权限、可撤销的 API 凭据。
- 首次在非生产资源验证开关机、重装、续费、DNS 和 SSL/TLS 操作。
- 重装、删除、续费、付款和 DNS 修改属于高风险操作，确认资源名称、地域、实例 ID 和账单信息后再执行。
- 为 SMTP 使用独立应用密码，不要使用邮箱主密码。
- 定期备份数据库和 `CREDENTIAL_ENCRYPTION_KEY`，并将备份放在受访问控制的位置。
- 定期撤销不再使用的统一 API Key 和服务商 API 凭据。
- 不要通过 Issue、日志、截图、前端代码或 Git 提交共享任何密码、Token、Secret、JWT、数据库连接串或付款链接。


## 目录说明

| 路径 | 说明 |
| --- | --- |
| `app/` | 控制器、命令、服务、服务商适配器和会话驱动 |
| `config/` | ThinkPHP、数据库、会话和服务商目录配置 |
| `database/migrations/` | 数据库结构迁移 |
| `database/seeds/` | 服务商目录初始化数据 |
| `docs/` | 统一管理 API 文档 |
| `public/` | Web 入口、静态资产与安装器入口 |
| `install.php` | 一次性 Web 安装器实现 |
| `.env.example` | 无敏感信息的环境变量模板 |

## 许可证

本项目使用 [Apache License 2.0](LICENSE)。该许可证允许商业使用、修改和再分发，并包含明确的专利授权条款；再分发时需要保留版权、许可证和 NOTICE 要求。

第三方服务商名称、商标、接口与文档分别归其权利人所有。本项目与这些服务商不存在默认的隶属、授权或背书关系。
