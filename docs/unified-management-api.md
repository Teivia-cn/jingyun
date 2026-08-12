# 塔维云资源管理系统统一管理 API

本文档描述塔维云资源管理系统对外提供的版本化 API。它统一返回已接入账号、标准化资源、资源操作目录及同步任务；服务商凭据始终保留在服务端加密存储，不会通过此 API 返回或接受。

## 基本信息

- Base URL: `https://console.example.com/api/v1`（将示例域名替换为你的站点地址）
- 数据格式: `application/json; charset=utf-8`
- 鉴权方式: `Authorization: Bearer tvr_...`
- 所有写请求必须携带 `Content-Type: application/json`。

在系统设置的“统一管理 API”区域创建 API 密钥。密钥仅会显示一次，应立即保存到密钥管理工具。密钥可单独撤销，撤销后立即失效。

所有成功响应均使用以下信封：

```json
{
  "code": 0,
  "message": "ok",
  "data": {}
}
```

失败响应的 `code` 与 HTTP 状态码一致，并可能包含字段错误：

```json
{
  "code": 422,
  "message": "This operation is not available for the resource provider.",
  "errors": {
    "operation": "Unsupported operation."
  }
}
```

## 权限范围

| Scope | 权限 |
| --- | --- |
| `accounts.read` | 读取已接入的服务商账号 |
| `resources.read` | 读取资源和可用操作目录 |
| `resources.manage` | 执行资源操作 |
| `sync.read` | 读取同步任务 |
| `sync.manage` | 为指定账号创建同步任务 |

建议为自动化任务创建最小权限的独立密钥。例如只读盘点只需要 `accounts.read`、`resources.read` 和 `sync.read`。

## 分页

列表接口接受 `page` 与 `per_page` 参数。`page` 从 1 开始，`per_page` 范围为 1-100，默认 20。列表结果包含 `items` 与 `pagination`，例如：

```json
{
  "items": [],
  "pagination": {
    "page": 1,
    "per_page": 20,
    "total": 0,
    "last_page": 1
  }
}
```

## 账号

### 读取账号

`GET /accounts?page=1&per_page=20`

需要 `accounts.read`。响应中的账号会包含服务商标识、区域、同步状态等安全字段；不会包含 API Token、密码或 Secret。

```bash
curl -sS 'https://console.example.com/api/v1/accounts?page=1&per_page=20' \
  -H 'Authorization: Bearer tvr_replace_with_your_key'
```

## 资源

### 列出资源

`GET /resources?page=1&per_page=20`

需要 `resources.read`。可选过滤参数：`cloud_account_id`、`provider_slug`、`resource_type`、`status` 与 `region`。

```bash
curl -sS 'https://console.example.com/api/v1/resources?provider_slug=cloudflare' \
  -H 'Authorization: Bearer tvr_replace_with_your_key'
```

### 获取资源详情

`GET /resources/{resourceId}`

需要 `resources.read`。资源使用系统内的数值 `id` 寻址；`external_id` 是服务商侧标识，仅供展示和追踪。

### 获取可执行操作

`GET /resources/{resourceId}/actions`

需要 `resources.read`。返回值中的 `actions` 是该资源当前可执行的唯一操作集合。不要假设所有实例、域名或面板产品支持相同操作。

每个操作会给出 `id`、`label`、`dangerous`、`fields`、`read_only` 与所需确认方式。`type: "select"` 的字段必须从 `options[].value` 选择。

对于魔方财务系统，系统会先读取该产品控制面板；若支持重装，会从 `GET /v1/hosts/{hostId}/module/reinstall` 获取可重装系统。`reinstall` 操作的 `os_id` 选项即服务商要求的操作系统 ID，调用方应提交该值而不是显示名称。

### 执行资源操作

`POST /resources/{resourceId}/actions`

需要 `resources.manage`。只能执行上一节操作目录中出现的 `operation`，不能通过此接口传入任意服务商 URL、Header 或凭据。

```json
{
  "operation": "start",
  "parameters": {},
  "confirmation": ""
}
```

危险操作必须将 `confirmation` 设置为资源的完整 `name`。例如重装系统：

```json
{
  "operation": "reinstall",
  "parameters": {
    "os_id": "provider-returned-os-id",
    "password": "one-time-new-password",
    "part_type": 0
  },
  "confirmation": "资源完整名称"
}
```

密码字段仅用于本次服务商请求，会从审计记录和响应展示中剔除。服务商操作成功后，响应会返回处理后的安全摘要；变更操作通常还会返回 `sync_job_id`，用于等待资源目录更新。

Cloudflare DNS 新增或修改使用 `create_dns_record` 或 `update_dns_record`。`type` 必须是操作目录提供的 DNS 记录类型之一，例如 `A`、`AAAA`、`CNAME`、`TXT`、`MX`、`NS`、`SRV` 或 `CAA`。服务端还会再次验证 Cloudflare 的完整记录类型白名单。

## 同步任务

### 列出同步任务

`GET /sync-jobs?page=1&per_page=20`

需要 `sync.read`。可使用 `status` 过滤 `queued`、`running`、`succeeded` 或 `failed`。

### 创建账号同步任务

`POST /accounts/{accountId}/sync`

需要 `sync.manage`。此接口只会入队；Worker 会异步调用服务商 API。若账号已有排队或运行中的任务，系统会返回该任务而不会创建重复任务。

```bash
curl -sS -X POST 'https://console.example.com/api/v1/accounts/12/sync' \
  -H 'Authorization: Bearer tvr_replace_with_your_key' \
  -H 'Content-Type: application/json' \
  --data '{}'
```

## 状态码与安全约束

- `200` / `202`: 请求已完成或已入队。
- `401`: API 密钥缺失、无效、已撤销或已过期。
- `403`: API 密钥不具备该接口所需的 scope。
- `409`: 危险操作确认文本不匹配，或资源状态不允许该请求。
- `415`: 写请求缺少 `application/json`。
- `422`: 参数、分页值、资源操作或选择项无效。
- `502` / `503`: 服务商或服务端暂时不可用，可按退避策略重试只读和同步请求。

不要在浏览器前端、日志、工单或源码中保存 API 密钥。密钥的使用会进入本系统审计记录，但密钥原文、服务商凭据和一次性操作密码不会记录。
