# 服务商 API 接入说明

系统只调用已经由官方文档核验的接口。服务商凭据加密保存，只在同步和资源操作进程内解密，绝不会复制到资源、任务或审计日志；上游资源元数据在写入前会递归脱敏。

| 服务商 | 官方文档 | 认证方式 | 已实现的只读同步 |
| --- | --- | --- | --- |
| 阿里云 ECS | [ECS API 概览](https://help.aliyun.com/zh/ecs/developer-reference/api-ecs-2014-05-26-overview) | RAM AccessKey，RPC Signature v1 | `DescribeInstances`，`PageNumber` / `PageSize` 分页 |
| 腾讯云 CVM | [CVM DescribeInstances](https://cloud.tencent.com/document/api/213/15728)、[TC3-HMAC-SHA256 签名](https://cloud.tencent.com/document/product/1278/46660) | TC3-HMAC-SHA256 | `https://cvm.tencentcloudapi.com` 的 `DescribeInstances`（`2017-03-12`），`Offset` / `Limit` 分页 |
| 腾讯云轻量应用服务器 Lighthouse | [Lighthouse DescribeInstances](https://cloud.tencent.com/document/api/1207/47573) | TC3-HMAC-SHA256 | `https://lighthouse.tencentcloudapi.com` 的 `DescribeInstances`（`2020-03-24`，service `lighthouse`），`Offset` / `Limit` 分页 |
| 华为云 ECS | [查询云服务器详情](https://support.huaweicloud.com/intl/en-us/api-ecs/ecs_02_0101.html) | AK/SK，`SDK-HMAC-SHA256` | `GET /v1/{project_id}/cloudservers/detail`，marker 分页 |
| AWS EC2 | [DescribeInstances](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstances.html) | AWS Signature Version 4 | `DescribeInstances`，`NextToken` 分页 |
| Google Compute Engine | [aggregatedList](https://cloud.google.com/compute/docs/reference/rest/v1/instances/aggregatedList) | Service Account JWT OAuth 2.0 | `aggregated/instances`，`nextPageToken` 分页 |
| Cloudflare | [Cloudflare API](https://developers.cloudflare.com/api/) | API Token | Token 验证和 `GET /zones`，`page` / `per_page` 分页 |
| 阿里云万网 | [QueryDomainList](https://help.aliyun.com/zh/domain/api-domain-2018-01-29-querydomainlist) | RAM AccessKey，RPC Signature v1 | `QueryDomainList`，`PageNum` / `PageSize` 分页 |
| 西部数码 | [公共参数](https://www.west.cn/CustomerCenter/doc/apiv2.html)、[域名列表](https://www.west.cn/CustomerCenter/doc/domain_v2.html) | `md5(username + api_password + timestamp)` 合作商 Token | `GET /domain/?act=getdomains`，发送必填公共参数 `username`、`time`、`token` 与 `page` / `limit`；仅 `result=200` 视为成功 |
| Spaceship | [Spaceship API](https://docs.spaceship.dev/#section/Spaceship-API) | `X-API-Key`、`X-API-Secret` | `GET /v1/domains`，`take` / `skip` 分页（`take` 为 1-100） |
| 魔方财务系统 | [参考 API 文档](http://w2.test.idcsmart.com/doc) | API 登录 JWT | `POST /v1/login_api`，随后以 `authorization: JWT {token}` 调用 `GET /v1/hosts?page={page}&limit={limit}` |
| IDCsmart V10 | [前台 API 文档](https://docs.idcsmart.com/docs/API%E6%96%87%E6%A1%A3) | 用户前台 Bearer Token | `GET /console/v1/idcsmart_common/host` |

## 自定义服务地址

魔方财务和 IDCsmart V10 可由各租户独立部署，因而每个账号必须填写服务地址。地址必须使用 HTTPS；保存和请求前都会拒绝私网、回环、链路本地及无法解析的目标，并在请求时锁定已验证的公网 IP 以降低 DNS 重绑定风险。其余服务商固定使用官方端点，不能由账号配置覆盖。

IDCsmart V10 使用用户前台 `bearer_token`。系统不会猜测或调用未经核验的登录接口，因为登录路径和请求载荷会随部署而异。

## 同步可靠性与对账

`sync_jobs` 是持久化任务队列。Worker 仅原子领取已到重试时间的任务，每次领取增加 `attempt_count` 并持有五分钟租约。每个上游请求及大批量本地写入前都会刷新 `heartbeat_at` 和 `lease_expires_at`；调度器、手动入队和 Worker 均会先恢复过期租约。

失败会在同一任务中依次延迟 1、2、4、8 分钟后重试，第五次失败才终止。终止失败会推进账号的调度时间，下一批任务须等待该账号设定的同步间隔；手动触发在重试等待期只会返回现有任务，不能绕过退避。任务 API 会返回 `attempt_count`、`last_attempt_at`、`next_retry_at`、`heartbeat_at`、`lease_expires_at`、`resources_stale`、`retry_pending` 与 `lease_active`。

只有完整成功的资源列表才会触发库存对账。发现到的资源标记为 `inventory_state=active` 并更新 `last_seen_at`；同一轮未再发现的自动资源标记为 `stale` 并写入 `stale_at`，历史记录不会被删除。手工创建的资源为 `inventory_state=manual`，不参与失联标记；服务商自身状态仍保存在 `cloud_resources.status`。

## 资源操作与 DNS

“获取当前状态”不会使用本地缓存伪造结果，而是为该账号创建一次库存同步任务。需要人工确认的操作必须精确输入资源名称；查询 DNS 记录属于只读操作，不会创建额外同步任务。

域名操作仅使用以下经过核验的写接口：阿里云万网续费、自动续费、DNS 服务器，以及 AliDNS `DescribeDomainRecords`、`AddDomainRecord`、`UpdateDomainRecord`、`DeleteDomainRecord`；Cloudflare `/zones/{zone_id}/dns_records` 的查询、新增、更新、删除；西部数码 `getdnsrecord`、`adddnsrecord`、`moddnsrecord`、`deldnsrecord` 表单接口；Spaceship `/v1/dns/records/{domain}` 的查询、记录集合保存和记录集合删除。Spaceship 的接口不是单条记录 ID CRUD，客户端必须提交服务商返回的记录对象数组。

云主机与业务面板的可执行按钮由对应服务商文档和产品控制面板共同限制。腾讯云 CVM 与轻量应用服务器是不同产品：轻量实例以 `lighthouse_instance` 保存，开机、关机、重启、销毁走 Lighthouse `2020-03-24`；重装走 `ResetInstance`，参数为 `BlueprintId` 而不是 CVM 的 `ImageId`。魔方财务、IDCsmart V10 只显示其当前产品控制面板返回的操作，避免对不支持的产品发送猜测性请求。

魔方财务的 KVM、iKVM、VNC 操作会从模块响应中提取服务商返回的连接地址，并在用户点击操作后于新窗口打开。仅允许 `http`、`https`、`vnc` 和 `vnc+ssl` 协议；操作响应中的其他文本不会作为浏览器地址执行。
