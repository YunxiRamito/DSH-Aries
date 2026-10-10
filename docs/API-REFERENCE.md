# Aries API v1 接入参考

本文按当前服务端实现整理，覆盖设备与群组公开 API、文件传输 API、服务器管理 API 和管理命令 API。第三方客户端应以此文及链接的专题文档为准；“当前实现边界”一节会标出尚未实现的能力。本参考不把未来设计契约描述成已上线功能。

## 1. 服务地址和传输规则

服务端有两个独立监听地址：

| 监听器 | 用途 | 路径 |
|---|---|---|
| Public listener | 设备、群组、消息和文件客户端 | `/api/v1/public/...` |
| Admin listener | `ariesctl` 和其他服务器管理前端 | `/api/v1/admin/...` |
| 两个监听器 | 健康检查 | `GET /healthz` |

监听地址由服务端配置决定。公开 API 与管理 API 不共享认证方式：公开 API 使用设备 Ed25519 请求签名；管理 API 使用管理员 Bearer token。不要把管理 token 放进客户端设备凭据，也不要把公开设备签名当作管理认证。

所有 JSON 请求和响应使用 UTF-8。请求体上限为 4 MiB。JSON 请求拒绝未知字段和尾随的第二个 JSON 值。文件块请求例外：请求体是原始二进制密文，不是 JSON。

非 loopback 连接必须使用 HTTPS。当前服务内核不直接配置 TLS 证书；生产远程接入应由 TLS 反向代理终止 TLS，并将服务监听绑定在 loopback 或可信私有接口。仅当 `allow_insecure_loopback` 启用时，loopback 上才接受明文 HTTP。服务端不信任转发头来判断客户端是否为 loopback。

## 2. 公开 API 认证

### 2.1 注册设备

客户端本地生成 Ed25519 密钥对。私钥只能保存在客户端。

1. 请求 `POST /api/v1/public/devices/challenge`，发送新设备的公钥：

   ```json
   {"public_key":"<Ed25519 公钥的无填充 base64url>"}
   ```

   成功响应包含 `challenge_id`、32 字节随机 `nonce` 和 `expires_at`。挑战有效两分钟；同一来源 IP 每分钟最多申请八次，同时最多保留 4,096 个未过期挑战。

2. 按下列 UTF-8 字符串生成签名消息，并用设备私钥签名：

   ```text
   enroll\n<challenge_id>\n<nonce>\n<public_key>
   ```

   `nonce` 和 `public_key` 使用上一步及第一步请求中的无填充 base64url 字符串。将签名以无填充 base64url 编码。

3. 请求 `POST /api/v1/public/devices/enroll`，并附上 `Idempotency-Key`：

   ```json
   {"challenge_id":"ch_...","signature":"<签名的无填充 base64url>"}
   ```

   成功响应为 `201 Created`，包含由公钥确定性派生的 `device_id` 和 `status: "registered"`。`Idempotency-Key` 长度为 8–128 个字符。

`POST /devices/challenge` 也接受 `{"device_id":"dev_..."}` 来取得绑定已登记设备的挑战；该挑战不替代下面每个请求都需要的设备请求证明。

### 2.2 签署已登记设备的请求

每个需要设备认证的请求（包括 GET）都必须包含以下请求头：

```text
X-Device-ID: dev_<server-issued-id>
X-Device-Timestamp: <RFC3339 时间戳>
X-Device-Nonce: <本请求唯一的 12–128 字符随机值>
X-Device-Signature: <Ed25519 签名，无填充 base64url>
```

需要幂等保护的写请求还必须包含：

```text
Idempotency-Key: <8–128 字符>
```

签名原文为下列各行以单个 LF (`\n`) 连接后的 UTF-8 字节，不包含最后的换行：

```text
<HTTP method>
<原始 request URI，包含 query string>
<X-Device-Timestamp 的原值>
<X-Device-Nonce 的原值>
<Idempotency-Key 的原值；非幂等请求为空行>
<base64url(SHA-256(原始请求体字节))>
```

空请求体的哈希是空字节串的 SHA-256。签名必须覆盖实际发送的请求体字节，不能先解析再重新序列化 JSON 后签名。时间戳允许与服务器时间相差最多五分钟。设备 nonce 只允许使用一次，服务端持久保存其哈希以便重启后仍能拒绝重放。

每个已认证的写操作均要求 `Idempotency-Key`。相同设备、操作、key 和请求体的重试返回第一次保存的 HTTP 状态码和响应体；相同操作重用 key 但请求体不同会返回 `409 idempotency_conflict`。发生网络超时、客户端未收到响应等结果不确定的情况，使用原 key 和原请求体重试。新业务操作必须生成新 key。

### 2.3 管理 API 认证

除 `GET /healthz` 外，管理 API 使用：

```text
Authorization: Bearer <admin-token>
```

管理写操作按接口要求使用 `Idempotency-Key`，但不使用设备签名。服务器不会在配置响应中返回 token 本身。

## 3. 通用响应与错误

成功响应根据接口使用 JSON 或文件块二进制。服务端为每个请求返回 `X-Request-ID`。错误响应均为 JSON：

```json
{
  "error": {
    "code": "membership_required",
    "message": "active group membership is required",
    "request_id": "<与 X-Request-ID 相同>"
  }
}
```

常见状态码：

| HTTP 状态 | 含义 |
|---|---|
| `400` | 请求体、签名字段、游标、参数或幂等 key 格式无效 |
| `401` | 管理 token、挑战或设备请求证明无效/过期 |
| `403` | 已认证但无群组成员资格、权限不足，或功能未启用 |
| `404` | 群组、邀请、申请、成员、事件或文件不存在/不可用 |
| `409` | 幂等 key 冲突、状态冲突、版本代次错误或签名 nonce 重放 |
| `410` | 文件密文已清理；或调用了已退役的 inline 文件 API |
| `422` | 已上传文件的整体 SHA-256 与声明值不匹配 |
| `426` | 非 loopback 明文 HTTP；应改用 HTTPS |
| `429` | challenge 请求超过来源 IP 速率限制 |
| `500` / `503` | 服务内部或持久化暂时不可用 |
| `507` | 全局或群组文件配额无法容纳新文件 |

收到 `4xx` 验证或权限错误时不要原样重试；瞬时 `5xx` 可在退避后重试。写操作结果不确定时遵守幂等规则并重用原 key。

## 4. 公开设备和群组 API

以下路径均以 `/api/v1/public` 为前缀。除表中标记为“公开”的路径外，都必须带设备请求证明；所有写操作都必须带 `Idempotency-Key`。示例中的 `{group}`、`{code}`、`{application}`、`{member}`、`{event}`、`{delivery}` 是路径参数，客户端应按 URL path segment 编码。

### 4.1 节点和设备

| 方法和路径 | 认证 | 请求 | 成功响应 |
|---|---|---|---|
| `GET /healthz` | 公开 | 无 | `status`、`api_version`、`build_version`、`started_at` |
| `GET /node` | 公开 | 无 | `node_id`、`server_code`、`api_version` |
| `POST /devices/challenge` | 公开 | `public_key` 或 `device_id` 二选一 | `challenge_id`、`nonce`、`expires_at` |
| `POST /devices/enroll` | enroll challenge 签名 + 幂等 key | `challenge_id`、`signature` | `device_id`、`status`；首次注册 `201`，已有相同设备 `200` |

公钥必须是 32 字节 Ed25519 公钥的无填充 base64url。设备 ID 为 `dev_` 加公钥 SHA-256 前 16 字节的小写十六进制。`server_code` 是供人识别的短码，可能碰撞；协议识别节点时必须使用完整 `node_id`。

### 4.2 邀请、申请和入群

| 方法和路径 | 请求体 | 成功响应与约束 |
|---|---|---|
| `POST /groups` | `{"name":"...","approval_policy":"creator"}` | `201`：`group_id`、`authority_node`、`generation`、`invite_code`、`invite_expires_at`、`member`。创建者自动成为 creator，初始 generation 为 1，并同时创建一个三分钟邀请。 |
| `POST /groups/{group}/invites` | 空 body 或 `{}` | `201`：`invite_code`、`group_id`、`expires_at`。任何活跃成员都可创建邀请。 |
| `GET /invites/{code}` | 公开，无 body | `200`：`group_id`、`group_name`、`authority_node`、`member_count`、`approval_policy`、`expires_at`。仅返回展示信息。 |
| `POST /invites/{code}/applications` | 空 body 或 `{}` | `201`：`application_id`、`group_id`、`status`、`required_approvals`。邀请必须尚未过期/撤销，设备不能已是活跃成员。 |
| `GET /groups/{group}/applications` | query 可选 `status`、`cursor`、`limit` | `200`：`items`、`next_cursor`。仅群组活跃成员可读取；默认只返回 `pending_approval`、`awaiting_key`，排序为 `created_at` 升序再按 `application_id` 升序。 |
| `GET /groups/{group}/applications/{application}` | 无 body | `200`：`application_id`、`device_id`、`public_key`、`status`、`approvals`、`created_at`、`updated_at`。申请人本人或群组活跃成员可查看。 |
| `POST /groups/{group}/applications/{application}/approvals` | `{"approve":true}` 或 `false` | `200`：`application_id`、`status`、`approvals`。活跃成员须为此申请的审批人；群组 admin 可代行一个尚未处理的审批槽。拒绝后为 `rejected`，全部批准后为 `awaiting_key`。 |
| `POST /groups/{group}/applications/{application}/key-delivery` | `{"envelope":"<opaque base64url>"}` | `201`：`application_id`、`status:"approved"`、`member_device_id`、`generation`。任何活跃成员可在申请为 `awaiting_key` 时提交加密信封；成员加入和信封入队原子提交。 |

`approval_policy` 可选 `all`、`creator`、`inviter`、`creator_inviter` 或 `public`。`public` 申请跳过审批并进入 `awaiting_key`；其他策略依据邀请时对应的活跃成员产生审批槽。申请状态常见值为 `pending_approval`、`awaiting_key`、`approved`、`rejected`。

申请列表的 `limit` 默认 100、最大 200；`status` 可重复或使用逗号分隔，支持上述四种状态和 `all`。`cursor` 是服务端返回的不透明无填充 base64url 游标，客户端不得自行构造或解析；空 `next_cursor` 表示没有下一页。列表和详情中的 `public_key` 始终从已登记设备身份读取，并与 `device_id` 一致。

信封是 opaque payload；服务端只存储和转交，不能解密内容密钥。加入设备通过 `GET /groups/{group}/key-deliveries` 获取未确认的密钥投递，见 4.5。

### 4.3 群组、成员、离开和轮换

| 方法和路径 | 请求体 / query | 成功响应与权限 |
|---|---|---|
| `GET /groups/{group}/members` | 无 body | `200`：`{"items":[Member...]}`。仅活跃成员可读取；Member 字段为 `device_id`、`public_key`、`role`、`active`、`joined_at`。 |
| `PUT /groups/{group}/members/{member}/role` | `{"role":"admin"}` 或 `{"role":"member"}` | `200`：`group_id`、`device_id`、`role`。仅 creator 可调整其他活跃成员的角色；creator 角色必须通过下方转让接口转移。 |
| `DELETE /groups/{group}/members/{member}` | 空 body 或 `{}` | `202`：`group_id`、`device_id`、`status:"revoked"`、`control_event_id`、`required_generation`。Creator 可撤销任一非 creator 成员（包括 admin）；admin 只能撤销普通成员。被撤销的成员立即失去群组访问权。 |
| `POST /groups/{group}/creator` | `{"new_creator_id":"dev_..."}` | `200`：`group_id`、`creator_id`。仅当前 creator 可将角色转给一个活跃成员；原 creator 转成普通 member。 |
| `POST /groups/{group}/leave` | 空 body 或 `{}` | `202`：`status:"left"` 加轮换事件字段；若最后一名成员离开则 `200`、`status:"group_closed"`。Creator 有其他成员时须先转让 creator。 |
| `GET /groups/{group}/events?after=0&wait_ms=0&limit=100` | query 可选 | `200`：`items`、`next_cursor`。仅活跃成员可读取，按群组序号升序返回控制事件和消息。 |
| `POST /groups/{group}/rotations/{event}` | `{"epoch":N,"envelopes":{"dev_id":"<opaque base64url>"}}` | `200`：`event_id`、`status:"completed"`、`generation`。见下文轮换要求。 |

`GET /events` 参数：`after` 是无符号整数序号（默认 0）；`wait_ms` 默认 0、负值无效、最大等待 25,000 ms（更大值会被截到 25,000）；`limit` 默认 100，必须为正数，最大 200（更大值会被截到 200）。成功响应中的 `next_cursor` 是十进制字符串，应保存并在下一次请求中作为 `after` 传回。长轮询被客户端取消时，服务器可能直接结束连接而不发送 JSON 响应。

`items` 是以下混合形式，消息和控制事件共享同一群组序号空间：

```json
{"sequence":12,"type":"control","event":{"id":"evt_...","type":"member_left","device_id":"dev_...","required_epoch":2,"created_at":"...","sequence":12}}
{"sequence":13,"type":"message","message":{"id":"msg_...","group_id":"grp_...","sender_id":"dev_...","epoch":2,"ciphertext":"...","created_at":"...","sequence":13}}
```

成员离开或被撤销会创建持久的控制事件和递增的 required generation。剩余成员先读取事件，再由任一活跃成员为除自己以外的每个活跃成员提供且仅提供一个新密钥信封。轮换必须按事件顺序完成，`epoch` 必须等于事件的 `required_epoch` 且大于当前 generation。存在未完成轮换时，消息和文件发布返回 `409 rotation_required`；旧 epoch 内容返回 `409 generation_mismatch`。

### 4.4 设备心跳与小组在线状态

| 方法和路径 | 请求体 | 成功响应与权限 |
|---|---|---|
| `POST /devices/heartbeat` | `{}` 或 `{"client_version":"launcher/1.0"}` | `200`：`device_id`、`online:true`、服务端生成的 `last_seen_at`、`expires_at`，以及可选 `client_version`。需要设备签名，不要求幂等 key。 |
| `GET /groups/{group}/presence` | 无 body | `200`：`{"items":[...]}`。仅当前小组活跃成员可读，按 `device_id` 稳定排序。 |

心跳时间由服务端接收时间决定，客户端不能提交或覆盖 `online`。presence 默认超时为 90 秒，心跳建议间隔为 30 秒；可通过 `heartbeat_interval_seconds` 和 `heartbeat_timeout_seconds` 配置，0 使用默认值。`client_version` 最多 64 字节且不得包含换行。返回项包含 `device_id`、`online`、`last_seen_at`，有版本时还包含 `client_version`；从未心跳的成员 `online:false` 且 `last_seen_at` 为空。在线状态只保存在进程内内存，服务重启后所有成员先报告离线，不从历史快照恢复。单进程最多保留 100,000 个设备记录，过期记录会在心跳时清理。成员离开或被撤销后立即失去 presence 读取权限，并从其小组结果中消失。

### 4.5 密钥投递

| 方法和路径 | 请求体 | 成功响应与说明 |
|---|---|---|
| `GET /groups/{group}/key-deliveries` | 无 body | `200`：`{"items":[KeyDelivery...]}`，只返回当前设备尚未确认的投递。 |
| `POST /groups/{group}/key-deliveries/{delivery}/ack` | 空 body 或 `{}` | `200`：`delivery_id`、`status:"acknowledged"`。只有指定 recipient 可确认。 |

KeyDelivery 对象包含 `id`、`group_id`、`sender_id`、`recipient_id`、`epoch`、`envelope`、`created_at`、`acknowledged`。确认后再次读取未确认列表时不会再出现该项。

### 4.6 群组消息

| 方法和路径 | 请求体 / query | 成功响应 |
|---|---|---|
| `POST /groups/{group}/messages` | `{"epoch":N,"ciphertext":"<非空无填充 base64url>"}` | `201`：`message_id`、`generation`、`created_at`。 |
| `GET /groups/{group}/messages?after=0&limit=100` | `after`、`limit` 可选 | `200`：`items`、`next_cursor`。每项含 `id`、`group_id`、`sender_id`、`epoch`、`ciphertext`、`created_at`、`sequence`。 |

两个接口仅活跃成员可用。消息 ciphertext 必须是非空、无 `=` padding 的 base64url。`epoch` 必须严格匹配当前 generation。`after` 是无符号序号；`limit` 默认 100、最大 200。消息列表对格式错误或小于 1 的 limit 使用默认值，对大于最大值的 limit 截为最大值；`next_cursor` 是十进制字符串。

### 4.7 文件传输

文件 API 的逐步上传、断点续传、配额、TTL、校验、tombstone 和响应示例见 [FILE-TRANSFER.md](FILE-TRANSFER.md)。接口清单：

| 方法和路径 | 用途 |
|---|---|
| `POST /groups/{group}/file-transfers` | 创建上传；JSON 包含 `epoch`、`encrypted_metadata`、`size_bytes`、`sha256`，可选 `chunk_size_bytes`、`ttl_seconds`、`targets`。 |
| `PUT /groups/{group}/file-transfers/{file}/chunks/{index}` | 上传 raw ciphertext chunk。必须与声明长度一致，最多 4 MiB；成功返回该块 SHA-256。 |
| `GET /groups/{group}/file-transfers/{file}/chunks/{index}` | 下载 raw ciphertext chunk；响应头 `X-Chunk-SHA256` 给出该块摘要。 |
| `POST /groups/{group}/file-transfers/{file}/complete` | 校验所有块和整体 SHA-256 并完成上传；空 body 或 `{}`。 |
| `GET /groups/{group}/file-transfers` | 按 `offset`/`limit` 分页列出上传、已完成及 tombstone 元数据。 |
| `GET /groups/{group}/file-transfers/cache` | 返回当前小组 transfer 缓存的 `uploading`、`available`、`cleanup_pending`、`logical_deleted` 统计，不触碰其他小组。 |
| `POST /groups/{group}/file-transfers/cache/cleanup` | `{"file_ids":["ft_..."]}` 批量逻辑删除当前小组文件缓存；最多 100 个 ID，需要幂等 key。 |
| `POST /groups/{group}/file-transfers/{file}/ack` | 接收目标确认下载；空 body 或 `{}`。 |
| `DELETE /groups/{group}/file-transfers/{file}` | 发送者、creator 或 admin 删除传输。 |

上传/完成/确认/删除和块上传都是设备签名的写请求，均需要幂等 key。文件块请求签名时直接对原始 ciphertext 字节计算 SHA-256。文件存储必须启用；若关闭则文件 API 返回 `403 file_storage_disabled`。旧 `POST|GET /groups/{group}/files` 和 `DELETE /groups/{group}/files/{file}` inline API 已退役，返回 `410 file_transfer_required`；客户端应迁移到分块 API。

缓存统计每个桶包含 `count` 和逻辑 `bytes`，另外返回 `physical_bytes`。`cleanup_pending` 表示已有 tombstone 但磁盘 blob 或上传目录仍存在，`logical_deleted` 表示逻辑删除记录总数。清理成功响应包含 `group_id`、`requested`、`logical_deleted`、`already_deleted`、`cleanup_pending` 和 `physical_cleanup_complete`；逻辑状态先提交，物理删除失败时会保留 tombstone 并报告待清理文件。普通成员只能清理自己发送的 transfer，creator/admin 可清理本组 transfer；请求中的任何文件 ID 跨组、未知或不属于当前小组时整批失败。该接口不会清理其他小组、成员关系、设备身份、密钥投递或控制事件。

## 5. 管理 API

以下路径以 `/api/v1/admin` 为前缀，除 `GET /healthz` 外均需要 Bearer 管理 token。所有写操作按表使用 `Idempotency-Key`。

| 方法和路径 | 请求 | 成功响应 / 说明 |
|---|---|---|
| `GET /healthz` | 无认证 | `status`、`api_version`、`build_version`、`started_at`。 |
| `GET /status` | 无 body | 节点身份、监听地址/状态、运行时间、存储状态、待处理控制事件数，以及明确标记为 `not_supported` 或 `not_implemented` 的状态。当前 `connected_devices` 为 null、`connected_devices_state` 为 `not_supported`。 |
| `GET /config` | 无 body | 返回有效配置，不含 token 秘密值；只含 `admin_token_file` 路径。 |
| `PUT /config` | 完整配置 JSON；需要幂等 key | 校验并持久化配置。未知字段被拒绝。建议先 GET，再修改后发送完整对象；省略字段会取当前版本默认值，而不是沿用现有值。监听地址、数据目录或 token 文件路径变化时，响应包含 `restart_required:true`。 |
| `GET /groups` | 无 body | `{"items":[...]}`，列出本节点群组摘要。 |
| `GET /storage` | 无 body | 返回用量、配额、文件数、待完成上传、tombstone、淘汰数、功能开关和状态。 |
| `POST /shutdown` | 空 body；需要幂等 key | 返回 `202 {"status":"shutting_down"}`，先持久化幂等结果并关闭状态存储，再请求服务退出。 |
| `GET /commands` | 无 body | 返回 canonical typed command registry（`api_version`、`items`）。 |
| `GET /commands/help?path=groups%20list` | 查询命令路径 | 返回 `command` 元数据和 `help` 摘要；缺省 path 为 `help`。 |
| `POST /commands/complete` | `{"words":["groups",""],"cursor_position":2}` | 返回 `{"candidates":[{"value":"list","display":"list","description":"..."}]}`。cursor 是 token 数组中的位置。 |
| `POST /commands/execute` | `{"argv":["status"],"flags":{}}` | 返回 `status`、`summary`、可选 `data`、`warnings`、`request_id`。`argv` 是结构化 token 数组，不是 shell 字符串。持久化命令须有幂等 key。 |

配置字段和 JSON 类型：

| 字段 | 类型 | 含义 |
|---|---|---|
| `schema_version` | integer | 当前为 `1`。 |
| `public_listen`、`admin_listen` | string | `host:port` 监听地址。 |
| `data_dir`、`admin_token_file` | string | 数据目录和 token 文件路径；相对路径按配置文件所在目录解析。 |
| `max_storage_bytes` | integer | 全局文件存储配额；`0` 表示不设该限额。 |
| `allow_insecure_loopback`、`peer_relay_enabled`、`file_storage_enabled` | boolean | loopback 明文开发模式、peer relay 开关、文件存储开关。Peer relay 当前未实现；开关为 true 时 status 会报告 `not_implemented`。 |
| `group_quota_bytes`、`quota_bytes_per_member` | integer | 群组配额，或按活跃成员数计算的配额；大于 0 的 per-member 值优先。 |
| `max_file_bytes`、`max_file_ttl_seconds` | integer | 单文件大小和最长保留时间上限。 |
| `heartbeat_interval_seconds`、`heartbeat_timeout_seconds` | integer | 客户端建议心跳间隔和在线超时；默认分别为 30 和 90，0 使用默认值。超时不得小于间隔，且分别不超过 86400 和 604800。 |

管理配置 PUT 使用严格 JSON 解码但会先以当前构建的默认配置填充未提供字段，因此发送配置更新时应始终带上 GET 返回的完整字段，避免静默恢复其他设置的默认值。管理命令的完整注册表、类型、权限标签、示例和本地命令限制见 [ADMIN-COMMANDS.md](ADMIN-COMMANDS.md)。Token create/rotate 是本地 CLI 操作，执行 API 不会生成或传回 token。

当前 REST 管理端只有群组摘要 `/groups`，没有单独的 REST 群组详情/成员管理路径；详情、角色、撤销和邀请管理由 canonical command API 提供。

## 6. 分页、重试和客户端实现建议

- 保存事件和消息的 `next_cursor`，处理完当前批次后再提交游标，避免客户端崩溃时跳过尚未持久化处理的消息。
- 对控制事件先执行密钥轮换并确认投递，再恢复发布新消息/文件。服务端只检查信封集合和 generation，不验证客户端的端到端加密是否正确。
- 网络中断或超时时，查询列表/状态确认操作是否提交；对幂等写请求用相同 key 和完全相同的 body 重试。
- 以节点完整 `node_id` 标识服务器。当前 `server_code` 仅用于显示，节点间发现、邀请转发和源节点解析未实现。
- 除文件 API 外，当前公开协议没有 WebSocket。事件通过有上限的 HTTP long-poll 获取。

## 7. 当前实现与验证边界

此 API 版本已实现单节点设备注册、群组邀请与审批、待处理申请列表、公钥读取、成员角色/撤销、设备心跳与小组 presence、持久事件、轮换信封、opaque 消息中继、可续传加密文件存储和按小组缓存清理。在线状态只存在内存，重启后从离线开始；缓存清理只写入文件 tombstone 并清理指定小组的 blob/上传临时目录，不影响控制事件、成员关系、设备身份或密钥投递。以下能力未实现：WebSocket、多节点 federation/复制/转发、跨节点邀请发现、数据库后端、群组审计日志、生产 TLS 证书管理和 peer relay。状态字段遇到未实现能力时会返回 `not_supported` 或 `not_implemented`，客户端不应假定它可用。

当前自动化 API 测试使用进程内 `httptest` 服务端：覆盖了设备注册、群组入群/消息/离开/重启/轮换的主流程、申请列表和公钥边界、心跳过期/重启/撤销权限、挑战限流和签名 nonce 重放、管理认证/配置校验/命令 API，以及文件上传续传/下载/确认/配额/TTL/tombstone/按组缓存清理。它们验证服务端处理器和持久化行为，不等于对生产部署逐路由的线上验证。仍缺少直接 HTTP 路由测试的接口包括：邀请创建/查询、申请状态、事件 long-poll、角色更新、成员列表、密钥投递列表/确认、消息列表，以及管理端群组/存储查询、shutdown、成功的 REST 配置更新。服务器上的人工检查目前确认过管理端 `GET /status`；公开设备、群组、消息及文件全流程尚未在部署服务器完成端到端联调。

路由注册和数据结构以 `internal/kernel/server.go`、`internal/kernel/public.go`、`internal/kernel/files.go`、`internal/kernel/commands.go` 和 `internal/store/store.go` 为实现依据。专题说明：[CLIENT-PROTOCOL.md](CLIENT-PROTOCOL.md)、[FILE-TRANSFER.md](FILE-TRANSFER.md)、[ADMIN-COMMANDS.md](ADMIN-COMMANDS.md)。
