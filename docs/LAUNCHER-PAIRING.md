# 启动器配对与设备名称接入（0.0.3）

2026-10-12，Asia/Shanghai。本文是服务端接入契约；Windows 启动器和 Android 客户端代码由各自项目负责。

## 能力协商及入口

当前部署客户端入口为 `https://202.189.21.218:10240`。客户端须使用已交付的自定义 CA，同时保持证书链、有效期和 IP SAN 严格校验。内部明文地址及 admin listener 不应提供给远程客户端。

`GET /api/v1/public/node` 无需认证。部署节点的响应如下；客户端应继续 pin 完整 `node_id`，短码只用于展示。

```json
{
  "api_version": "v1",
  "node_id": "node_b33cb5aeb7f7b28f2aad04918966c7b1",
  "server_code": "224Y",
  "capabilities": [
    "group_applications",
    "device_public_key",
    "device_name",
    "device_presence",
    "group_file_cache_cleanup"
  ]
}
```

只有能力数组包含 `device_name` 时才上传新字段。旧版本可能没有能力数组但已有申请列表；合法 `{"items":[],"next_cursor":""}` 是正常空列表。`404/405` 应结合具体路径判断是否缺接口；`401/403` 是认证或成员权限错误，不能显示为“不支持”。忽略未知响应字段和能力值。

## 上传名称

保持原 Ed25519 注册流程和请求签名规范；名称不放入 enroll 请求。名称通过设备本人的已签名心跳发送：

```http
POST /api/v1/public/devices/heartbeat
Content-Type: application/json
X-Device-ID: dev_<已登记设备>
X-Device-Timestamp: <RFC3339 UTC>
X-Device-Nonce: <新随机 nonce>
X-Device-Signature: <现有规范的 Ed25519 签名>
```

```json
{"client_version":"android/1.0","device_name":"  OPPO Find X8  "}
```

成功响应为 `200`。下面除名称/版本外的设备 ID 和时间是示例值；时间由服务器接收心跳时生成，默认过期时间为 90 秒后。

```json
{
  "device_id": "dev_<已登记设备>",
  "device_name": "OPPO Find X8",
  "online": true,
  "last_seen_at": "2026-10-12T08:00:00Z",
  "expires_at": "2026-10-12T08:01:30Z",
  "client_version": "android/1.0"
}
```

- 先拒绝原始名称中的 Unicode 控制字符，包括换行、Tab、NUL、DEL；再 trim 两端 Unicode 空白。
- trim 后要求 1–128 个 Unicode code point，按字符而非 UTF-8 字节、UTF-16 code unit 或显示字素计数。
- 未提供名称或 `"device_name":null` 保留原值；空字符串/全空白不用于清空名称。
- 无已存名称时省略响应 `device_name`；有名称时，即使发送旧 `{}` 心跳，响应也包含当前名称。`client_version` 仍按原契约处理，省略时响应为空字符串。
- 名称实际变更才原子持久化；普通心跳或同名上报不重写 JSON 状态快照。名称跨服务重启保留，在线状态仍只在内存中，重启先报告离线。
- 心跳不要求或缓存 `Idempotency-Key`。按既有签名原文，在未发送该头时对应行为空；重试必须换 nonce 并重新签名。其他配对写操作仍要求稳定幂等 key，重试同一操作保留 key 和原始 body，但更新 nonce/签名。

## 读取并配对

已签名 `GET /api/v1/public/groups/{group}/applications?limit=100`，仅本组活跃成员可读取。默认仅返回 `pending_approval`、`awaiting_key`；排序是 `created_at` 升序后 `application_id` 升序。最大 `limit=200`；使用返回的 opaque `next_cursor` 请求后续页。以下为字段示例，省略号占位符不是可使用的身份或公钥。

```json
{
  "items": [
    {
      "application_id": "app_...",
      "device_id": "dev_...",
      "public_key": "<32 字节 Ed25519 公钥的无填充 base64url>",
      "device_name": "OPPO Find X8",
      "status": "pending_approval",
      "created_at": "2026-10-12T08:00:00Z",
      "updated_at": "2026-10-12T08:00:00Z"
    }
  ],
  "next_cursor": ""
}
```

已签名 `GET /api/v1/public/groups/{group}/applications/{application}`，申请人本人或本组活跃成员可读：

```json
{
  "application_id": "app_...",
  "device_id": "dev_...",
  "public_key": "<已登记设备公钥>",
  "device_name": "OPPO Find X8",
  "status": "pending_approval",
  "approvals": {"dev_<审批成员>": false},
  "created_at": "2026-10-12T08:00:00Z",
  "updated_at": "2026-10-12T08:00:00Z"
}
```

已签名 `GET /api/v1/public/groups/{group}/members`，仅本组活跃成员可读：

```json
{
  "items": [
    {
      "device_id": "dev_...",
      "public_key": "<已登记设备公钥>",
      "device_name": "OPPO Find X8",
      "role": "member",
      "active": true,
      "joined_at": "2026-10-12T08:00:30Z"
    }
  ]
}
```

三个接口的 `device_name` 均可省略，读取的是已登记设备的当前名称；公钥也来自该设备身份记录。重命名不修改申请状态、申请时间、设备 ID、公钥或已配对关系。成员列表只返回活跃成员。

推荐接入顺序：

1. 验证 TLS 及节点 pin，读取 capabilities，正常 enroll 后用 signed heartbeat 上传本机名称。
2. 创建小组或通过原短期邀请提交申请。现有邀请码、审批策略不变。
3. 活跃成员读取申请，展示名称并核验 ID/公钥指纹；用户确认后发送原 `{"approve":true}` 审批。拒绝发送 `false`。
4. 状态为 `awaiting_key` 后，根据已登记公钥在客户端加密内容密钥，按原 `key-delivery` 契约提交 opaque 信封。
5. 申请设备读取 `/key-deliveries`，在客户端校验/解密后向 `/key-deliveries/{delivery}/ack` 确认。列表中投递标识字段是 `id`，ack 响应字段是 `delivery_id`。
6. 通过成员列表获取已确认对端名称，用 presence 获取在线状态。没有名称时显示“对方尚未共享设备名称”。名称不能替代身份或作为审批凭据。

服务端通用小组仍支持多人；启动器可把两个成员显示为双设备连接。没有新增人数限制、自动同意或自动内容密钥分发。

## 错误和失败处理

错误响应统一为 `{"error":{"code":"...","message":"...","request_id":"..."}}`。

| HTTP / code | 触发条件及处理 |
|---|---|
| `400 invalid_device_name` | 名称为空、超长或含控制字符；修正后发送，不污染原值/不刷新此次在线时间。 |
| `400 invalid_request` | 字段类型、未知请求字段或 JSON 不合法。 |
| `401 device_proof_required` / `device_proof_expired` / `invalid_device_proof` | 签名证明缺失、过期、nonce 格式无效或验签失败；检查已有认证契约。 |
| `403 membership_required` | 不是目标小组的活跃成员，包括未加入、已离开或已撤销。详情接口仍保留申请人本人可读的原例外。 |
| `404 group_not_found` / `application_not_found` | 目标不存在，或申请 ID 不属于请求的小组。 |
| `409 replayed_device_proof` | nonce 重用；必须重新签名。 |
| `409 idempotency_conflict` | 其他配对写操作用同一幂等 key 发送不同 body。 |
| `500 storage_unavailable` | 名称提交失败；未提交名称不发布，此次心跳不刷新在线时间。重试使用新 nonce。 |
| `503 presence_capacity` | 内存 presence 记录达到上限且无可清理过期项；退避重试。 |

身份签名、nonce 防重放、时间窗口、group 权限及文件能力规则继续按 [API-REFERENCE.md](API-REFERENCE.md) 执行。设备名称由用户设备自行声明，可能同名或虚报型号。

## 升级及回滚

0.0.3 可读取原 0.0.2 状态。旧版存储解码器拒绝未知 `device_name` 字段，所以首次名称持久化后，不能直接换回 0.0.2 二进制并读取新快照。部署前备份二进制、配置、状态快照及 nonce sidecar；回滚要协调状态格式迁移或恢复匹配备份，评估备份后的写入，不能覆盖仍在运行的服务状态。

## 验证记录

发布前 `go test ./...` 与 `go vet ./...` 均通过。新增自动化测试覆盖名称 roundtrip、Unicode 限制、旧心跳与同名无快照重写、重启名称/离线分离、持久化失败不刷新在线状态、同公钥重新 enrollment 保留名称、签名冒充和匿名拒绝、完整批准/拒绝/密钥投递/确认链路、分页及原权限边界，并确认三成员小组继续可用。

2026-10-12 13:45（Asia/Shanghai），服务器升级到 0.0.3。Windows 本地 Go 客户端从上述公网入口完成 44 项 HTTP 状态及响应检查，使用可信 CA 根指纹校验、正常证书链验证、IP SAN 校验和完整节点 ID pinning，没有跳过 TLS 校验。线上覆盖名称 trim/读取、旧心跳保留、非法名称拒绝、空申请列表、真实申请及分页/详情、公钥一致性、批准/拒绝、信封投递、仅接收人可确认及 ack 幂等、三成员、跨组/撤销权限，以及测试组关闭。三个测试身份仍按正常注册设备记录保留，两个临时测试小组均已关闭。

实际健康响应：

```json
{"api_version":"v1","build_version":"0.0.3","started_at":"2026-10-12T05:45:49.565315522Z","status":"ok"}
```

实际 node 响应就是本文入口章节给出的 JSON。公网 TLS 监听为 `10240`，内核监听 `127.0.0.1:11240`，管理监听为 `127.0.0.1:7788`。部署前备份位于服务器 `releases/before-v0.0.3-20261012T054549Z/`，包含原内核/CLI、配置、状态快照和 nonce sidecar。升级期间 TLS 代理会因其 `Requires=aries-server.service` 被一起停止，所以升级结束必须同时启动并检查 `aries-server.service`、`aries-tls.service`。

验证使用模拟 opaque 信封，只确认服务端中继和 ack；不代表 Windows/Android 已完成真实内容密钥加解密联调。两个客户端仍需按本契约协商能力、上传本机名称并验证真实配对 UI。
