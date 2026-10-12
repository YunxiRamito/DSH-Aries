# 配对确认与通用小组生命周期（0.0.4）

2026-10-12，Asia/Shanghai。此增量契约回应 Windows 能力审计。设备名称接入继续按 [LAUNCHER-PAIRING.md](LAUNCHER-PAIRING.md)；注册、设备证明、邀请、审批、opaque 信封、成员和轮换继续按 [CLIENT-PROTOCOL.md](CLIENT-PROTOCOL.md)。客户端地址为 `https://202.189.21.218:10240`，保持自定义 CA、证书 IP SAN 与节点 pin 校验。

## 能力声明

`GET /api/v1/public/node` 的 `capabilities` 继续是字符串数组，0.0.4 追加：

- `pairing_key_confirmation`：申请详情、申请列表、成员列表返回持久化密钥接收确认元数据。
- `pairing_unpair`：签名、幂等的双成员组取消接口，以及原参与者可查询的终态接口。
- `group_key_confirmation`：成员列表的当前密钥投递确认覆盖 join 与 rotation；轮换后按新 epoch 重新确认。
- `group_lifecycle`：本人退出、创建者原子转让并退出、创建者解散任意人数小组，以及可签名查询的本人成员终态。
- `group_invite_rotation`：只替换明确指定的旧邀请码。

客户端忽略未知能力。能力缺失时不发送取消请求，不用组合 leave/revoke 模拟原子取消，不把已有两名成员或对端在线当成已确认。旧客户端可继续原协议；`approved` 仍表示信封已投递、成员资格已授予，服务端没有改变消息/文件发布的原授权规则。

## 观察接收人密钥确认

在这些原有响应里新增字段，权限保持原样：

```text
GET /api/v1/public/groups/{group}/applications/{application}
GET /api/v1/public/groups/{group}/applications?status=all
GET /api/v1/public/groups/{group}/members
POST /api/v1/public/groups/{group}/applications/{application}/key-delivery
```

注意申请列表默认仅包含 `pending_approval`、`awaiting_key`；投递后已经 `approved` 的申请需用详情、成员列表或 `status=approved`/`all` 读取。

接收人 ack 之前，申请详情示例：

```json
{
  "application_id": "app_...",
  "device_id": "dev_<接收人>",
  "public_key": "<已登记 Ed25519 公钥>",
  "device_name": "OPPO Find X8",
  "status": "approved",
  "approvals": {"dev_<审批人>": true},
  "created_at": "2026-10-12T08:00:00Z",
  "updated_at": "2026-10-12T08:00:30Z",
  "key_delivery_id": "kd_...",
  "key_recipient_id": "dev_<接收人>",
  "key_epoch": 1,
  "key_confirmation_status": "awaiting_ack"
}
```

接收人仍先通过原 `/key-deliveries` 取得信封，在客户端检查签名/指纹、组与代次绑定并解密，之后向原 `/key-deliveries/{delivery}/ack` 提交签名和稳定幂等 key。首次成功会持久记录服务端确认时间：

```json
{
  "delivery_id": "kd_...",
  "status": "acknowledged",
  "acknowledged_at": "2026-10-12T08:01:00Z"
}
```

发起端重新读取同一申请详情，会看到：

```json
{
  "key_delivery_id": "kd_...",
  "key_recipient_id": "dev_<接收人>",
  "key_epoch": 1,
  "key_confirmation_status": "acknowledged",
  "confirmed_at": "2026-10-12T08:01:00Z"
}
```

上段仅展示变化的字段，原详情字段继续返回。成员列表中该接收人的条目也有同样的确认字段；创建者没有 join 信封，因此其自身条目通常为 `unknown`，发起端应检查对端成员/申请的投递确认。元数据不包含信封、私钥或内容密钥。

| `key_confirmation_status` | 含义 |
|---|---|
| `unknown` | 尚无 join 投递，或旧状态没有可靠投递/成员绑定、旧 ack 没有持久确认时间；不能推断已配对。 |
| `awaiting_ack` | 当前 join 投递绑定有效、发送人/接收人仍是对应活跃成员、代次有效，但接收人尚未 ack。 |
| `acknowledged` | 在上述有效授权上下文中，接收人已持久 ack；`confirmed_at` 为服务端记录的首次确认时间。 |
| `revoked` | 此投递已不再适用于当前授权上下文：发送人/接收人离开或撤销、重新加入改变成员绑定、代次变化，或有待处理密钥轮换。此状态不等于全局设备撤销。 |

`confirmed_at` 只在 `acknowledged` 时返回；同 key 重放、不同 key 再 ack、服务重启都不改变首次确认时间。旧快照不猜测或自动补造确认。关闭的组不再返回其申请/成员确认数据；应查询下方终态接口。服务端只能证明已认证接收人提交了 ack，无法证明客户端实际完成了正确解密，这仍是客户端责任。

客户端收到确认后还必须核对当前 group、recipient、delivery、epoch 和公钥身份，才将“等待对端确认”变为完整连接；presence 的 `online` 只用于在线显示。`revoked`/`unknown` 不能继续沿用历史确认。此能力描述 join 信封确认，不能替代通用组密钥轮换接续。

多人小组轮换仍通过原 `/rotations/{event}` 提交，每个其他活跃成员都有自己的新信封。当前成员列表会绑定新投递：先 `awaiting_ack`，各接收人 ack 后分别 `acknowledged`，`key_epoch` 是新代次。历史申请详情继续指向其 join 投递，不把旧确认改写成新确认。轮换作者自己没有收件信封，当前确认字段为 `unknown`；客户端依据自己的轮换提交结果和本地持有密钥处理，不伪造 recipient ack。存在多个轮换事件时，完成全部必要事件之前，旧确认仍不适用，新内容仍按原 `rotation_required` 规则暂停。

## 原子取消双设备组

```http
POST /api/v1/public/groups/{expected_group_id}/unpair
Content-Type: application/json
Idempotency-Key: <稳定操作 key，8–128 字符>
X-Device-ID: <调用者登记设备>
X-Device-Timestamp: <RFC3339 UTC>
X-Device-Nonce: <本次新 nonce>
X-Device-Signature: <原 canonical Ed25519 请求签名>
```

```json
{}
```

必须发送空 JSON 对象 `{}`，不接受空 body、`null`、数组或扩展字段。成功是持久事务完成后的 `200`，只返回三字段：

```json
{"group_id":"grp_...","device_id":"dev_<调用者>","status":"unpaired"}
```

首次取消仅允许目标组活跃成员；创建者、admin、普通成员均可调用，不要求转让 creator。当前必须恰好两个活跃成员；一人或三人以上组返回 `409 pair_not_two_devices`。没有新增 `max_members`，通用小组仍能加入第三成员；即使历史有已离开的成员，只要当前活跃数恰好为二即可取消。

两个活跃成员包括已投递信封但尚未 ack 的成员。因此等待密钥确认期间可取消；其他 pending/awaiting_key 申请也不阻碍取消，它们在关闭时一并失效。只有创建者、仍未投递密钥的单成员组不能用此接口取消，应按原单成员 leave 关闭。存在待轮换事件也允许取消双成员组，关闭仅移除该组的事件，不要求先完成轮换。

同一原子事务会：

1. 关闭目标组，取消双方该组访问；移除其 invites、applications、key deliveries、messages、成员/角色、轮换和控制事件。
2. tombstone 该组文件传输记录，停止新的上传、complete、download、ack 授权；物理 blob 和上传块由原后台 worker 异步清理并重试，`200` 不表示磁盘字节已清零。
3. 保存最小关闭标记（组 ID、两名原活跃成员的设备 ID、关闭时间），并与调用者的幂等响应一并持久提交。

设备登记、公钥、名称、全局心跳和其他组不变。旧组不能用旧邀请码/申请/投递复活；新配对创建新组并使用新内容密钥。已完成并正在发送的下载可能先于取消提交结束；取消后获得授权的新请求会被拒绝。文件锁与状态锁按原次序串行化，旧上传/complete 不能在关闭后重新发布旧组文件。

同调用者、同组、同 key 和完全相同 body，重启后仍返回原三字段，即使调用者已因本次取消失去成员资格。相同 key、不同 body 返回 `409 idempotency_conflict`。操作域绑定完整目标 group：旧组重试不会清新组。两端并发取消时，首次关闭后另一原参与者用自己的 key 也返回 `200 unpaired`，确认的是已关闭旧组；陌生设备不能获取此响应。

普通新取消失败不改变组、文件或 presence；认证 nonce 日志仍按现有规则记录，失败重试必须用新 nonce。提交后响应丢失时，客户端保留旧绑定和准确 key/body，重新签名重试；只有三字段匹配当前绑定后才清除本地配对，保留设备私钥和 node pin。服务端的旧写操作幂等结果仍可能重放历史成功回包，但不会恢复内容或成员权限，客户端必须结合目标组的当前终态，不能据历史成功回包重开配对。

## 另一端离线后读取终态

```http
GET /api/v1/public/groups/{expected_group_id}/pairing-status
X-Device-ID: <本人>
X-Device-Timestamp: <RFC3339 UTC>
X-Device-Nonce: <新 nonce>
X-Device-Signature: <签名>
```

活跃组只有该组活跃成员可读：

```json
{"group_id":"grp_...","device_id":"dev_<调用者>","status":"active"}
```

`active` 仅表示组仍存在、本人是活跃成员，不表示双方密钥已确认，也不限制该组人数。已取消组只有取消时的两名原活跃成员可读：

```json
{
  "group_id": "grp_...",
  "device_id": "dev_<调用者>",
  "status": "unpaired",
  "unpaired_at": "2026-10-12T08:02:00Z"
}
```

客户端只在能力声明、目标 group/device 匹配且返回明确 `unpaired` 时回收旧配对。不能把路径不存在、代理 404、暂时断线、unknown/offline 等当成取消。其他方式关闭/离开/撤销的组继续原语义，本接口没有补造其终态。

关闭标记及取消幂等结果跨重启持久保留，不自动过期，不设置 TTL 来冒充重新授权。仅供对应旧组原参与者查询。当前单节点 JSON 原型没有终态归档/垃圾回收、数据库或固定数量上限，历史规模会增加快照大小，应按小型单节点部署容量规划；不能运行多个进程共享状态目录。

## 错误码

统一 JSON 错误形状继续是 `{"error":{"code":"...","message":"...","request_id":"..."}}`。

| HTTP / code | 条件 |
|---|---|
| `400 invalid_request` | 新取消操作的 body 不是 `{}`。 |
| `400 idempotency_key_required` | 取消幂等 key 缺失或长度不合法。 |
| `401 device_proof_required` / `device_proof_expired` / `invalid_device_proof` / `unknown_device` | 设备请求证明缺失、过期、无效或设备未登记。 |
| `403 membership_required` | 活跃组非成员/被撤销成员，或终态查询/确认不是取消时的两名原参与者。 |
| `404 group_not_found` | 目标既没有活跃组也没有取消终态；不是取消证明。 |
| `409 pair_not_two_devices` | 首次取消时活跃成员数不是二。 |
| `409 idempotency_conflict` | 相同取消作用域/key 使用不同原始 body。 |
| `409 replayed_device_proof` | nonce 重用；重试重新签名。 |
| `500 storage_unavailable` | 取消事务或幂等提交失败；首次事务不发布任何关闭状态。 |

ack 原权限和错误码不变，仅接收人可确认，不允许发送人代确认。`pairing-status` 存储读取失败沿用通用 `500 internal_error`。

## 多人小组：退出本人与解散整组分开

通用小组继续支持任意人数。`unpair` 是恰好双成员时的一次性关闭操作；多人客户端使用下列生命周期接口，避免普通成员的“取消连接”把所有人清除。原 `/leave`、`/creator`、成员撤销与轮换接口的权限和事件语义保持，新增接口把需要一起提交的操作做成原子事务。

### 本人退出与创建者转让并退出

```http
POST /api/v1/public/groups/{expected_group_id}/disconnect
```

所有请求使用原设备签名和稳定 `Idempotency-Key`。普通成员/admin 退出发送 `{}`；有其他活跃成员的 creator 退出须明确选择接任者：

```json
{"transfer_creator_to":"dev_<活跃接任成员>"}
```

转让 creator 及本人失去该组成员权限在同一快照事务中提交，避免两个 HTTP 之间失败。不会按在线状态或随机规则偷偷选择接任者；普通成员不能传转让字段。最后一个成员退出会关闭组，不需要接任者。

首次退出且组内仍有其他成员时成功为 `202`，返回 `group_id`、本人 `device_id`、`status:"left"`、当前 `creator_id`、`control_event_id`、`required_generation`。`202` 表示退出已持久提交，但剩余成员仍须完成轮换。最后成员关闭为 `200`、`status:"group_closed"`。本人用同 key/body 重试得到原响应；用新 key 确认已经退出时返回简化的 `200 left` 或 `200 group_closed` 终态，不补造新事件。

其他成员继续属于该组。退出在同事务移除该设备的文件目标/审批槽，并保留一个真实 `member_left` 控制事件，不能为省略客户端实现而删除他人需要的轮换事件。剩余成员继续原 events→rotation→key-delivery→ack 链路；新代次投递可通过成员列表观察确认。此接口不做全局设备 revoke，不清本人其他组。

### 创建者解散任意人数的小组

```http
POST /api/v1/public/groups/{expected_group_id}/close
```

请求 `{}`，设备签名和稳定 `Idempotency-Key`。仅当前 creator 可发起，普通成员和 admin 无权解散整组。一人、两人、多人均可关闭，不要求先转让或完成轮换。

```json
{"group_id":"grp_...","device_id":"dev_<创建者>","status":"group_closed"}
```

`200` 表示关闭及幂等结果已原子持久化。该组 invites、applications、messages、key deliveries、控制事件与成员权限失效，文件 tombstone 后异步清理。全局身份、名称、presence 与其他组保留。组关闭时只给当时活跃成员记录 `group_closed` 终态，历史已离开/被撤销者保留自身原终态。原创建者重试可以确认已关闭；其他原成员只能查询，不因终态获得整组关闭权限。

### 本人当前成员状态及退出终态

```http
GET /api/v1/public/groups/{expected_group_id}/membership-status
```

签名认证，不需要幂等 key。本人仍活跃时：

```json
{"group_id":"grp_...","device_id":"dev_<本人>","status":"active","role":"member","generation":2}
```

离开、撤销或整组关闭后，对应本人可读终态：

```json
{"group_id":"grp_...","device_id":"dev_<本人>","status":"left","changed_at":"<RFC3339 UTC>"}
```

`status` 可以是 `left`、`revoked`、`group_closed`；本人须严格匹配 group/device。重新加入同一仍存在的小组后，当前活跃资格优先于历史退出记录，旧记录不能撤销新成员权限。非本人/没有该组资格或退出记录的设备不允许读取他人的状态。原 leave/revoke 也记录对应终态；它们继续原权限和轮换规则。

新客户端可周期检查本人状态，或在原 members/events/presence 请求返回组权限错误后查询明确终态。不能把任意 404 或临时 offline 当成退出。退出/关闭结果丢失时保留原操作 key、body 和目标组，签名重试；旧组重试不能影响新的小组绑定。

同一设备重新加入同一个仍存在的组时，旧 disconnect key 重放仍返回历史 `left`，不会退出新的成员资格。客户端应把待确认操作绑定本地会话版本，处理历史响应前核对当前会话，并用 `membership-status` 复核；不能让旧操作成功回包清除后来重新加入的关系。

### 邀请码的明确替换

普通 `POST /groups/{group}/invites` 仍新建邀请，其他旧码继续自然过期。客户端若要求“刷新后旧码立即作废”，使用：

```http
POST /api/v1/public/groups/{group}/invites/rotate
```

```json
{"replace_code":"224Y-123456"}
```

需要设备签名、稳定幂等 key，且 caller 是本组活跃成员。仅原邀请创建者本人或该组 creator/admin 可替换指定码。原子撤销该码并生成三分钟新邀请，保留其他邀请和已提交的申请，不重新启动既有审批。已自然过期但尚未撤销的本组码也可替换。

```json
{"group_id":"grp_...","invite_code":"224Y-654321","expires_at":"<RFC3339 UTC>","replaced_invite_code":"224Y-123456"}
```

成功为 `201`。旧码查询/申请不再可用；同 key/body 重放同一新码，相同 key 不同 body 为 `409 idempotency_conflict`，新 key 重复替换已撤销码为 `409 invite_revoked`。指定其他组的码返回 `404 invite_not_found`；权限不足返回 `403 invite_rotation_forbidden`；缺失/未知字段或空码返回 `400 invalid_request`。事务失败原码仍有效，不修改其他邀请码。

上述成员退出、整组关闭及邀请替换的状态变更和幂等结果都跨重启持久保存。历史记录沿用小型单节点快照的容量限制，不自动清理到失去离线端确认机会。

多人退出补充错误：creator 有其他成员但缺少接任者返回 `409 creator_transfer_required`；接任者是本人、不活跃或不属于该组返回 `400 invalid_successor`；非 creator 提供转让字段、末成员提供接任者或非法 body 返回 `400 invalid_request`。非 creator 解散整组返回 `403 creator_required`，被撤销成员不能用 disconnect 伪造自行离开的成功结果。本人历史 `revoked` 终态仍可通过 membership-status 安全读取。

## 升级和验证边界

旧 0.0.3 快照可升级，历史确认无可靠绑定时返回 `unknown`。新快照增加成员/投递关联、确认时间及终态字段，旧二进制严格解码不能直接降级读取；回滚需兼容迁移或匹配备份，不能覆盖备份后真实业务写入。

`go test ./... -count=1` 和 `go vet ./...` 均通过。新增 13 个生命周期顶层测试与 2 个邀请码替换测试，覆盖 sender 可观察 ack、重复确认首次时间、旧绑定 unknown、持久化失败原子性、重启与 nonce/幂等恢复、双角色取消、多人转让退出与真实 rotation/ack、creator 解散一人/多人、不同退出原因收据，以及 16 次关闭与上传/complete 并发竞争。失败的物理清理在解除阻塞后可重试；其他组的文件、事件、身份、名称和 presence 均保留。

2026-10-12 16:09（Asia/Shanghai），服务器升级到 0.0.4。Windows 本地 Go 客户端通过公网 HTTPS 完成 84 项实际响应检查，严格校验指定 CA 根指纹、证书链、IP SAN 和完整节点 ID。测试覆盖发送端等待/确认状态、ack 稳定时间和重放、双设备取消与离线端终态、三成员组、原子转让并退出、旧确认失效、当前代次 rotation/ack 和恢复消息发布、仅替换指定邀请码、creator 关闭三成员组、uploading/available 文件关闭后不可读取/完成，以及历史 left 收据不被后来关闭覆盖。三个临时测试小组均已关闭；三个测试设备身份、终态与文件 tombstone 按正常持久规则保留，后台继续物理清理。

实际健康响应：

```json
{"api_version":"v1","build_version":"0.0.4","started_at":"2026-10-12T08:09:45.132321944Z","status":"ok"}
```

实际节点响应：

```json
{
  "api_version": "v1",
  "node_id": "node_b33cb5aeb7f7b28f2aad04918966c7b1",
  "server_code": "224Y",
  "capabilities": [
    "group_applications", "device_public_key", "device_name",
    "device_presence", "group_file_cache_cleanup", "pairing_key_confirmation",
    "pairing_unpair", "group_key_confirmation", "group_lifecycle", "group_invite_rotation"
  ]
}
```

内核和 TLS 代理均 active；public TLS 监听 `10240`，内核明文 `127.0.0.1:11240`，admin `127.0.0.1:7788`。升级前二进制、配置、快照与 nonce sidecar 备份位于服务器 `releases/before-v0.0.4-20261012T080944Z/`。Linux amd64 服务端 SHA-256 为 `edd6e805fd04b2685625102ffc47b07c6e344f0d69cfe2636d3cca66d7436167`。

线上信封和消息是模拟 opaque 载荷，测试证明服务端授权、中继、确认和事务行为。Windows/Android 的真实 UI 状态切换、真实内容密钥解密、插件同步、通用 rotation 接续分别由客户端/插件负责人完成，不由服务端测试替代。
