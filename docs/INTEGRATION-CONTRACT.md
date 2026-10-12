# Aries Kernel and CLI Integration Contract

This is the shared contract for Aries server-kernel and CLI work. Update it whenever an implementation requires a compatibility change.

## Scope and invariants

- Aries is a cross-platform Go service. The CLI and later GUI are server-management front ends and must use the same management API and canonical command registry.
- Keep local caches, build outputs, and temporary files under the project-root `temp/` directory. Windows developers can source `scripts/use-project-temp.ps1`; POSIX developers can source `scripts/use-project-temp.sh`.
- This stage does not implement an Android/PC client or the DSH plugin. We will build the DSH plugin after the kernel, public protocol, and CLI have passed integration checks.
- Public API versions are explicit (`/api/v1/...`). Breaking wire changes require a new API version.
- A device has a client-held signing private key and a server-registered public identity. Group membership authorization is separate, per device, and revocable. Revoking one device must not revoke other devices or the device's membership in other groups.
- The group model remains general-purpose and supports any number of active members. A two-member group is a launcher presentation choice, not a server-enforced limit; do not add or infer max_members.
- The server stores and relays opaque end-to-end encrypted message, file, and key-delivery payloads. It never stores a plaintext content key.
- The authoritative group node commits membership changes. A connected relay must durably queue a leave request if the authority is unavailable. Once leave is confirmed, the authority durably queues a key-rotation control event until a remaining member handles it. Control events are not subject to file TTL, quota, or eviction.
- On reconnect, an active member receives pending control events before ordinary new-content synchronization. The client handles rotation and submits encrypted key-delivery envelopes before publishing new-generation content.
- Persist authoritative state and pending events across restart. Reprocessing a request or event must be idempotent.

## Transport and encoding

- Use JSON over HTTP for request/response operations and a bounded long-poll event stream for ordered server events in the first vertical slice. The public protocol document must explain reconnect cursors, ordering, backpressure, and the path to WebSocket if load tests show a need; do not claim WebSocket support until implemented.
- All remote production connections require TLS. Plain HTTP may be used only for loopback development unless an explicit secure reverse-proxy mode is configured.
- JSON uses UTF-8 and `application/json`. Timestamps are RFC 3339 UTC. Opaque ciphertext is base64url without padding; the kernel must not parse it.
- Every error response uses `{"error":{"code":"...","message":"...","request_id":"..."}}`; never include secrets in errors or logs.
- Requests that create/transition durable state accept an `Idempotency-Key`; replaying the same key and body returns the original result.

## Management API used by CLI and GUI

Base path: `/api/v1/admin`. Every route below requires `Authorization: Bearer <admin-token>`, except `GET /healthz`, which is read-only and unauthenticated. Local and remote management use the same API and permission checks.

| Method and path | Purpose |
| --- | --- |
| `GET /healthz` | Liveness/readiness, API version and build version |
| `GET /api/v1/admin/status` | Node identity, uptime, listener state and aggregate connection/store health |
| `GET /api/v1/admin/config` | Read effective non-secret configuration; redact tokens and private keys |
| `PUT /api/v1/admin/config` | Validate and atomically persist configuration; return field-specific validation errors |
| `GET /api/v1/admin/groups` | List local authoritative group summaries and membership counts, without secrets |
| `GET /api/v1/admin/storage` | Storage use, quotas, pending uploads and eviction counters |
| `POST /api/v1/admin/shutdown` | Graceful shutdown; must flush durable state before success |
| `GET /api/v1/admin/commands` | List registered admin commands and argument/flag metadata |
| `GET /api/v1/admin/commands/help?path=<...>` | Return canonical help for a command path |
| `POST /api/v1/admin/commands/complete` | Return safe next-token completion candidates for a command line |
| `POST /api/v1/admin/commands/execute` | Execute a validated command as the authenticated admin |

Responses are JSON objects. Collection responses use `{"items":[...]}`. Status includes `api_version`, `node_id`, `server_code`, `uptime_seconds`, `started_at`, `public_listener`, `admin_listener`, `connected_devices`, `connected_devices_state`, `pending_control_events`, `storage_state`, and `peer_relay_state`. Until connection sessions are tracked, `connected_devices` is `null` and its state is `not_supported`. Storage state reports `available`, `degraded`, or `unavailable` based on live store/blob-path checks. `peer_relay_state` is `disabled` when the feature flag is off and `not_implemented` when it is enabled in this single-node build. Config PUT accepts the complete writable config document and rejects unknown fields; its response returns the sanitized effective config.

The public API also exposes unauthenticated `GET /api/v1/public/node`, which returns `api_version`, persistent full `node_id`, and the four-character display `server_code`. The display code can collide; protocol identity and server selection use the full node ID. The current invitation code uses the display code as its prefix.

Build 0.0.3 adds `capabilities` as a string array: `group_applications`, `device_public_key`, `device_name`, `device_presence`, `group_file_cache_cleanup`. Unknown values must be ignored. Capabilities declare implementation, not permission or enabled file-storage configuration. Clients discover `device_name` before adding it to heartbeat requests; earlier servers have strict unknown-field decoding. Existing application-list functionality may exist without capabilities on older servers.

Build 0.0.4 appends `pairing_key_confirmation`, `pairing_unpair`, `group_key_confirmation`, `group_lifecycle`, `group_invite_rotation`; keep the array type. [PAIRING-LIFECYCLE.md](PAIRING-LIFECYCLE.md) specifies the wire contract. Recipient ack persists a first timestamp; application/member responses expose only bound confirmation metadata, never envelopes. Membership incarnation, current generation and pending rotations invalidate stale receipts. Current-member bindings follow rotation deliveries; original applications retain their join binding. Unbound legacy records remain unknown, and a key author without an inbound delivery has no synthetic recipient acknowledgement.

General groups remain unrestricted in member count. Signed idempotent disconnect removes only the caller; a departing creator supplies an explicit active successor, atomically transfers the role and leaves while preserving the remaining group's rotation event. Creator-only close dissolves any-sized group. Pair-specific unpair allows either participant to dissolve an exactly two-active-member group. All closures atomically revoke only the target group, preserve identities/presence/other groups, and tombstone files under the existing file-lock to store-lock ordering; physical cleanup is asynchronous. Scoped durable membership receipts distinguish left/revoked/group_closed from route errors and survive restart. Original leave/revoke semantics stay intact, now with same-transaction departure receipts. Idempotent historic results cannot remove a later membership; clients tie pending operations to their local session revision.

Explicit invite rotation replaces only one selected code, under inviter or creator/admin permission, and preserves unrelated codes and submitted applications. Ordinary invitation creation retains its original multiple-code semantics. Closing and membership receipts have no automatic expiry in this JSON prototype; historical growth remains a documented single-node capacity limit. Back up state before upgrade; older strict decoders cannot read the added receipt and binding fields without migration.

The public pairing surface includes the group application list endpoint. It is restricted to active members and supports a bounded status filter, opaque cursor, and limit (default 100, maximum 200). It defaults to pending_approval and awaiting_key, sorts by created_at then application_id, and returns the registered applicant public key. Existing application detail and member list responses carry the same identity-bound public key.

Presence uses a signed device heartbeat endpoint and an active-member-only group presence endpoint. The server timestamps receipt and computes expiry; clients cannot assert online. Presence is memory-only, capped at 100,000 records, pruned after the configured timeout, and cleared on restart. Defaults are a 30-second heartbeat interval and 90-second timeout; heartbeat_interval_seconds and heartbeat_timeout_seconds are configuration fields, with zero meaning default.

Signed heartbeats optionally carry `device_name`. Reject raw Unicode control characters, trim surrounding Unicode whitespace, and accept 1–128 Unicode code points; reject empty/invalid names with `400 invalid_device_name`, wrong JSON types with `400 invalid_request`. Omitted or `null` names preserve the prior value. Only an authenticated device can update its own name, which is display metadata and must never replace the device ID, registered public key, fingerprint check or pairing approval. Application list/detail and active-member list responses return optional nonempty names from the identity table, and heartbeat echoes the current name. Enrollment proofs, group size and approval/key-rotation rules are unchanged.

Names are durable; presence is not. A changed name uses atomic snapshot commit, unchanged names avoid snapshot writes. If a changed-name commit fails, return `500 storage_unavailable` without publishing the name or heartbeat online update. Nonce authentication remains durable. Heartbeats are the exception to durable mutation response caching: no `Idempotency-Key` is required or cached, and retries use a fresh signed nonce. Rollback to 0.0.2 after a name has been stored requires a compatible state migration or coordinated restoration of the pre-upgrade snapshot because the old store rejects unknown device fields; never pair an old binary with a new named-device snapshot.

Group file-cache support provides group-scoped statistics and idempotent batch cleanup. Statistics distinguish uploading, available, cleanup-pending, and logical-deleted records and report physical bytes. Cleanup accepts at most 100 file IDs, commits tombstones before physical removal, enforces existing sender/creator/admin permissions, and cannot remove membership, device identities, key deliveries, control events, or another group's files.

The initial writable config uses these stable JSON fields:

```json
{
  "public_listen": ":8080",
  "admin_listen": "127.0.0.1:8081",
  "data_dir": "./data",
  "admin_token_file": "./secrets/admin.token",
  "max_storage_bytes": 1073741824,
  "allow_insecure_loopback": true,
  "peer_relay_enabled": false,
  "file_storage_enabled": true,
  "group_quota_bytes": 1073741824,
  "quota_bytes_per_member": 0,
  "max_file_bytes": 268435456,
  "max_file_ttl_seconds": 2592000,
  "heartbeat_interval_seconds": 30,
  "heartbeat_timeout_seconds": 90
}
```

`peer_relay_enabled` is currently configuration-only. Setting it does not connect to peers or relay traffic; status reports `peer_relay_state: not_implemented` when enabled.

`allow_insecure_loopback` only permits plaintext HTTP on loopback during development. Remote production admin access requires TLS. `file_storage_enabled` is the global feature gate for all public transfer operations; disabling it blocks access but does not itself erase cached blobs, which remain subject to normal TTL cleanup. `group_quota_bytes` is the fixed per-group limit, and a positive `quota_bytes_per_member` overrides it as a member-based quota. `max_file_bytes` and `max_file_ttl_seconds` cap an individual upload. A zero value disables that numeric cap. `heartbeat_interval_seconds` and `heartbeat_timeout_seconds` control signed device heartbeats and group presence; timeout must be at least interval when both are non-zero, and values are bounded by the server. Additional TLS certificate/key configuration may be added as documented optional fields. Keep these names consistent in kernel, config output, and CLI `config set`.

## Canonical instruction system

- The kernel owns one registry of typed server-management commands. Each entry defines its path, summary, usage, arguments, flags, validation, required permission, handler, examples, and safe completion providers.
- CLI and later GUI are front ends to that registry. They discover help and completion metadata from the same command definitions and execute through the authenticated management API. They must not reimplement server-side business rules.
- `POST /commands/execute` accepts structured argv and typed flags, never an arbitrary shell string. It returns a stable JSON command result (`status`, `summary`, `data`, `warnings`, `request_id`). The command dispatcher invokes the same application/service functions used by any direct management REST routes. Commands marked `local_only` are metadata for front ends and must be rejected by remote execution.
- `GET /commands` and `/help` expose human-readable help plus machine-readable metadata. Completion accepts tokenized words and cursor position, and returns candidates with display/description fields; it must not reveal token values, private keys, secret paths, invite secrets, or unredacted configuration values.
- The CLI supplies shell-specific Tab completion scripts (PowerShell, Bash, and Zsh where supported). Completion uses cached registry metadata when offline and may refresh it from the authenticated command API. `help` works locally from the same metadata and remotely from the kernel.
- Unknown commands, invalid argument types, missing required flags, permission failures, and handler failures use stable machine-readable errors and actionable human messages. Include request IDs and preserve exit-code classes in the CLI.
- Initial command families: `status`, `config show|set|validate`, local-only `token create|rotate`, `groups list|inspect`, `members list|revoke|role`, `invites list|revoke`, `storage status`, `server shutdown`, and `help`.
- Do not add an unrestricted OS shell command. The instruction system manages the service only and applies typed authorization before every handler.

## Admin token bootstrap

- The admin token is an operator secret, separate from group/device/content keys. The service reads it from a configured token file or secret source; it never returns the token from an API.
- The CLI generates at least 256 bits of cryptographically secure random token material and writes it atomically with owner-only permissions/ACL where supported. Never print the secret unless the operator explicitly requests one-time display.
- `token create` and `token rotate` are local-only file operations. Replacing the token file does not remotely rotate a running service's in-memory verifier; restart the local service to load a replacement. The command API must never mint or return token material.
- The server stores only a verifier when feasible. Token rotation must not expose the previous or next secret through logs, status, or config responses.

## CLI contract

The CLI has two modes: local server lifecycle (`serve`, foreground; installation/service-manager integration can be added later) and remote/local API administration. The CLI must not open or edit the server's database directly.

Minimum commands for this milestone:

- `aries-server serve --config <path>`
- `ariesctl status --endpoint <url> --token-file <path>`
- `ariesctl config show --endpoint <url> --token-file <path>`
- `ariesctl config set --endpoint <url> --token-file <path> <key> <value>` (read current document, modify one supported leaf, PUT the full document)
- `ariesctl token create --out <path>` (local-only bootstrap)
- `ariesctl groups list --endpoint <url> --token-file <path>`
- `ariesctl storage status --endpoint <url> --token-file <path>`
- `ariesctl help [command...]`
- `ariesctl completion install <powershell|bash|zsh>`

Support Windows and Linux, non-interactive scripts, useful exit codes, timeouts, and clear errors. Never put an admin token in command-line arguments or shell history.

## Ownership for parallel implementation

- Kernel implementation owns the public/admin HTTP server, persistence, configuration schema, command registry/dispatcher, documented JSON response types, and a runnable `aries-server` command.
- CLI implementation owns `ariesctl`, its API client, shell completion installers, command UX, and CLI tests. It must discover/execute registered server commands through the command API and may not modify kernel-owned files.
- Both implementations may add tests/docs under their owned paths. If the contract needs a change, report the proposed change before changing shared behavior.
