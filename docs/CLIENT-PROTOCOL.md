# Aries client protocol, version 1

This is the first runnable public protocol slice for third-party Android and PC clients. The server relays opaque application payloads. Clients own device private keys and group content keys; the server never receives a plaintext content key or tries to interpret ciphertext. All paths are rooted at `/api/v1/public` and use JSON UTF-8.

## Current implementation boundary

Implemented: public node identity discovery, device identity enrollment with Ed25519 proofs, group creation, short-lived invite lookup, join applications and approvals, active-member application listing with registered public keys, opaque key-delivery envelopes, group membership roles/revocation, durable leave/revoke rotation events, ordered bounded long-poll events, signed device heartbeats and in-memory group presence, opaque message relay, and a resumable encrypted file-transfer API with filesystem blobs, quotas, TTL, receipts, tombstones, group-scoped cache statistics, and bounded cache cleanup. State metadata persists in an atomic JSON snapshot for a small single-node prototype; presence is intentionally process memory only.

Not implemented in this vertical slice: WebSocket transport, multi-node federation, source-authority forwarding/partition resolution, snapshot backup, invite QR generation, multi-approval timeout policy, and full audit log. The legacy JSON file endpoints return `410 file_transfer_required`; use the resumable chunked endpoint below. Do not treat the snapshot store as a database or run multiple server processes over one data directory.

All non-loopback connections must use TLS. In development, plaintext loopback is enabled only by `allow_insecure_loopback`. The server currently exposes separate public and admin listeners; TLS certificates are not configured directly by this slice, so remote production deployments need a TLS reverse proxy and should bind the server to loopback/private interfaces.

## Device identity and request proof

Use Ed25519. Encode public keys, signatures, nonces and ciphertext as unpadded base64url. Create a keypair locally; never send the private key to the server.

1. `POST /devices/challenge` with `{"public_key":"<base64url-ed25519-public-key>"}` returns a random `challenge_id`, a 32-byte `nonce`, and an expiry.
2. Sign the UTF-8 string `enroll\n<challenge_id>\n<nonce>\n<public_key>` with the device private key.
3. `POST /devices/enroll` with `{"challenge_id":"...","signature":"..."}` and an `Idempotency-Key` registers the identity. The server derives the stable device ID from the public key.

Subsequent authenticated requests include:

```text
X-Device-ID: dev_<server-issued-id>
X-Device-Timestamp: <RFC3339 UTC>
X-Device-Nonce: <fresh random base64url string>
X-Device-Signature: <signature below, unpadded base64url>
Idempotency-Key: <required for durable mutations>
```

Sign the UTF-8 canonical request string:

```text
<HTTP method>\n<request URI including query>\n<timestamp>\n<nonce>\n<Idempotency-Key>\n<base64url(SHA-256(exact request body bytes))>
```

The timestamp is accepted only within five minutes. Nonces are one-use and their replay records persist across restarts. Challenges are two minutes, limited to eight per remote IP per minute and 4,096 outstanding entries. The first slice has no anonymous bulk enrollment API.

The server persists a hash of each `(device_id, nonce)` pair with its expiration time in an append-only `state.json.nonces` sidecar; it does not persist the raw nonce. Expired records are pruned during authentication, and the in-memory live set is capped at 100,000 entries. The log is compacted after it grows substantially beyond the live set. This prototype still uses a single local file and is intended for one process per data directory, not high-volume clustered deployment.

## Node identity and display code

`GET /api/v1/public/node` is an unauthenticated discovery endpoint returning `api_version`, the persistent full `node_id`, and a four-character uppercase alphanumeric `server_code`. The full node ID is the durable protocol identity. The short code is only a human-facing prefix and can collide across nodes; clients must use the full node identity when identifying or selecting a server. Invitations use `<server_code>-<six digits>` and still expire after three minutes. Multi-node invitation discovery and routing are not implemented in this slice.

Starting in build 0.0.3, discovery also returns a `capabilities` string array: `group_applications`, `device_public_key`, `device_name`, `device_presence`, and `group_file_cache_cleanup`. These describe implemented contracts, not authorization or enabled file-storage policy. Ignore unknown values. Only send the new heartbeat `device_name` field after discovering `device_name`; older builds reject unknown request fields. Absence of capabilities in an older build does not imply absence of the existing application-list endpoint.

## Enrollment, invite, approval and membership

1. A registered device creates a group with `POST /groups` and `{"name":"...","approval_policy":"creator"}`. Policies are `all`, `creator`, `inviter`, `creator_inviter`, or `public`. Response returns `group_id`, current generation (initially 1), and a three-minute `invite_code`.
2. A client can inspect a current invitation with unauthenticated `GET /invites/{code}`. This reveals only group display metadata, never membership credentials.
3. A registered device submits `POST /invites/{code}/applications` with `{}`. The invitation only works while the code is active. This slice creates one application per idempotency key; clients should use a fresh key for each distinct attempt.
4. Required group members approve via `POST /groups/{group}/applications/{application}/approvals` and `{"approve":true}`. An active group admin can act for one pending approval slot at a time. `false` rejects.
5. Once approved (or in public mode), an existing active member submits `POST /groups/{group}/applications/{application}/key-delivery` with `{"envelope":"<opaque encrypted content-key envelope>"}`. This atomically marks the new device as an active group member and queues the envelope for the applicant. The server cannot decrypt the envelope.
6. Applicants check `GET /groups/{group}/applications/{application}`. Members check `GET /groups/{group}/members`.

Active members can poll `GET /groups/{group}/applications?limit=100&cursor=<opaque>&status=pending_approval,awaiting_key` for pending pairing work. The default status filter is `pending_approval` and `awaiting_key`; `status=all` includes terminal states. Results are stably ordered by `created_at` and `application_id`, and `next_cursor` is an opaque base64url continuation value. Both application details and member entries include the registered Ed25519 `public_key`; the server reads it from the device identity table and does not accept a copied key from application state.

Application list/detail and active-member list entries also include optional `device_name`, read from the same registered identity. It is omitted until a name is shared. Names are current display metadata, not immutable application snapshots; a rename does not alter identity, approvals, application ordering or public-key fingerprints. Always compare device IDs and public keys and require the existing user approval; a self-declared name can be duplicated or misleading.

The source node is authority in this single-node slice. Every membership authorization is group-specific; revoking a group member does not delete the device public identity. The creator can appoint/remove group admins via `PUT /groups/{group}/members/{device}/role` with `{"role":"admin"|"member"}`. The creator or an admin can revoke an ordinary member via `DELETE /groups/{group}/members/{device}`. Admins cannot revoke admins or the creator, appoint admins, or transfer creator. Only the creator transfers the role through `POST /groups/{group}/creator` with `{"new_creator_id":"..."}`. The old creator remains an ordinary member after transfer.

## Leave, revocation and key rotation

An active member submits `POST /groups/{group}/leave` with `{}`. The authority revokes that member immediately and durably queues a `member_left` control event for the remaining members. An administrator revocation follows the same queueing path with `member_revoked`. Each event has a monotonically increasing group `sequence` and required `generation`.

Remaining active members poll events using `GET /groups/{group}/events?after=<sequence>&wait_ms=<0..25000>&limit=<1..200>`. Response includes ordered `items` and `next_cursor`. Events are persisted; the client should keep the highest fully handled sequence and resume with it after reconnect. The default item limit is 100 and the server caps it at 200. Clients should use short long-polls and back off when disconnected. A slow client must reconnect by cursor; the server does not hold an unbounded per-device live queue. There is no WebSocket implementation yet; it can be added later if measurements justify it. See [API-REFERENCE.md](API-REFERENCE.md) for every endpoint's current request and response schema.

For each pending control event, any active remaining device can submit `POST /groups/{group}/rotations/{event}` with `{"epoch":<required_generation>,"envelopes":{"<other-active-device-id>":"<encrypted-envelope>",...}}`. It must include an opaque envelope for each other active member and not include its own device ID. Event completion, generation advancement, and delivery queueing commit atomically. Until all outstanding rotations complete, new message/file publication is rejected with `rotation_required`. Once rotation completes, only the exact current generation is accepted. The server stores envelope bytes and never the content key. A restart does not lose queued events.

Recipients retrieve envelopes with `GET /groups/{group}/key-deliveries` and acknowledge a specific delivery with `POST /groups/{group}/key-deliveries/{delivery}/ack` and `{}`. Device identity proof still works for a former member, but group APIs return `membership_required`; rejoining requires a new group membership grant through a new application and approval.

Devices may send `POST /devices/heartbeat` with `{}` or an optional bounded `client_version`. The server timestamps receipt and derives `online`; clients cannot submit an online flag. Active members read `GET /groups/{group}/presence`, which returns every active member sorted by device ID with `device_id`, `online`, `last_seen_at`, and optional `client_version`. The default heartbeat interval is 30 seconds and presence expires after 90 seconds; `heartbeat_interval_seconds` and `heartbeat_timeout_seconds` can override these limits. Presence records are memory-only, capped at 100,000 devices, pruned when expired, and cleared by a process restart. A departed or revoked member cannot read presence and is omitted from the group's result immediately.

With the `device_name` capability, the signed heartbeat may additionally send `{"device_name":"OPPO Find X8","client_version":"android/1.0"}`. Reject Unicode control characters before trimming surrounding Unicode whitespace, then require 1–128 Unicode code points. Invalid names return `400 invalid_device_name`; wrong field types return `400 invalid_request`. Missing or `null` names preserve the stored value; empty strings do not clear it. Only the signing device's own registered name changes. A nonempty stored name is also returned on successful heartbeats, including older `{}` requests.

Device names persist in the identity snapshot across restarts, while presence remains memory-only. Repeated unchanged names and ordinary heartbeats do not rewrite the full JSON snapshot. A changed name commits atomically before the heartbeat refreshes presence; a failed snapshot write returns `500 storage_unavailable` and publishes neither the rename nor this heartbeat's online update. The existing authentication nonce log still records authenticated requests. Heartbeats do not require or cache `Idempotency-Key`; retry with a new nonce and signature, and the name assignment represents the current request. Enrollment proof bytes and group membership/key-delivery semantics remain unchanged. See [LAUNCHER-PAIRING.md](LAUNCHER-PAIRING.md) for client integration examples.

## Messages and files

- `POST /groups/{group}/messages` accepts `{"epoch":N,"ciphertext":"<non-empty unpadded base64url>"}`.
- `GET /groups/{group}/messages` returns the durable relay list for active members.
- The former `POST`, `GET`, and `DELETE /groups/{group}/files` inline endpoints return `410 file_transfer_required`. They no longer accept or return payload bytes.
- New clients should use the resumable API documented in [FILE-TRANSFER.md](FILE-TRANSFER.md): create a transfer with encrypted metadata, declared size, chunk size, SHA-256, TTL and target devices; upload raw ciphertext chunks; finalize after all chunks arrive; download raw chunks; and acknowledge receipt. Payload blobs are outside the JSON snapshot. Completed delivery, TTL expiry, deletion, and quota eviction produce durable tombstones so clients receive an explicit no-copy response and can ask a member to upload again.
- Current-group cache support is exposed as `GET /groups/{group}/file-transfers/cache` and `POST /groups/{group}/file-transfers/cache/cleanup`. Statistics distinguish `uploading`, `available`, `cleanup_pending`, and `logical_deleted`, plus physical bytes. Cleanup accepts at most 100 file IDs, requires an idempotency key, and applies existing sender/creator/admin deletion permissions. It writes tombstones before removing only the selected group's blob and upload directories; it never removes control events, member/device state, key deliveries, or another group's files.

Requests that mutate durable state require `Idempotency-Key` (8-128 characters). Repeating the same key with identical body returns the original status and response. Reusing it with a different body returns `409 idempotency_conflict`. The request signature includes this key. Chunk uploads are raw request bodies with a maximum of 4 MiB per chunk. The transfer endpoints still use the current single-node JSON metadata store and filesystem blobs, so they are not a multi-node or multi-process storage backend.

## Error shape

Errors are JSON:

```json
{"error":{"code":"membership_required","message":"active group membership is required","request_id":"..."}}
```

Do not retry authorization or validation failures. Retry transient `5xx`, and use the same idempotency key/body after an uncertain mutation outcome.
