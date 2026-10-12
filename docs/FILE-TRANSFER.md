# Resumable encrypted file transfer API

Aries stores these bytes as opaque ciphertext. It validates request sizes and a declared SHA-256 digest but does not decrypt, inspect file names, or interpret encrypted metadata.

## Integration state

The transfer routes are registered by `(*Server).PublicHandler()` through `s.registerFileRoutes(mux)`. `(*Server).FileHandler()` also exposes the same transfer API as a standalone handler. The old `/groups/{group}/files` endpoints return `410 file_transfer_required`; inline JSON ciphertext is no longer stored.

The server process starts one expiry worker and cancels it during shutdown. Cleanup also runs when creating, downloading, acknowledging, or deleting transfers. A leave or revoke removes that member from outstanding target lists in the same state transaction that deactivates the membership. An uploading transfer is tombstoned when its sender leaves or is revoked; an already available transfer remains available to its recipients. Closing a group tombstones chunked transfers in the same transaction; the cleanup worker then removes their blobs while preserving tombstone metadata for retry/no-copy reporting.

Build 0.0.4 adds explicit creator-only group close and double-member unpair, plus atomic creator-transfer-and-disconnect. Closure holds the existing file lock before the store lock, so upload/finalize/download cannot authorize a new operation across a committed close or resurrect a closed group. The success response confirms logical closure and tombstones, not immediate physical deletion. The janitor keeps retrying cleanup even when file storage is disabled. Other groups' files and control events are untouched. See [PAIRING-LIFECYCLE.md](PAIRING-LIFECYCLE.md).

## API

All paths below are under `/api/v1/public`; every request needs the normal Ed25519 device-proof headers. Mutating requests also need an `Idempotency-Key`, and that key is part of the signed request.

1. Create an upload with `POST /groups/{group}/file-transfers`:

   ```json
   {
     "epoch": 4,
     "encrypted_metadata": "<base64url ciphertext>",
     "size_bytes": 9000000,
     "chunk_size_bytes": 1048576,
     "sha256": "<64 lowercase hex characters>",
     "ttl_seconds": 604800,
     "targets": ["dev_recipient_1", "dev_recipient_2"]
   }
   ```

   `chunk_size_bytes` defaults to 1 MiB and may be at most 4 MiB. If `targets` is omitted, all currently active members except the sender are selected. The server rejects an empty target set. The response contains a `file_id`, the expected chunk count, expiry, recipients, and any `evicted_files` whose bytes were removed to meet quota.

2. Upload each chunk with `PUT /groups/{group}/file-transfers/{file}/chunks/{index}`. The request body is raw ciphertext bytes, not JSON. Indexes start at zero. A chunk must exactly match its declared size; repeating the same chunk is safe. The sender can inspect the file record's `received_chunks` map in `GET /groups/{group}/file-transfers` to resume missing indexes.

3. Finalize with `POST /groups/{group}/file-transfers/{file}/complete` and an empty body or `{}`. The server checks each stored chunk and the assembled file SHA-256 before marking it available.

4. Any currently active group member may download a cached chunk with `GET /groups/{group}/file-transfers/{file}/chunks/{index}`; this lets a newly added member fetch ciphertext while it remains cached. The response body is raw ciphertext. The server records download time for eviction ranking; targets control which acknowledgements are required before cleanup.

5. A target confirms receipt with `POST /groups/{group}/file-transfers/{file}/ack` and an empty body or `{}`. When every remaining target has acknowledged, Aries writes a durable tombstone and returns `cleanup_pending: true`; the response confirms the metadata commit and does not claim that the blob has already been physically removed. Blob and upload-chunk deletion is retried by the cleanup worker or a later transfer request. Non-final acknowledgements return `cleanup_pending: false`. A departed member is removed from the target set when the integration hook above runs; if this leaves no targets, the blob is tombstoned.

6. The sender, group admin, or creator may remove a transfer with `DELETE /groups/{group}/file-transfers/{file}`. `GET /groups/{group}/file-transfers` lists transfer metadata, resumable indexes, acknowledgements, state, and tombstone reason. Pagination uses `offset` and `limit`.

7. A current active group member can inspect only that group's cache with `GET /groups/{group}/file-transfers/cache`. The response separates `uploading`, `available`, `cleanup_pending`, and `logical_deleted` buckets; each bucket has `count` and logical `bytes`, and `physical_bytes` reports the on-disk bytes belonging to that group's transfer cache.

8. A sender, creator, or admin can request bounded cleanup with `POST /groups/{group}/file-transfers/cache/cleanup` and `{"file_ids":["ft_..."]}`. A batch contains at most 100 IDs and requires the normal device proof plus `Idempotency-Key`. Ordinary members may select only files they sent; creator/admin permissions follow the single-file delete rule. All IDs must belong to the requested group or the batch fails. The server commits tombstones first, removes only the selected blob/upload paths, and returns `logical_deleted`, `already_deleted`, `cleanup_pending`, and `physical_cleanup_complete`. The operation never deletes group membership, device identities, key deliveries, control events, or files in another group.

Expired, explicitly removed, fully acknowledged, and quota-evicted transfers keep a metadata tombstone. A later fetch returns `410 file_unavailable` with a message that the source has no cached copy and a member must upload a fresh copy. Tombstones distinguish this from a missing ID.

## Quota and durability behavior

`max_storage_bytes` limits total file bytes. `group_quota_bytes` limits each group; a positive `quota_bytes_per_member` overrides it with member-count times the per-member amount. `max_file_bytes` caps one transfer. `max_file_ttl_seconds` caps requested retention. Set `file_storage_enabled` to false to block all public file-transfer operations, including listing, upload, download, acknowledgement, and deletion. Existing blobs are not removed just by toggling the feature off; normal TTL cleanup continues, and an unexpired blob becomes accessible again if storage is re-enabled. The quota allocator evicts available blobs with fewer downloads first, then the longest time since the last download (or creation); it never silently evicts durable control events.

Blob bytes are written under `data_dir/file-blobs` with restricted file permissions, outside `state.json`. Chunk files are synced before their receipt is committed. Finalization validates and atomically renames the assembled blob, then removes upload-chunk copies after the available metadata commit. Downloads read and verify the full requested chunk (up to 4 MiB) before writing response bytes; a missing, truncated, or corrupt blob is durably tombstoned and returns `410 file_unavailable`. Cleanup removes controlled temporary files left by interrupted writes. The JSON snapshot stores only the encrypted metadata, digest, chunk receipts, recipient acknowledgements, and state. This first implementation remains single-process and single-node; do not share one data directory among server processes.

The previous `POST /groups/{group}/files` JSON endpoint is disabled with `410 file_transfer_required`. Clients must migrate to `/file-transfers`; this prevents any new file payload from entering the state snapshot or bypassing transfer quotas.

## Implemented limits

- Chunks are bounded at 4 MiB and a transfer may contain at most 65,536 chunks.
- Per-group quota is evaluated when a transfer is reserved. The allocator has a global total-download counter, not per-recipient download analytics.
- TTL cleanup runs immediately when the cleanup worker starts, every minute thereafter, and opportunistically during transfer operations.
- Federation/replication of blob data, cryptographic client SDKs, and a database-backed high-concurrency quota allocator are outside this slice.
