# Aries administrative command registry, API v1

The server owns one typed command registry. CLI and GUI clients render the registry and call its authenticated API; they must not copy command business logic. Commands are structured tokens and JSON flags. The service never interprets an arbitrary shell string or executes operating-system shell commands.

All routes require `Authorization: Bearer <admin-token>` and are mounted under `/api/v1/admin`.

| Method/path | Behavior |
|---|---|
| `GET /commands` | Returns `{"api_version":"v1","items":[...]}` with command paths, argument/flag types, permission class, usage, examples, and `local_only` marker. |
| `GET /commands/help?path=members%20revoke` | Returns one canonical metadata object and short help text. |
| `POST /commands/complete` | Body `{"words":["groups",""],"cursor_position":2}`. Returns `{ "candidates": [{"value":"list","display":"list","description":"..."}] }`. Cursor counts tokens before the token currently being completed. Candidates are generated from fixed registry/config names and safe group IDs; secret token material and invitation codes are never completion values. |
| `POST /commands/execute` | Body `{"argv":["config","set"],"flags":{"key":"max_storage_bytes","value":1073741824}}`. Returns `status`, `summary`, `data`, `warnings`, and `request_id`. |

`argv` is a JSON string array, never a shell command line. `flags` is a JSON object; values are checked against command definitions. Unknown commands, arguments, flags, and malformed types receive stable API errors. Initial commands include `status`, `config show|set|validate`, `token create|rotate`, `groups list|inspect`, `members list|revoke|role`, `invites list|revoke`, `storage status`, `server shutdown`, and `help`.

`token create` and `token rotate` are listed as `local_only` so frontends can discover their canonical help and completion metadata. The execute endpoint rejects both commands. A CLI or GUI frontend generates token material on the operator's host and writes it to a protected file; the admin API never generates, accepts, or returns token material. Registering a newly generated verifier with a remotely managed server is not implemented in this first slice; token files must currently be provisioned on the server host, and changing `admin_token_file` requires restart.

The permission labels are metadata for future management frontends and delegated authorization. The current server has a single all-powerful admin token, so it does not yet implement separate admin roles. The group-facing API does enforce creator/admin/ordinary-member role rules.
