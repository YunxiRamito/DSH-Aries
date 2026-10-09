# Aries server management CLI

The server-management front end is named `ariesctl`. It discovers the server's
canonical command registry through the authenticated admin API, validates
arguments using that metadata, and sends structured `argv` plus typed JSON
flags to the server dispatcher. It never sends an arbitrary shell command and
does not open the server's database.

Build the executable as `ariesctl` (or `ariesctl.exe` on Windows):

```powershell
go build -o temp/builds/ariesctl.exe ./cmd/cli
```

Use `.tools/go/bin/go.exe` when the bundled Go toolchain is needed. The CLI is
written in Go and builds for Windows and Linux without a platform-specific UI
dependency:

```sh
go build -o temp/builds/ariesctl ./cmd/cli
```

To produce a Linux amd64 binary from Windows PowerShell, set `GOOS=linux` and
`GOARCH=amd64` for the build command, then remove those environment variables.
`ariesctl` or `ariesctl ui` starts the interactive menu; add `--language zh` or
`--language en` to select its language explicitly.

## Global connection options

Commands accept `--endpoint <https-url>`, `--token-file <path>`, and
`--timeout <duration>` before or after the command words. The timeout defaults
to 10 seconds. For scripts, set `ARIES_ENDPOINT` and `ARIES_TOKEN_FILE` in the
process environment instead of repeating the flags. Remote requests require
HTTPS; plain HTTP works only for loopback development endpoints. Redirects are
not followed. If `--endpoint` is omitted, the CLI defaults to
`http://127.0.0.1:7788`. If `--token-file` is omitted, it searches the current
directory, the directory containing `ariesctl`, and the user's
`DSH-Aries/secrets/admin.token` location for `secrets/admin.token`; an explicit
`ARIES_ENDPOINT` or `ARIES_TOKEN_FILE` environment variable takes precedence.

## Canonical commands

Use `ariesctl help` for the locally available command index, or
`ariesctl help <command...>` for detailed usage. With a reachable server and
valid credentials, help refreshes metadata and asks the kernel's command-help
API for the selected command. `ariesctl commands` prints the current command
registry as JSON.

The initial server command families are:

```text
status
config show | validate | set --key <field> --value <json-scalar>
groups list | inspect <group-id>
members list <group-id>
members revoke <group-id> <device-id>
members role <group-id> <device-id> --role <admin|member>
invites list <group-id>
invites revoke <group-id> <invite-code>
storage status
server shutdown
```

For example:

```powershell
ariesctl --endpoint https://relay.example:8788 --token-file .\admin.token status
ariesctl --endpoint https://relay.example:8788 --token-file .\admin.token config set --key max_storage_bytes --value 2147483648
ariesctl --endpoint https://relay.example:8788 --token-file .\admin.token members list group-id
```

The older shorthand `config set <key> <value>` is accepted and mapped to the
registry's typed flags. Commands print JSON results to stdout; diagnostics go
to stderr. Exit codes are 0 for success, 1 for operational failure, 2 for
usage or validation errors, 3 for authentication/authorization failure, 4 for
connection/timeout failure, and 5 for server failure.

## Interactive terminal UI

Run `ariesctl` (or `ariesctl ui`) to open the bilingual Windows/Linux terminal interface. On
interactive terminals, use the Up/Down arrow keys and Enter to choose menu
items; the interface does not ask users to type menu numbers. Press `q` or
Ctrl+C to leave the CLI; the service continues running in the background.
First use asks for a language and lets the operator configure a local core
or connect to an online core. The local deployment wizard creates a config,
data/log directories, and an owner-protected admin token file. It never prints
the token. Online core setup requires an admin token file and accepts only the
same endpoint rules as other commands: loopback HTTP for development and HTTPS
for remote management.

The main menu shows connection state, node ID, server code, listeners, storage,
connected-device support state, and uptime. It offers status refresh, local
service start, authenticated service shutdown, core selection, settings,
language switch, and CLI exit. The settings page follows the config contract:
`public_listen`, `admin_listen`, `data_dir`, `admin_token_file`,
`max_storage_bytes`, `allow_insecure_loopback`, `peer_relay_enabled`,
`file_storage_enabled`, `group_quota_bytes`, `quota_bytes_per_member`,
`max_file_bytes`, and `max_file_ttl_seconds`. The UI keeps the admin listener on
loopback because this server build does not provide a direct TLS admin
listener; remote access belongs behind a TLS reverse proxy. The peer relay
flag remains configuration-only until peer relay is implemented. Byte limits
are shown in decimal GB values using fixed-point formatting, without scientific
notation.

Starting a local service launches `aries-server` as a detached background
process and redirects its output to the deployment's `logs/server.log`. The
Windows and Linux launch paths isolate the server from the CLI process group,
so leaving the menu or interrupting `ariesctl` does not stop the server. The
Stop service menu action requests a graceful shutdown through the authenticated
admin API. Online core can manage and stop a connected server, but cannot start
a remote process. UI preferences, including language, selected core, endpoint,
and token file path, are stored under the user's Aries config directory; token
contents are never copied there.

## Local token bootstrap

`token create --out <path>` and `token rotate --out <path>` are local-only
operations. They generate at least 256 bits of cryptographically random
material on the machine running `ariesctl`; neither command calls the server
API or returns a token from an API response. Creation refuses to overwrite an
existing file. Rotation atomically replaces an existing file with a newly
generated token. Both write owner-only files (Unix mode 0600 or a
current-account-only Windows ACL), and neither prints the secret unless
`--show` is explicitly provided.

Local rotation only replaces the selected file. Arrange secure delivery to the
server and restart it as required by the server's token bootstrap setup. The
management API must never return the current or next token.

## Help and shell completion

The CLI stores a bounded, sanitized copy of command metadata at the user config
directory under `Aries/commands.json`. It contains command descriptions,
argument names and types, flags, and permissions only. It omits examples and
redacts sensitive argument/flag descriptions. The cache is written atomically
with owner-only permissions. Local help and completion remain usable while the
server is offline; authenticated command metadata refreshes the cache when
available.

Install completion for PowerShell, Bash, or Zsh:

```text
ariesctl completion install powershell
ariesctl completion install bash
ariesctl completion install zsh
```

The installer writes a small shell script under the user's Aries config
directory and adds one source line to the corresponding profile. It is
idempotent. Shell completion asks the CLI's safe metadata/completion path for
candidates, filters candidate characters, and suppresses suggestions for
sensitive arguments such as invitation codes. It does not complete token
values, private keys, secret paths, or configuration values.

Completion uses the server API when credentials and connectivity are available
and otherwise falls back to cached/built-in command metadata. The JSON helper
is `ariesctl __complete <current-token>...`; shell scripts use the line-based
`ariesctl __complete-values` wrapper.

## Security behavior

Tokens are accepted only from a token file or the `ARIES_TOKEN_FILE`
environment variable; there is no `--token` option. API failures are bounded
and stripped of terminal control characters, and the loaded bearer token is
redacted from server error text. Remote command requests contain structured
arguments and JSON values only. The kernel performs the actual authorization
and command validation for each operation.
