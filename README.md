# DSH-Aries

DSH-Aries is a Go relay server for end-to-end encrypted device and group data, with a bilingual terminal management CLI (`ariesctl`). The server stores opaque ciphertext and encrypted key envelopes; clients keep device private keys and group content keys.

**Version:** `0.0.2` · **API:** `v1` · **Status:** early single-node release

This release is an integration prototype. It has a durable JSON state store and filesystem-backed file transfer, but no database backend, WebSocket transport, peer relay, or multi-node federation. Review [API implementation limits](docs/API-REFERENCE.md#7-当前实现与验证边界) before exposing a deployment to users.

## Download 0.0.2

Release binaries are published at [GitHub Releases](https://github.com/YunxiRamito/DSH-Aries/releases/tag/v0.0.2). The release contains the server and management CLI for Linux amd64, Linux arm64, and Windows amd64. Verify downloads against `SHA256SUMS.txt`.

| Platform | Server | Management CLI |
|---|---|---|
| Linux amd64 | `aries-server-v0.0.2-linux-amd64` | `ariesctl-v0.0.2-linux-amd64` |
| Linux arm64 | `aries-server-v0.0.2-linux-arm64` | `ariesctl-v0.0.2-linux-arm64` |
| Windows amd64 | `aries-server-v0.0.2-windows-amd64.exe` | `ariesctl-v0.0.2-windows-amd64.exe` |

## Deploy on Linux

The example below installs the service under `/opt/dsh-aries`, keeps config and the admin token under `/etc/dsh-aries`, and writes durable data under `/var/lib/dsh-aries`. It binds both listeners to loopback. Put a TLS reverse proxy in front of the **public** listener; keep the admin listener private.

1. Download `aries-server-v0.0.2-linux-amd64` (or the matching architecture) from the release page and install it:

   ```sh
   sudo useradd --system --home-dir /var/lib/dsh-aries --shell /usr/sbin/nologin dsh-aries
   sudo install -d -o root -g dsh-aries -m 0750 /etc/dsh-aries
   sudo install -d -o dsh-aries -g dsh-aries -m 0750 /opt/dsh-aries /var/lib/dsh-aries
   sudo install -o root -g dsh-aries -m 0750 aries-server-v0.0.2-linux-amd64 /opt/dsh-aries/aries-server
   ```

2. Create an administrator token and the config file. Keep the token out of source control and logs:

   ```sh
   openssl rand -base64 48 | tr -d '\n' | sudo tee /etc/dsh-aries/admin.token >/dev/null
   sudo chown root:dsh-aries /etc/dsh-aries/admin.token
   sudo chmod 0640 /etc/dsh-aries/admin.token
   sudo tee /etc/dsh-aries/config.json >/dev/null <<'JSON'
   {
     "schema_version": 1,
     "public_listen": "127.0.0.1:8787",
     "admin_listen": "127.0.0.1:8788",
     "data_dir": "/var/lib/dsh-aries/data",
     "admin_token_file": "/etc/dsh-aries/admin.token",
     "max_storage_bytes": 1073741824,
     "allow_insecure_loopback": true,
     "peer_relay_enabled": false,
     "file_storage_enabled": true,
     "group_quota_bytes": 1073741824,
     "quota_bytes_per_member": 0,
     "max_file_bytes": 268435456,
     "max_file_ttl_seconds": 2592000
   }
   JSON
   sudo chown root:dsh-aries /etc/dsh-aries/config.json
   sudo chmod 0640 /etc/dsh-aries/config.json
   ```

3. Create `/etc/systemd/system/dsh-aries.service`:

   ```ini
   [Unit]
   Description=DSH-Aries relay server
   After=network-online.target
   Wants=network-online.target

   [Service]
   Type=simple
   User=dsh-aries
   Group=dsh-aries
   ExecStart=/opt/dsh-aries/aries-server serve --config /etc/dsh-aries/config.json
   Restart=on-failure
   RestartSec=3
   NoNewPrivileges=true
   PrivateTmp=true
   ProtectSystem=strict
   ProtectHome=true
   ReadWritePaths=/var/lib/dsh-aries

   [Install]
   WantedBy=multi-user.target
   ```

   Then enable and inspect the service:

   ```sh
   sudo systemctl daemon-reload
   sudo systemctl enable --now dsh-aries
   sudo systemctl status dsh-aries
   curl http://127.0.0.1:8787/healthz
   curl http://127.0.0.1:8787/api/v1/public/node
   ```

4. Configure Caddy (or another TLS proxy) with a public hostname. For Caddy:

   ```caddyfile
   aries.example.com {
       reverse_proxy 127.0.0.1:8787
   }
   ```

   Open only the proxy's HTTPS port to clients. Do not expose port `8788` to the public internet. To manage remotely, use a VPN or an SSH tunnel to the admin listener, for example `ssh -L 8788:127.0.0.1:8788 user@server`, then connect `ariesctl` to `http://127.0.0.1:8788` through that tunnel.

The public service port defaults to `8787`; the admin port defaults to `8788`. The current build does not implement peer relay or federation listeners. Back up the service data directory and admin token securely. Run one server process per data directory.

## Deploy on Windows

Download the Windows amd64 server binary, create a protected directory such as `C:\ProgramData\DSH-Aries`, and create a token with `ariesctl token create --out C:\ProgramData\DSH-Aries\admin.token`. Create `config.json` using the same fields as the Linux example, with Windows absolute paths, and set `data_dir` to a directory writable by the service account. Start the server in PowerShell:

```powershell
.\aries-server-v0.0.2-windows-amd64.exe serve --config C:\ProgramData\DSH-Aries\config.json
```

For unattended startup, register that command in Windows Task Scheduler under a dedicated account with access only to the config, token, and data directories. The release does not include a Windows Service wrapper. As on Linux, keep the admin listener on loopback and terminate public TLS at a reverse proxy.

## API usage

The public client API is rooted at `/api/v1/public`. Health and node discovery are public:

```sh
curl https://aries.example.com/healthz
curl https://aries.example.com/api/v1/public/node
```

Start device enrollment by generating an Ed25519 keypair locally, then requesting a challenge with the public key:

```sh
curl -X POST https://aries.example.com/api/v1/public/devices/challenge \
  -H 'Content-Type: application/json' \
  -d '{"public_key":"<unpadded-base64url-ed25519-public-key>"}'
```

The client signs the enrollment challenge with its private key and submits it to `/api/v1/public/devices/enroll`. Every later authenticated request, including reads, must carry the device ID, RFC3339 timestamp, one-use nonce, and Ed25519 signature. Durable mutations also require an `Idempotency-Key`. Do not send the private key to Aries. The full canonical signing string, every route and schema, pagination, retry behavior, and error codes are documented in [API-REFERENCE.md](docs/API-REFERENCE.md); file chunking is covered in [FILE-TRANSFER.md](docs/FILE-TRANSFER.md).

The separate admin API is rooted at `/api/v1/admin` and uses `Authorization: Bearer <admin-token>`. For example, query status locally:

```sh
curl http://127.0.0.1:8788/api/v1/admin/status \
  -H "Authorization: Bearer $(cat /etc/dsh-aries/admin.token)"
```

Or use the bilingual terminal UI and server-management commands:

```sh
./ariesctl --endpoint http://127.0.0.1:8788 \
  --token-file /etc/dsh-aries/admin.token status
./ariesctl --endpoint http://127.0.0.1:8788 \
  --token-file /etc/dsh-aries/admin.token
```

Omit the command to open the TUI. Read [CLI.md](docs/CLI.md) and [ADMIN-COMMANDS.md](docs/ADMIN-COMMANDS.md) for its commands, options, and admin API. Remote administration requires HTTPS unless you use a protected local tunnel; never place the admin token in a URL, shell history, or a public proxy log.

## Build from source

Go `1.27.2` or newer is required. The release build helper puts all Go caches under the project `temp/` directory and produces Linux amd64, Linux arm64, and Windows amd64 binaries:

```powershell
.\scripts\build-release.ps1
```

On Linux/macOS:

```sh
. ./scripts/use-project-temp.sh
./scripts/build-release.sh
```

Run tests and static analysis before packaging:

```sh
go test ./...
go vet ./...
```

Build outputs and caches stay under `temp/` and are not committed. `VERSION` records the current release version.

## Documentation

- [API v1 integration reference](docs/API-REFERENCE.md)
- [Public client protocol](docs/CLIENT-PROTOCOL.md)
- [Encrypted file transfer](docs/FILE-TRANSFER.md)
- [Management CLI](docs/CLI.md)
- [Admin command API](docs/ADMIN-COMMANDS.md)
- [Kernel and CLI integration contract](docs/INTEGRATION-CONTRACT.md)
