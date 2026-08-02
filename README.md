# Sub-Store Go

A lightweight Sub-Store rewrite in Go (backend) + Vue 3 / Element Plus (web
frontend). Supports subscription management, node parsing/conversion, combined
subscriptions, and token-based sharing, with account/password login.

## Features

- **Subscription management**: add/edit/delete subscriptions (remote URL or
  local content), set custom User-Agent, define per-sub operators.
- **Combined subscriptions**: aggregate multiple subscriptions into one.
- **Node conversion**: parse SS / SSR / VMess / VLESS / Trojan / Hysteria /
  Hysteria2 / TUIC / WireGuard / AnyTLS / SOCKS / HTTP / Surge / Quantumult X /
  Clash / SSD / Base64 subs, and produce JSON, URI, Clash/Mihomo YAML, Surge,
  SurgeMac, Loon, Shadowrocket, Stash, Surfboard, Quantumult X, sing-box,
  V2Ray, Egern output.
- **Operators**: Useless/Region/Regex/Type/Conditional filters and
  Sort/Regex Sort/Regex Rename/Regex Delete/Handle Duplicate/Flag/Quick
  Setting/Resolve Domain operators.
- **Sharing**: generate time-limited or usage-count-limited tokens and share
  `sub` / `col` via public URLs.
- **Auth**: JWT login with bcrypt password hashing. The admin account is fixed
  by environment variables (default `admin`/`admin`); public registration and
  in-app password changes are disabled.

## Build

Backend (requires Go 1.23+). The frontend is embedded into the binary via
`go:embed`, so build the frontend first:

```sh
cd web
npm install
npm run build
cd ..
go build -o substore ./cmd
```

The resulting `substore` binary is self-contained (backend + web UI). If the
frontend has not been built (`web/dist` is empty), the server falls back to
serving the on-disk directory given by `SUB_STORE_FRONTEND_PATH`.

## Run

The admin account is fixed by environment variables. Defaults to
`admin` / `admin` when unset; set the env vars to override. The admin password
is reset from the env var on every start, so changing credentials is done by
restarting with new values. Public registration and in-app password change are
not supported.

```sh
SUB_STORE_ADMIN_USERNAME=admin \
SUB_STORE_ADMIN_PASSWORD=secret \
./substore
```

The server listens on `http://0.0.0.0:3000` and serves the frontend at `/`.

### Environment variables

| Variable | Default | Description |
| --- | --- | --- |
| `SUB_STORE_BACKEND_API_HOST` | `0.0.0.0` | Listen host |
| `SUB_STORE_HTTP_PORT` | `3000` | HTTP listen port (preferred). `SUB_STORE_BACKEND_API_PORT` is honored as a fallback. |
| `SUB_STORE_BACKEND_API_PORT` | `3000` | Legacy alias for `SUB_STORE_HTTP_PORT` |
| `SUB_STORE_DATA_DIR` | `./data` | Data directory (SQLite + JWT secret). Preferred; `SUB_STORE_DATA_PATH` is honored as a fallback. |
| `SUB_STORE_DATA_PATH` | `./data` | Legacy alias for `SUB_STORE_DATA_DIR` |
| `SUB_STORE_JWT_SECRET` | *(auto-generated)* | JWT signing secret. When unset a random one is generated once and persisted to `$SUB_STORE_DATA_PATH/jwt_secret` |
| `SUB_STORE_TOKEN_TTL_HOURS` | `168` | JWT validity in hours |
| `SUB_STORE_ADMIN_USERNAME` | `admin` | Admin username. Overrides the default `admin`. |
| `SUB_STORE_ADMIN_PASSWORD` | `admin` | Admin password. Overrides the default `admin`; re-applied on every start. |
| `SUB_STORE_FRONTEND_PATH` | `./web/dist` | On-disk frontend fallback (used only when the embedded dist is empty) |

## API

Auth (`Bearer <jwt>` required):

- `POST /api/login` `{username,password}` -> `{token,username}`
- `GET  /api/subs` / `POST /api/subs`
- `GET  /api/sub/:name` / `PATCH /api/sub/:name` / `DELETE /api/sub/:name`
- `GET  /api/collections` / `POST /api/collections`
- `GET  /api/col/:name` / `PATCH /api/col/:name` / `DELETE /api/col/:name`
- `GET  /api/node-info/:name` (node preview)
- `GET  /api/tokens` / `POST /api/token` / `DELETE /api/token/:token`
- `GET  /api/settings` / `PATCH /api/settings`

Public:

- `GET /download/:name?target=mihomo` (requires Bearer token or `?token=`)
- `GET /share/sub/:name?token=...&target=...`
- `GET /share/col/:name?token=...&target=...`

Targets: `mihomo`, `clash`, `stash`, `surge`, `surge-mac`, `surfboard`,
`loon`, `shadowrocket`, `qx`, `sing-box`, `v2ray`, `egern`, `json`, `uri`.

## Docker

```sh
docker build -t substore .
docker run -p 3000:3000 \
  -e SUB_STORE_ADMIN_USERNAME=admin \
  -e SUB_STORE_ADMIN_PASSWORD=secret \
  -v substore-data:/app/data \
  substore
```
