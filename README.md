# Paka

A small token-gated file server. An admin hands out tokens; every request to read, write, delete or list files spends one. Files and token metadata are encrypted at rest.

[paka-works.png](https://postimg.cc/kBQ4gTYP)

## Running

```sh
cargo run --release
```

On first start Paka prints a generated admin password **once** (only its argon2 hash is stored). To set your own, or to recover a lost one, start it with `PAKA_ADMIN_PWD=...`.

Open `http://localhost:9797/` for the web UI: generate tokens with the admin password, then upload, list, download and delete files with them.

### Configuration

| env var | default | |
|---|---|---|
| `PAKA_ADDR` | `0.0.0.0` | bind address |
| `PAKA_PORT` | `9797` | port |
| `PAKA_CERT` / `PAKA_KEY` | `./secrets/cert.pem` / `./secrets/priv.pem` | if these exist Paka serves HTTPS (rustls), otherwise plain HTTP |
| `PAKA_MAX_UPLOAD_MB` | `64` | largest accepted upload |
| `PAKA_TOKEN_TTL` | `86400` | default token lifetime in seconds |
| `PAKA_ADMIN_PWD` | | sets the admin password on startup |

### Files on disk

| path | |
|---|---|
| `secrets/master.key` | random 32 byte key that encrypts everything. **Back it up**: without it the files can't be read. |
| `admin_pwd.txt` | argon2 hash of the admin password |
| `tokens/` | one file per token, named by a keyed hash of the token so the names can't be used as tokens |
| `dist/` | uploaded files, encrypted (ChaCha20-Poly1305) |
| `static/` | the web UI and `paka.mjs`, gzipped in memory when served |

Upgrading from the old version, where `admin_pwd.txt` held the plaintext password and encrypted the files: on first start Paka re-encrypts `dist/` with the new master key and hashes the password (it stays the same). Old tokens are dropped.

## Tokens

Tokens are single use and live for a day by default. With `/mktn` you can also give them several uses, a custom lifetime, restrict them to one file or to some operations, and attach a JSON payload the token holder can read back.

Pass a token as `?tk=TOKEN` or in an `x-paka-token` header. A token is spent when a request is authorised, even if the file then turns out not to exist. A request outside a token's scope is refused with 403 and doesn't spend it.

## API

Admin routes (wrong password → 401):

| route | body | returns |
|---|---|---|
| `POST /make-tokens/{count}` | admin password | `["token", ...]` single use, default lifetime |
| `POST /mktn` | JSON, see below | `["token", ...]` |
| `POST /expire-tokens` | admin password | `{"removed": n}` deletes expired tokens (also done hourly) |
| `POST /revoke-tokens` | admin password | `{"removed": n}` deletes all tokens |
| `POST /admin/change-password` | `{"pwd": "...", "new_pwd": "..."}` | `{"ok": true}` |
| `POST /remove-gz-files` | admin password | `{"cleared": n}` clears the static gzip cache |

`/mktn` body, everything but `pwd` optional:

```json
{
  "pwd": "admin password",
  "count": 10,
  "uses": 3,
  "ttl": 3600,
  "exp": 1790000000,
  "file": "report.pdf",
  "ops": ["read", "write", "delete", "list"],
  "payload": {"anything": "json"}
}
```

`exp` is an absolute unix time and wins over `ttl` (seconds from now). At most 1000 tokens per request.

Token routes:

| route | op | returns |
|---|---|---|
| `GET /token?tk=` | — | `{exp, uses, file, ops, payload}` without spending the token |
| `GET /files?tk=` | list | `[{filename, size, modified}]` |
| `GET /file-info/{name}?tk=` | read | `{filename, size, modified}` |
| `GET /file/{name}?tk=` | read | the file, as an attachment |
| `POST /file/{name}?tk=` | write | uploads/overwrites, body is the file |
| `DELETE /file/{name}?tk=` | delete | `{"deleted": name}` |

File names are plain names: no `/` or `\`, no leading `.`, at most 255 bytes. Errors come back as `{"error": "..."}`.

Static: `GET /` serves `static/index.html`, `GET /static/{name}` serves `static/`.

## paka.mjs

A browser client, served at `/static/paka.mjs`:

```js
import paka from '/static/paka.mjs'

const tokens = await paka.makeTokens(adminPwd, 3)
// or paka.makeTokenRequest({ pwd: adminPwd, count: 3, uses: 2, ops: ['read'] })

const client = paka('/file/', tokens)
client.ifTaking(() => localStorage.setItem('tokens', JSON.stringify(client.tokens)))

await client.post('notes.txt', 'music is cool')
const text = await (await client.get('notes.txt')).text()
await client.delete('notes.txt')
```

Client methods `get`, `post`, `delete`, `info`, `list` each spend one token and return the `fetch` Response; `tokenInfo()` checks a token for free. `feed(...tokens)` adds tokens, `tokens` shows what's left. Admin helpers: `paka.expireTokens`, `paka.revokeTokens`, `paka.changePassword`, `paka.clearStaticCache`.

## License

MIT
