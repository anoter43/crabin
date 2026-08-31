# crabin

An [httpbin](https://httpbin.org) clone written in Rust with axum and tokio. It reproduces the original's endpoints, response formats, and edge cases: Flask-style pretty JSON (sorted keys, trailing spaces), the werkzeug teapot, digest auth handshakes, and static pages. Verified against httpbin.org with curl.

The HTML/XML/text payloads and images come from the httpbin repository and ship via `include_str!`/`include_bytes!` from `assets/`.

## Run

```sh
cargo run              # 127.0.0.1:5000
PORT=8080 HOST=0.0.0.0 cargo run
```

No landing page. `tests/curl_smoke.sh` runs a curl battery against a running server:

```sh
cargo run &
BASE=http://127.0.0.1:5000 ./tests/curl_smoke.sh
```

## Endpoints

### Request inspection

| Endpoint | Description |
|---|---|
| `/ip` | Origin IP, honors `X-Forwarded-For` |
| `/user-agent` | The `User-Agent` header |
| `/headers` | Request headers (hides proxy headers unless `?show_env=`) |
| `/get` | `url`, `args`, `headers`, `origin` |
| `/anything`, `/anything/{*path}` | Everything: method, form, data, files, json. Accepts GET, POST, PUT, DELETE, PATCH, TRACE |
| `/post` `/put` `/patch` `/delete` | Method-specific request echo |

`data` is the raw body, base64-wrapped as a `data:` URL when it is not valid UTF-8. `json` holds the parsed body or `null`. `form` and `files` fill from `application/x-www-form-urlencoded` and `multipart/form-data` bodies; file contents become `data:` URLs when binary.

### Status codes

`/status/{codes}` returns the given code. Comma-separated codes are chosen by weight: `/status/200:3,418:1` returns 200 three quarters of the time. Special bodies match httpbin: 301/302/303/305/307 send `Location: /redirect/1`, 401 sends a Basic challenge, 402 pays up, 406 lists accepted media types, 407 proxies, 418 brews tea. Invalid codes return 400.

### Redirects

| Endpoint | Description |
|---|---|
| `/redirect/{n}` | n 302s, ends at `/get`. `?absolute=true` uses absolute URLs |
| `/relative-redirect/{n}` | Relative `Location` chains |
| `/absolute-redirect/{n}` | Absolute `Location` chains |
| `/redirect-to?url=X&status_code=3XX` | Redirect anywhere, any method |

### Auth

| Endpoint | Description |
|---|---|
| `/basic-auth/{user}/{passwd}` | 401 with `WWW-Authenticate: Basic realm="Fake Realm"` on failure |
| `/hidden-basic-auth/{user}/{passwd}` | 404 instead of 401 on failure |
| `/bearer` | 401 unless `Authorization: Bearer ...` |
| `/digest-auth/{qop}/{user}/{passwd}` | `qop` is `auth` or `auth-int` |
| `/digest-auth/{qop}/{user}/{passwd}/{algorithm}` | `MD5`, `SHA-256`, or `SHA-512` (curl supports the first two) |
| `/digest-auth/{qop}/{user}/{passwd}/{algorithm}/{stale_after}` | Stale nonce after n uses, driven by cookies |

Digest challenges match the original's header format and cookie flow (`fake`, `stale_after`, `last_nonce`), including `?require-cookie=true` handling. Works with `curl --digest`.

```sh
curl --digest -u john:hello http://127.0.0.1:5000/digest-auth/auth/john/hello/SHA-256
```

### Cookies

| Endpoint | Description |
|---|---|
| `/cookies` | Cookie jar as JSON |
| `/cookies/set/{name}/{value}` | Set one, 302 to `/cookies` |
| `/cookies/set?k=v&k2=v2` | Set several, 302 to `/cookies` |
| `/cookies/delete?k1&k2` | Expire cookies, 302 to `/cookies` |

### Dynamic data

| Endpoint | Description |
|---|---|
| `/uuid` | Random UUID4 |
| `/delay/{n}` | Sleep up to 10 seconds, then echo the request. Floats work (`/delay/0.5`) |
| `/drip?numbytes=&duration=&code=&delay=` | Stream `*` bytes at an even rate, default 10 bytes over 2s |
| `/bytes/{n}` | Random bytes, max 100KB. `?seed=` makes output repeatable |
| `/stream/{n}` | n JSON lines, max 100 |
| `/stream-bytes/{n}` | Random bytes in chunks, `?chunk_size=` and `?seed=` |
| `/range/{n}` | The first n letters of the alphabet. Supports `Range` headers: 206, 416 with `Content-Range`, `ETag: range{n}`, `Accept-Ranges: bytes` |
| `/base64/{value}` | URL-safe base64 decode. Invalid input gets the original's error message |
| `/links/{n}`, `/links/{n}/{offset}` | Pages of n links, one plain |

### Response inspection

| Endpoint | Description |
|---|---|
| `/cache` | 304 when `If-Modified-Since` or `If-None-Match` is present, else 200 with fresh `Last-Modified` and `ETag` |
| `/cache/{n}` | 200 with `Cache-Control: public, max-age={n}` |
| `/etag/{etag}` | 304 on `If-None-Match` hit, 412 on `If-Match` miss, 200 otherwise |
| `/response-headers?k=v` | Sets the query params as response headers and reports them in the body |

### Response formats

| Endpoint | Description |
|---|---|
| `/gzip` `/deflate` `/brotli` | The request echo, compressed, with `Content-Encoding` |
| `/html` | Moby Dick excerpt |
| `/json` | Slideshow document |
| `/xml` | Slideshow XML |
| `/encoding/utf8` | UTF-8 demo page |
| `/robots.txt` | Points crawlers at `/deny` |
| `/deny` | You shouldn't be here |
| `/forms/post` | HTML form that posts to `/post` |
| `/image` | Picks by `Accept` header, 406 when nothing matches |
| `/image/png` `/image/jpeg` `/image/webp` `/image/svg` | Specific formats |

### CORS

Every response carries `Access-Control-Allow-Origin` (echoes `Origin`, else `*`) and `Access-Control-Allow-Credentials: true`. OPTIONS requests get 200 with the usual preflight headers.

## Differences from httpbin.org

- `/bytes/{n}` and `/stream-bytes/{n}` use a Rust PRNG, so seeded output differs from Python's Mersenne Twister. Same seed always gives the same bytes here.
- `/drip` paces the bytes on a fixed schedule; the original's ancient gunicorn adds jitter.
- The `Allow` header on OPTIONS responses lists all methods instead of the per-route list.
- No Swagger UI at `/` and no `/spec.json`.
- Header names in JSON bodies are title-cased (`User-Agent`); the original echoes the exact client casing.
- Hyper serves HTTP/1.1 (and h2c-less); it does not emit `Server: gunicorn`.

