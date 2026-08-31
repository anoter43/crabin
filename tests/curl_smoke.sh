#!/bin/zsh
# Curl smoke tests against a running server. Usage: BASE=http://127.0.0.1:5000 ./tests/curl_smoke.sh
BASE="${BASE:-http://127.0.0.1:5000}"
fail=0
t() {
  local expected="$1"; shift
  local got
  got=$(curl -s -o /dev/null -w "%{http_code}" "$@" 2>&1)
  if [ "$got" = "$expected" ]; then
    echo "PASS: $*"
  else
    echo "FAIL: $* => expected $expected, got $got"
    fail=1
  fi
}

# HTTP methods / request inspection
t 200 "$BASE/get"
t 200 "$BASE/ip"
t 200 "$BASE/user-agent"
t 200 "$BASE/headers"
t 200 "$BASE/uuid"
t 200 -X PUT "$BASE/put"
t 200 -X DELETE "$BASE/delete"
t 200 -X PATCH "$BASE/patch"
t 200 -d a=1 "$BASE/post"
t 200 "$BASE/anything"
t 200 -X TRACE "$BASE/anything/deep/path"

# Status codes
t 200 "$BASE/status/200"
t 418 "$BASE/status/418"
t 401 "$BASE/status/401"
t 402 "$BASE/status/402"
t 407 "$BASE/status/407"
t 301 "$BASE/status/301"
t 400 "$BASE/status/abc"
t 500 "$BASE/status/60000"

# Redirects
t 302 "$BASE/redirect/2"
t 200 -L "$BASE/redirect/3"
t 302 "$BASE/relative-redirect/2"
t 302 "$BASE/absolute-redirect/2"
t 307 "$BASE/redirect-to?url=http://example.com/&status_code=307"
t 500 "$BASE/redirect-to"

# Auth
t 200 -u user:pass "$BASE/basic-auth/user/pass"
t 401 "$BASE/basic-auth/user/pass"
t 404 "$BASE/hidden-basic-auth/user/pass"
t 200 -u user:pass "$BASE/hidden-basic-auth/user/pass"
t 200 -H "Authorization: Bearer tok" "$BASE/bearer"
t 401 "$BASE/bearer"
t 200 --digest -u john:hello "$BASE/digest-auth/auth/john/hello"
t 401 --digest -u john:wrong "$BASE/digest-auth/auth/john/hello"
t 200 --digest -u john:hello "$BASE/digest-auth/auth/john/hello/SHA-256"
t 200 --digest -u john:hello "$BASE/digest-auth/auth-int/john/hello"

# Cookies
t 200 "$BASE/cookies"
t 302 "$BASE/cookies/set/a/b"
t 302 "$BASE/cookies/delete?a"

# Compression
t 200 "$BASE/gzip"
t 200 "$BASE/deflate"
t 200 "$BASE/brotli"

# Dynamic data
t 200 "$BASE/bytes/100"
t 200 "$BASE/stream/5"
t 200 "$BASE/stream-bytes/100"
t 200 "$BASE/drip?numbytes=3&duration=0.3"
t 400 "$BASE/drip?numbytes=-1"
t 200 "$BASE/delay/0.2"
t 500 "$BASE/delay/-1"
t 200 "$BASE/base64/SFRUUEJJTiBpcyBhd2Vzb21l"
t 200 "$BASE/base64/notvalid!"
t 200 "$BASE/range/100"
t 206 -H "Range: bytes=0-4" "$BASE/range/100"
t 416 -H "Range: bytes=999999-" "$BASE/range/100"
t 404 "$BASE/range/0"

# Response inspection
t 304 -H "If-None-Match: x" "$BASE/cache"
t 200 "$BASE/cache/60"
t 304 -H "If-None-Match: \"x\"" "$BASE/etag/x"
t 412 -H "If-Match: other" "$BASE/etag/x"
t 200 "$BASE/response-headers?foo=bar"
t 302 "$BASE/links/3"
t 200 -L "$BASE/links/3"
t 200 "$BASE/links/3/0"

# Images
t 200 "$BASE/image/png"
t 200 -H "Accept: image/jpeg" "$BASE/image"
t 406 -H "Accept: application/json" "$BASE/image"

# Formats
for p in xml json html robots.txt deny encoding/utf8 forms/post; do
  t 200 "$BASE/$p"
done

t 404 "$BASE/definitely/not/here"

[ $fail = 0 ] && echo "ALL PASS" || exit 1
