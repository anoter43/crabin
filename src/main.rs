// ponytail: Response-as-Err is the whole error strategy; boxing every handler
// for clippy::result_large_err buys nothing at this scale.
#![allow(clippy::result_large_err)]

use std::{
    io::Write,
    net::SocketAddr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    Router,
    body::{Body, Bytes, to_bytes},
    extract::{ConnectInfo, FromRequest, Multipart, Path, Request},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::Response,
    routing::{MethodFilter, delete, get, on, patch, post, put},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE},
};
use brotli::CompressorWriter;
use flate2::{Compression, write::GzEncoder, write::ZlibEncoder};
use md5::{Digest, Md5};
use rand::{Rng, RngExt, SeedableRng, rngs::StdRng};
use serde_json::{Map, Value, map::Entry};
use sha2::{Sha256, Sha512};
use uuid::Uuid;

const REALM: &str = "me@kennethreitz.com";
const REDIRECT_LOCATION: &str = "/redirect/1";
const ROBOT_TXT: &str = "User-agent: *\nDisallow: /deny\n";
const MAX_BODY: usize = 100 * 1024 * 1024;

const ACCEPTED_MEDIA_TYPES: &[&str] = &[
    "image/webp",
    "image/svg+xml",
    "image/jpeg",
    "image/png",
    "image/*",
];

const ASCII_ART: &str = r#"
    -=[ teapot ]=-

       _...._
     .'  _ _ `.
    | ."` ^ `". _,
    \_;`"---"`|//
      |       ;/
      \_     _/
        `"""`
"#;

const ANGRY_ASCII: &str = r#"
          .-''''''-.
        .' _      _ '.
       /   O      O   \
      :                :
      |                |
      :       __       :
       \  .-"`  `"-.  /
        '.          .'
          '-......-'
     YOU SHOULDN'T BE HERE
"#;

const ENV_HEADERS: &[&str] = &[
    "X-Varnish",
    "X-Request-Start",
    "X-Heroku-Queue-Depth",
    "X-Real-Ip",
    "X-Forwarded-Proto",
    "X-Forwarded-Protocol",
    "X-Forwarded-Ssl",
    "X-Heroku-Queue-Wait-Time",
    "X-Forwarded-For",
    "X-Heroku-Dynos-In-Use",
    "X-Forwarded-Port",
    "X-Request-Id",
    "Via",
    "Total-Route-Time",
    "Connect-Time",
];

const ENV_COOKIES: &[&str] = &[
    "_gauges_unique",
    "_gauges_unique_year",
    "_gauges_unique_month",
    "_gauges_unique_day",
    "_gauges_unique_hour",
    "__utmz",
    "__utma",
    "__utmb",
];

// ---------------------------------------------------------------------------
// JSON serialization matching Flask's jsonify (sort_keys, indent=2, ", " and
// ": " separators, ensure_ascii) plus compact json.dumps for streaming lines.
// ---------------------------------------------------------------------------

fn py_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c if (c as u32) <= 0x7e => out.push(c),
            c => {
                let cp = c as u32;
                if cp > 0xffff {
                    let v = cp - 0x10000;
                    out.push_str(&format!(
                        "\\u{:04x}\\u{:04x}",
                        0xd800 + (v >> 10),
                        0xdc00 + (v & 0x3ff)
                    ));
                } else {
                    out.push_str(&format!("\\u{:04x}", cp));
                }
            }
        }
    }
    out.push('"');
    out
}

fn pretty(v: &Value, level: usize) -> String {
    match v {
        Value::Null => "null".into(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => py_str(s),
        Value::Array(a) if a.is_empty() => "[]".into(),
        Value::Array(a) => format!(
            "[\n{}\n{}]",
            a.iter()
                .map(|x| format!("{}{}", "  ".repeat(level + 1), pretty(x, level + 1)))
                .collect::<Vec<_>>()
                .join(", \n"),
            "  ".repeat(level)
        ),
        Value::Object(m) if m.is_empty() => "{}".into(),
        Value::Object(m) => format!(
            "{{\n{}\n{}}}",
            m.iter()
                .map(|(k, x)| format!(
                    "{}{}: {}",
                    "  ".repeat(level + 1),
                    py_str(k),
                    pretty(x, level + 1)
                ))
                .collect::<Vec<_>>()
                .join(", \n"),
            "  ".repeat(level)
        ),
    }
}

fn compact(v: &Value) -> String {
    match v {
        Value::Null => "null".into(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => py_str(s),
        Value::Array(a) => format!("[{}]", a.iter().map(compact).collect::<Vec<_>>().join(", ")),
        Value::Object(m) => format!(
            "{{{}}}",
            m.iter()
                .map(|(k, x)| format!("{}: {}", py_str(k), compact(x)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

fn sort_json(v: Value) -> Value {
    match v {
        Value::Object(m) => {
            let mut items: Vec<(String, Value)> = m.into_iter().collect();
            items.sort_by(|a, b| a.0.cmp(&b.0));
            Value::Object(
                items
                    .into_iter()
                    .map(|(k, v)| (k, sort_json(v)))
                    .collect::<Map<String, Value>>(),
            )
        }
        Value::Array(a) => Value::Array(a.into_iter().map(sort_json).collect()),
        other => other,
    }
}

fn jsonify(v: Value) -> Response {
    let body = format!("{}\n", pretty(&sort_json(v), 0));
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap()
}

fn obj(items: &[(&str, Value)]) -> Value {
    Value::Object(
        items
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect::<Map<String, Value>>(),
    )
}

fn s(v: impl Into<String>) -> Value {
    Value::String(v.into())
}

// ---------------------------------------------------------------------------
// Small response helpers
// ---------------------------------------------------------------------------

fn html_response(body: String) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(Body::from(body))
        .unwrap()
}

fn text_response(status: u16, body: &str) -> Response {
    html_text_response(status, "text/html; charset=utf-8", body)
}

fn plain_text_response(status: u16, body: &str) -> Response {
    html_text_response(status, "text/plain; charset=utf-8", body)
}

fn html_text_response(status: u16, ct: &str, body: &str) -> Response {
    Response::builder()
        .status(StatusCode::from_u16(status).unwrap())
        .header(header::CONTENT_TYPE, ct)
        .body(Body::from(body.to_string()))
        .unwrap()
}

// Jinja strips one trailing newline and renders url_for in the form template.
fn template(s: &str) -> String {
    s.strip_suffix('\n')
        .unwrap_or(s)
        .replace("{{ url_for('view_post') }}", "/post")
}

fn redirect_html(location: &str) -> String {
    format!(
        "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2 Final//EN\">\n\
         <title>Redirecting...</title>\n\
         <h1>Redirecting...</h1>\n\
         <p>You should be redirected automatically to target URL: \
         <a href=\"{location}\">{location}</a>.  If not click the link."
    )
}

fn redirect_response(status: u16, location: &str) -> Response {
    Response::builder()
        .status(StatusCode::from_u16(status).unwrap())
        .header(header::LOCATION, location)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(Body::from(redirect_html(location)))
        .unwrap()
}

fn redirect(location: &str) -> Response {
    redirect_response(302, location)
}

fn set_cookie_hdr(res: &mut Response, name: &str, value: &str) {
    if let Ok(v) = HeaderValue::from_str(&format!("{name}={value}; Path=/")) {
        res.headers_mut().append(header::SET_COOKIE, v);
    }
}

fn delete_cookie_hdr(res: &mut Response, name: &str) {
    if let Ok(v) = HeaderValue::from_str(&format!(
        "{name}=; Expires=Thu, 01-Jan-1970 00:00:00 GMT; Max-Age=0; Path=/"
    )) {
        res.headers_mut().append(header::SET_COOKIE, v);
    }
}

fn not_found() -> Response {
    html_response(
        "<!doctype html>\n\
         <html lang=en>\n\
         <title>404 Not Found</title>\n\
         <h1>404 Not Found</h1>\n\
         <p>The requested URL was not found on the server. If you entered the URL \
         manually please check your spelling and try again.</p>\n"
            .into(),
    )
    .with_status(404)
}

fn internal_error() -> Response {
    html_response(
        "<!doctype html>\n\
         <html lang=en>\n\
         <title>500 Internal Server Error</title>\n\
         <h1>Internal Server Error</h1>\n\
         <p>The server encountered an internal error and was unable to complete your \
         request. Either the server is overloaded or there is an error in the \
         application.</p>\n"
            .into(),
    )
    .with_status(500)
}

fn bad_request() -> Response {
    html_response(
        "<!doctype html>\n<html lang=en>\n<title>400 Bad Request</title>\n\
         <h1>400 Bad Request</h1>\n"
            .into(),
    )
    .with_status(400)
}

trait WithStatus: Sized {
    fn with_status(self, status: u16) -> Response;
}

impl WithStatus for Response {
    fn with_status(mut self, status: u16) -> Response {
        *self.status_mut() = StatusCode::from_u16(status).unwrap();
        self
    }
}

fn status_response(code: u16) -> Response {
    let b = Response::builder()
        .status(StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR));
    match code {
        301 | 302 | 303 | 305 | 307 => b.header("Location", REDIRECT_LOCATION),
        401 => b.header("WWW-Authenticate", "Basic realm=\"Fake Realm\""),
        407 => b.header("Proxy-Authenticate", "Basic realm=\"Fake Realm\""),
        _ => b,
    }
    .body(match code {
        301 | 302 | 303 | 305 | 307 | 401 | 407 => Body::empty(),
        402 => Body::from("Fuck you, pay me!"),
        406 => Body::from(format!(
            "{{\"message\": \"Client did not request a supported media type.\", \
             \"accept\": [{}]}}",
            ACCEPTED_MEDIA_TYPES
                .iter()
                .map(|t| format!("\"{t}\""))
                .collect::<Vec<_>>()
                .join(", ")
        )),
        418 => Body::from(ASCII_ART),
        _ => Body::empty(),
    })
    .unwrap()
    .with_headers(|h| {
        if code == 402 {
            h.insert(
                "x-more-info",
                HeaderValue::from_static("http://vimeo.com/22053820"),
            );
        }
        if code == 418 {
            h.insert(
                "x-more-info",
                HeaderValue::from_static("http://tools.ietf.org/html/rfc2324"),
            );
        }
        if code == 406 {
            h.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
        }
        // Werkzeug's default response content type survives unless the status
        // code map replaced the whole header set.
        if !matches!(
            code,
            301 | 302 | 303 | 305 | 307 | 401 | 402 | 406 | 407 | 418
        ) {
            h.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/html; charset=utf-8"),
            );
        }
    })
}

trait WithHeaders: Sized {
    fn with_headers(self, f: impl FnOnce(&mut axum::http::HeaderMap)) -> Response;
}

impl WithHeaders for Response {
    fn with_headers(mut self, f: impl FnOnce(&mut axum::http::HeaderMap)) -> Response {
        f(self.headers_mut());
        self
    }
}

fn http_date_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let (h, mi, sec) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // Howard Hinnant's civil-from-days algorithm
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    let wd = (days + 4).rem_euclid(7);
    const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} GMT",
        DAYS[wd as usize],
        d,
        MONTHS[(m - 1) as usize],
        y,
        h,
        mi,
        sec
    )
}

// ---------------------------------------------------------------------------
// Request inspection (werkzeug get_dict equivalent)
// ---------------------------------------------------------------------------

struct Info {
    url: String,
    args: Value,
    form: Value,
    data: Value,
    origin: String,
    headers: Value,
    files: Value,
    json: Value,
    method: String,
}

fn urldecode(input: &str, plus: bool) -> String {
    let b = input.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => {
                let (h, l) = (
                    hex_val(b.get(i + 1).copied()),
                    hex_val(b.get(i + 2).copied()),
                );
                if let (Some(h), Some(l)) = (h, l) {
                    out.push(h * 16 + l);
                    i += 3;
                } else {
                    out.push(b'%');
                    i += 1;
                }
            }
            b'+' if plus => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(c: Option<u8>) -> Option<u8> {
    match c? {
        b'0'..=b'9' => Some(c.unwrap() - b'0'),
        b'a'..=b'f' => Some(c.unwrap() - b'a' + 10),
        b'A'..=b'F' => Some(c.unwrap() - b'A' + 10),
        _ => None,
    }
}

fn parse_query(q: &str) -> Vec<(String, String)> {
    q.split('&')
        .filter(|p| !p.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((k, v)) => (urldecode(k, true), urldecode(v, true)),
            None => (urldecode(pair, true), String::new()),
        })
        .collect()
}

fn add_multi(map: &mut Map<String, Value>, k: String, v: Value) {
    match map.entry(k) {
        Entry::Vacant(e) => {
            e.insert(v);
        }
        Entry::Occupied(mut e) => {
            let ex = e.get_mut();
            if let Value::Array(a) = ex {
                a.push(v);
            } else {
                let prev = ex.take();
                *ex = Value::Array(vec![prev, v]);
            }
        }
    }
}

fn semi(pairs: Vec<(String, Value)>) -> Value {
    let mut m = Map::new();
    for (k, v) in pairs {
        add_multi(&mut m, k, v);
    }
    Value::Object(m)
}

fn title_case(name: &str) -> String {
    name.split('-')
        .map(|p| {
            let mut c = p.chars();
            match c.next() {
                Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join("-")
}

fn json_safe(bytes: &[u8], ct: &str) -> String {
    match std::str::from_utf8(bytes) {
        Ok(s) => s.to_string(),
        Err(_) => format!("data:{ct};base64,{}", STANDARD.encode(bytes)),
    }
}

async fn req_info(req: Request, addr: SocketAddr) -> Result<Info, Response> {
    let method = req.method().as_str().to_string();
    let uri = req.uri().clone();
    let headers = req.headers().clone();

    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .or_else(|| uri.authority().map(|a| a.as_str().to_string()))
        .unwrap_or_else(|| addr.to_string());
    let fwd = headers
        .get("x-forwarded-proto")
        .or_else(|| headers.get("x-forwarded-protocol"))
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .or_else(|| {
            (headers.get("x-forwarded-ssl").and_then(|v| v.to_str().ok()) == Some("on"))
                .then(|| "https".to_string())
        })
        .unwrap_or_else(|| uri.scheme_str().unwrap_or("http").to_string());
    let path = uri.path();
    let query = uri.query().unwrap_or("");
    let url = format!(
        "{fwd}://{host}{path}{}",
        if query.is_empty() {
            String::new()
        } else {
            format!("?{query}")
        }
    );

    let args = semi(
        parse_query(query)
            .into_iter()
            .map(|(k, v)| (k, s(v)))
            .collect(),
    );
    let origin = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .unwrap_or_else(|| addr.ip().to_string());

    let show_env = args.get("show_env").is_some();
    let mut hmap = Map::new();
    for (name, value) in &headers {
        if !show_env
            && ENV_HEADERS
                .iter()
                .any(|h| name.as_str().eq_ignore_ascii_case(h))
        {
            continue;
        }
        hmap.insert(
            title_case(name.as_str()),
            s(String::from_utf8_lossy(value.as_bytes())),
        );
    }
    let headers_v = Value::Object(hmap);

    let ct = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();

    let (form, files, data, json) = if ct.starts_with("application/x-www-form-urlencoded") {
        let body = to_bytes(req.into_body(), MAX_BODY)
            .await
            .map_err(|_| bad_request().with_status(413))?;
        let form = semi(
            parse_query(&String::from_utf8_lossy(&body))
                .into_iter()
                .map(|(k, v)| (k, s(v)))
                .collect(),
        );
        (form, Value::Object(Map::new()), s(""), Value::Null)
    } else if ct.starts_with("multipart/form-data") {
        let mut mp = Multipart::from_request(req, &())
            .await
            .map_err(|_| bad_request())?;
        let mut form_pairs = vec![];
        let mut files_map = Map::new();
        while let Ok(Some(field)) = mp.next_field().await {
            let name = field.name().unwrap_or("").to_string();
            let is_file = field.file_name().is_some();
            let fct = field
                .content_type()
                .map(String::from)
                .unwrap_or_else(|| "application/octet-stream".into());
            let bytes = field.bytes().await.map_err(|_| bad_request())?;
            if is_file {
                add_multi(&mut files_map, name, s(json_safe(&bytes, &fct)));
            } else {
                form_pairs.push((name, s(String::from_utf8_lossy(&bytes))));
            }
        }
        (
            semi(form_pairs),
            Value::Object(files_map),
            s(""),
            Value::Null,
        )
    } else {
        let body = to_bytes(req.into_body(), MAX_BODY)
            .await
            .map_err(|_| bad_request().with_status(413))?;
        let json = serde_json::from_slice::<Value>(&body).unwrap_or(Value::Null);
        (
            Value::Object(Map::new()),
            Value::Object(Map::new()),
            s(json_safe(&body, "application/octet-stream")),
            json,
        )
    };

    Ok(Info {
        url,
        args,
        form,
        data,
        origin,
        headers: headers_v,
        files,
        json,
        method,
    })
}

fn dict(info: &Info, keys: &[&str]) -> Value {
    let mut m = Map::new();
    for k in keys {
        let v = match *k {
            "url" => s(&info.url),
            "args" => info.args.clone(),
            "form" => info.form.clone(),
            "data" => info.data.clone(),
            "origin" => s(&info.origin),
            "headers" => info.headers.clone(),
            "files" => info.files.clone(),
            "json" => info.json.clone(),
            "method" => s(&info.method),
            _ => Value::Null,
        };
        m.insert((*k).to_string(), v);
    }
    Value::Object(m)
}

fn arg<'a>(args: &'a [(String, String)], name: &str) -> Option<&'a str> {
    args.iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

fn ci_arg<'a>(args: &'a [(String, String)], name: &str) -> Option<&'a str> {
    args.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

// ---------------------------------------------------------------------------
// Request inspection handlers
// ---------------------------------------------------------------------------

async fn ip(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
) -> Result<Response, Response> {
    let info = req_info(req, addr).await?;
    Ok(jsonify(obj(&[("origin", s(&info.origin))])))
}

async fn view_uuid() -> Response {
    jsonify(obj(&[("uuid", s(Uuid::new_v4().to_string()))]))
}

async fn view_headers(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
) -> Result<Response, Response> {
    let info = req_info(req, addr).await?;
    Ok(jsonify(obj(&[("headers", info.headers)])))
}

async fn user_agent(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
) -> Result<Response, Response> {
    let info = req_info(req, addr).await?;
    let ua = info
        .headers
        .get("User-Agent")
        .cloned()
        .unwrap_or(Value::Null);
    Ok(jsonify(obj(&[("user-agent", ua)])))
}

async fn view_get(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
) -> Result<Response, Response> {
    let info = req_info(req, addr).await?;
    Ok(jsonify(dict(&info, &["url", "args", "headers", "origin"])))
}

async fn anything(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
) -> Result<Response, Response> {
    let info = req_info(req, addr).await?;
    Ok(jsonify(dict(
        &info,
        &[
            "url", "args", "headers", "origin", "method", "form", "data", "files", "json",
        ],
    )))
}

async fn post_(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
) -> Result<Response, Response> {
    method_body(addr, req, "post").await
}

async fn put_(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
) -> Result<Response, Response> {
    method_body(addr, req, "put").await
}

async fn patch_(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
) -> Result<Response, Response> {
    method_body(addr, req, "patch").await
}

async fn delete_(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
) -> Result<Response, Response> {
    method_body(addr, req, "delete").await
}

async fn method_body(addr: SocketAddr, req: Request, _name: &str) -> Result<Response, Response> {
    let info = req_info(req, addr).await?;
    Ok(jsonify(dict(
        &info,
        &[
            "url", "args", "form", "data", "origin", "headers", "files", "json",
        ],
    )))
}

// ---------------------------------------------------------------------------
// Response formats
// ---------------------------------------------------------------------------

fn encoded_json(
    v: Value,
    flag: (&str, bool),
    encoding: &str,
    encode: impl FnOnce(&[u8]) -> Vec<u8>,
) -> Response {
    let mut m = match sort_json(v) {
        Value::Object(m) => m,
        _ => unreachable!(),
    };
    m.insert(flag.0.to_string(), Value::Bool(flag.1));
    let body = format!("{}\n", pretty(&Value::Object(m), 0));
    let encoded = encode(body.as_bytes());
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CONTENT_ENCODING, encoding)
        .body(Body::from(encoded))
        .unwrap()
}

async fn gzip(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
) -> Result<Response, Response> {
    let info = req_info(req, addr).await?;
    let v = obj(&[
        ("origin", s(&info.origin)),
        ("headers", info.headers),
        ("method", s(&info.method)),
    ]);
    Ok(encoded_json(v, ("gzipped", true), "gzip", |data| {
        let mut e = GzEncoder::new(Vec::new(), Compression::new(4));
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }))
}

async fn deflate(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
) -> Result<Response, Response> {
    let info = req_info(req, addr).await?;
    let v = obj(&[
        ("origin", s(&info.origin)),
        ("headers", info.headers),
        ("method", s(&info.method)),
    ]);
    Ok(encoded_json(v, ("deflated", true), "deflate", |data| {
        let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }))
}

async fn brotli(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
) -> Result<Response, Response> {
    let info = req_info(req, addr).await?;
    let v = obj(&[
        ("origin", s(&info.origin)),
        ("headers", info.headers),
        ("method", s(&info.method)),
    ]);
    Ok(encoded_json(v, ("brotli", true), "br", |data| {
        let mut out = Vec::new();
        let mut w = CompressorWriter::new(&mut out, 4096, 11, 22);
        w.write_all(data).unwrap();
        drop(w);
        out
    }))
}

async fn view_html() -> Response {
    html_response(template(include_str!("../assets/moby.html")))
}

async fn robots() -> Response {
    plain_text_response(200, ROBOT_TXT)
}

async fn deny() -> Response {
    plain_text_response(200, ANGRY_ASCII)
}

async fn view_xml() -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/xml")
        .body(Body::from(template(include_str!("../assets/sample.xml"))))
        .unwrap()
}

async fn json_doc() -> Response {
    jsonify(obj(&[(
        "slideshow",
        obj(&[
            ("title", s("Sample Slide Show")),
            ("date", s("date of publication")),
            ("author", s("Yours Truly")),
            (
                "slides",
                Value::Array(vec![
                    obj(&[
                        ("type", s("all")),
                        ("title", s("Wake up to WonderWidgets!")),
                    ]),
                    obj(&[
                        ("type", s("all")),
                        ("title", s("Overview")),
                        (
                            "items",
                            Value::Array(vec![
                                s("Why <em>WonderWidgets</em> are great"),
                                s("Who <em>buys</em> WonderWidgets"),
                            ]),
                        ),
                    ]),
                ]),
            ),
        ]),
    )]))
}

async fn utf8() -> Response {
    html_response(template(include_str!("../assets/UTF-8-demo.txt")))
}

async fn forms_post() -> Response {
    html_response(template(include_str!("../assets/forms-post.html")))
}

// ---------------------------------------------------------------------------
// Redirects
// ---------------------------------------------------------------------------

async fn redirect_n(Path(n): Path<String>, req: Request) -> Result<Response, Response> {
    let Ok(n) = n.parse::<u32>() else {
        return Ok(not_found());
    };
    if n == 0 {
        return Ok(internal_error());
    }
    let args = parse_query(req.uri().query().unwrap_or(""));
    let absolute = arg(&args, "absolute") == Some("true");
    let host = host_of(&req);
    if n == 1 {
        let loc = if absolute {
            format!("http://{host}/get")
        } else {
            "/get".to_string()
        };
        return Ok(redirect(&loc));
    }
    let loc = if absolute {
        format!("http://{host}/absolute-redirect/{}", n - 1)
    } else {
        format!("/relative-redirect/{}", n - 1)
    };
    Ok(redirect(&loc))
}

async fn relative_redirect_n(Path(n): Path<String>) -> Result<Response, Response> {
    let Ok(n) = n.parse::<u32>() else {
        return Ok(not_found());
    };
    if n == 0 {
        return Ok(internal_error());
    }
    let loc = if n == 1 {
        "/get".to_string()
    } else {
        format!("/relative-redirect/{}", n - 1)
    };
    Ok(redirect(&loc))
}

async fn absolute_redirect_n(Path(n): Path<String>, req: Request) -> Result<Response, Response> {
    let Ok(n) = n.parse::<u32>() else {
        return Ok(not_found());
    };
    if n == 0 {
        return Ok(internal_error());
    }
    let host = host_of(&req);
    let loc = if n == 1 {
        format!("http://{host}/get")
    } else {
        format!("http://{host}/absolute-redirect/{}", n - 1)
    };
    Ok(redirect(&loc))
}

async fn redirect_to(req: Request) -> Response {
    let args = parse_query(req.uri().query().unwrap_or(""));
    let Some(url) = ci_arg(&args, "url").map(String::from) else {
        return internal_error();
    };
    let status = ci_arg(&args, "status_code")
        .and_then(|s| s.parse::<u16>().ok())
        .filter(|c| (300..400).contains(c))
        .unwrap_or(302);
    Response::builder()
        .status(StatusCode::from_u16(status).unwrap())
        .header(header::LOCATION, url)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(Body::empty())
        .unwrap()
}

fn host_of(req: &Request) -> String {
    req.headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .unwrap_or_else(|| "localhost".into())
}

// ---------------------------------------------------------------------------
// Status codes
// ---------------------------------------------------------------------------

async fn status(Path(codes): Path<String>) -> Response {
    if !codes.contains(',') {
        let Ok(code) = codes.parse::<u16>() else {
            return text_response(400, "Invalid status code");
        };
        return status_response(code);
    }
    let mut choices = vec![];
    for c in codes.split(',') {
        let (code, weight) = match c.split_once(':') {
            Some((a, b)) => (a, b),
            None => (c, "1"),
        };
        match (code.parse::<u16>(), weight.parse::<f64>()) {
            (Ok(c), Ok(w)) => choices.push((c, w)),
            _ => return text_response(400, "Invalid status code"),
        }
    }
    let total: f64 = choices.iter().map(|(_, w)| w).sum();
    let mut point = rand::rng().random_range(0.0..total);
    for (c, w) in &choices {
        if point <= *w {
            return status_response(*c);
        }
        point -= w;
    }
    status_response(choices.last().map(|(c, _)| *c).unwrap_or(200))
}

async fn response_headers(req: Request) -> Response {
    let args = parse_query(req.uri().query().unwrap_or(""));
    let mut body_len = 0usize;
    let body = loop {
        let mut d = Map::new();
        d.insert("Content-Length".into(), s(body_len.to_string()));
        d.insert("Content-Type".into(), s("application/json"));
        let mut grouped: Vec<(String, Vec<String>)> = vec![];
        for (k, v) in &args {
            match grouped.iter_mut().find(|(g, _)| g == k) {
                Some((_, vals)) => vals.push(v.clone()),
                None => grouped.push((k.clone(), vec![v.clone()])),
            }
        }
        for (k, vals) in grouped {
            let v = if vals.len() == 1 {
                s(vals.into_iter().next().unwrap())
            } else {
                Value::Array(vals.into_iter().map(s).collect())
            };
            d.insert(k, v);
        }
        let body = format!("{}\n", pretty(&Value::Object(d), 0));
        if body.len() == body_len {
            break body;
        }
        body_len = body.len();
    };
    let mut b = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json");
    for (k, v) in &args {
        if let (Ok(name), Ok(val)) = (
            header::HeaderName::try_from(k.as_str()),
            HeaderValue::from_str(v),
        ) {
            b = b.header(name, val);
        }
    }
    b.body(Body::from(body)).unwrap()
}

// ---------------------------------------------------------------------------
// Cookies
// ---------------------------------------------------------------------------

fn parse_cookies(headers: &HeaderMap) -> Vec<(String, String)> {
    let mut out = vec![];
    for v in headers.get_all(header::COOKIE) {
        if let Ok(sv) = v.to_str() {
            for part in sv.split(';') {
                let part = part.trim();
                if let Some((k, val)) = part.split_once('=') {
                    let val = val.trim();
                    let val = val
                        .strip_prefix('"')
                        .and_then(|v| v.strip_suffix('"'))
                        .unwrap_or(val);
                    out.push((urldecode(k.trim(), false), urldecode(val, false)));
                }
            }
        }
    }
    out
}

async fn cookies(req: Request) -> Response {
    let show_env = arg(&parse_query(req.uri().query().unwrap_or("")), "show_env").is_some();
    let mut m = Map::new();
    for (k, v) in parse_cookies(req.headers()) {
        if !show_env && ENV_COOKIES.contains(&k.as_str()) {
            continue;
        }
        m.insert(k, s(v));
    }
    jsonify(obj(&[("cookies", Value::Object(m))]))
}

async fn set_cookie_one(Path((name, value)): Path<(String, String)>) -> Response {
    let mut r = redirect("/cookies");
    set_cookie_hdr(&mut r, &name, &value);
    r
}

async fn set_cookies(req: Request) -> Response {
    let args = parse_query(req.uri().query().unwrap_or(""));
    let mut r = redirect("/cookies");
    for (k, v) in args {
        set_cookie_hdr(&mut r, &k, &v);
    }
    r
}

async fn delete_cookies(req: Request) -> Response {
    let args = parse_query(req.uri().query().unwrap_or(""));
    let mut r = redirect("/cookies");
    for (k, _) in args {
        delete_cookie_hdr(&mut r, &k);
    }
    r
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

fn check_basic(headers: &HeaderMap, user: &str, passwd: &str) -> bool {
    let Some(auth) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    let Some(b64) = auth.strip_prefix("Basic ") else {
        return false;
    };
    let Some(decoded) = STANDARD
        .decode(b64.trim())
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
    else {
        return false;
    };
    match decoded.split_once(':') {
        Some((u, p)) => u == user && p == passwd,
        None => false,
    }
}

async fn basic_auth(Path((user, passwd)): Path<(String, String)>, req: Request) -> Response {
    if !check_basic(req.headers(), &user, &passwd) {
        return status_response(401);
    }
    jsonify(obj(&[
        ("authenticated", Value::Bool(true)),
        ("user", s(&user)),
    ]))
}

async fn hidden_basic_auth(Path((user, passwd)): Path<(String, String)>, req: Request) -> Response {
    if !check_basic(req.headers(), &user, &passwd) {
        return status_response(404);
    }
    jsonify(obj(&[
        ("authenticated", Value::Bool(true)),
        ("user", s(&user)),
    ]))
}

async fn bearer(req: Request) -> Response {
    let auth = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    match auth.filter(|a| a.starts_with("Bearer ")) {
        Some(a) => jsonify(obj(&[
            ("authenticated", Value::Bool(true)),
            ("token", s(&a["Bearer ".len()..])),
        ])),
        None => Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("WWW-Authenticate", "Bearer")
            .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
            .body(Body::empty())
            .unwrap(),
    }
}

// --- Digest auth ---

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn digest_h(data: &[u8], algorithm: &str) -> String {
    match algorithm {
        "SHA-256" => to_hex(&Sha256::digest(data)),
        "SHA-512" => to_hex(&Sha512::digest(data)),
        _ => to_hex(&Md5::digest(data)),
    }
}

#[derive(Default)]
struct DigestCreds {
    username: Option<String>,
    realm: Option<String>,
    nonce: Option<String>,
    uri: Option<String>,
    qop: Option<String>,
    nc: Option<String>,
    cnonce: Option<String>,
    response: Option<String>,
    algorithm: Option<String>,
}

fn split_params(s: &str) -> Vec<String> {
    let mut out = vec![];
    let mut cur = String::new();
    let mut in_q = false;
    let mut esc = false;
    for c in s.chars() {
        if esc {
            cur.push(c);
            esc = false;
        } else if c == '\\' && in_q {
            cur.push(c);
            esc = true;
        } else if c == '"' {
            in_q = !in_q;
            cur.push(c);
        } else if c == ',' && !in_q {
            out.push(std::mem::take(&mut cur));
        } else {
            cur.push(c);
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out
}

fn parse_digest(header: &str) -> Option<DigestCreds> {
    let rest = if header.len() >= 6 && header[..6].eq_ignore_ascii_case("Digest") {
        &header[6..]
    } else {
        return None;
    };
    let mut c = DigestCreds::default();
    for part in split_params(rest) {
        let Some((k, v)) = part.split_once('=') else {
            continue;
        };
        let v = v.trim().trim_matches('"').to_string();
        match k.trim().to_ascii_lowercase().as_str() {
            "username" => c.username = Some(v),
            "realm" => c.realm = Some(v),
            "nonce" => c.nonce = Some(v),
            "uri" => c.uri = Some(v),
            "qop" => c.qop = Some(v),
            "nc" => c.nc = Some(v),
            "cnonce" => c.cnonce = Some(v),
            "response" => c.response = Some(v),
            "algorithm" => c.algorithm = Some(v),
            _ => {}
        }
    }
    Some(c)
}

fn next_stale_after(v: &str) -> String {
    v.trim()
        .parse::<i64>()
        .map(|n| (n - 1).to_string())
        .unwrap_or_else(|_| "never".into())
}

fn digest_challenge(algorithm: &str, qop: Option<&str>, stale: bool, ip: &str) -> Response {
    let mut rnd = [0u8; 10];
    rand::rng().fill_bytes(&mut rnd);
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();
    let mut nonce_input = format!("{ip}:{time}:").into_bytes();
    nonce_input.extend_from_slice(&rnd);
    let nonce = digest_h(&nonce_input, algorithm);
    let opaque = digest_h(&rnd, algorithm);
    let qop_v = qop.unwrap_or("auth, auth-int");
    let www = format!(
        "Digest realm=\"{REALM}\", nonce=\"{nonce}\", qop=\"{qop_v}\", \
         opaque=\"{opaque}\", algorithm={algorithm}, stale={}",
        if stale { "TRUE" } else { "FALSE" }
    );
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("WWW-Authenticate", www)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(Body::empty())
        .unwrap()
}

fn check_digest(creds: &DigestCreds, passwd: &str, method: &str, uri: &str, body: &[u8]) -> bool {
    let algorithm = creds.algorithm.as_deref().unwrap_or("MD5");
    let ha1 = digest_h(
        format!(
            "{}:{}:{}",
            creds.username.as_deref().unwrap_or(""),
            creds.realm.as_deref().unwrap_or(""),
            passwd
        )
        .as_bytes(),
        algorithm,
    );
    let ha2 = match creds.qop.as_deref() {
        None | Some("auth") => digest_h(format!("{method}:{uri}").as_bytes(), algorithm),
        Some("auth-int") => digest_h(
            format!("{method}:{uri}:{}", digest_h(body, algorithm)).as_bytes(),
            algorithm,
        ),
        Some(_) => return false,
    };
    let expected = match creds.qop.as_deref() {
        None => digest_h(
            format!("{ha1}:{}:{ha2}", creds.nonce.as_deref().unwrap_or("")).as_bytes(),
            algorithm,
        ),
        Some(q) if q == "auth" || q == "auth-int" => digest_h(
            format!(
                "{ha1}:{}:{}:{}:{q}:{ha2}",
                creds.nonce.as_deref().unwrap_or(""),
                creds.nc.as_deref().unwrap_or(""),
                creds.cnonce.as_deref().unwrap_or("")
            )
            .as_bytes(),
            algorithm,
        ),
        Some(_) => return false,
    };
    creds.response.as_deref() == Some(expected.as_str())
}

#[allow(clippy::too_many_arguments)]
async fn digest_auth_handler(
    qop: String,
    user: String,
    passwd: String,
    algorithm: String,
    stale_after: String,
    addr: SocketAddr,
    req: Request,
) -> Response {
    let algorithm = if matches!(algorithm.as_str(), "MD5" | "SHA-256" | "SHA-512") {
        algorithm
    } else {
        "MD5".to_string()
    };
    let qop = if matches!(qop.as_str(), "auth" | "auth-int") {
        Some(qop)
    } else {
        None
    };
    let args = parse_query(req.uri().query().unwrap_or(""));
    let require_cookie = matches!(
        arg(&args, "require-cookie")
            .map(str::to_lowercase)
            .as_deref(),
        Some("1" | "t" | "true")
    );
    let cookies = parse_cookies(req.headers());
    let cookie = |name: &str| -> Option<&str> {
        cookies
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    };

    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let credentials = auth_header.and_then(parse_digest);

    if credentials.is_none() || (require_cookie && !req.headers().contains_key(header::COOKIE)) {
        let mut r = digest_challenge(&algorithm, qop.as_deref(), false, &addr.ip().to_string());
        set_cookie_hdr(&mut r, "stale_after", &stale_after);
        set_cookie_hdr(&mut r, "fake", "fake_value");
        return r;
    }
    let creds = credentials.unwrap();

    if require_cookie && cookie("fake") != Some("fake_value") {
        let mut r = jsonify(obj(&[(
            "errors",
            Value::Array(vec![s("missing cookie set on challenge")]),
        )]))
        .with_status(403);
        set_cookie_hdr(&mut r, "fake", "fake_value");
        return r;
    }

    let current_nonce = creds.nonce.clone().unwrap_or_default();
    let stale_after_value = cookie("stale_after").map(String::from);

    if (cookie("last_nonce").is_some() && cookie("last_nonce") == Some(current_nonce.as_str()))
        || stale_after_value.as_deref() == Some("0")
    {
        let mut r = digest_challenge(&algorithm, qop.as_deref(), true, &addr.ip().to_string());
        set_cookie_hdr(&mut r, "stale_after", &stale_after);
        set_cookie_hdr(&mut r, "last_nonce", &current_nonce);
        set_cookie_hdr(&mut r, "fake", "fake_value");
        return r;
    }

    let uri = format!(
        "{}{}",
        req.uri().path(),
        req.uri()
            .query()
            .map(|q| format!("?{q}"))
            .unwrap_or_default()
    );
    let method = req.method().as_str().to_string();
    let body = to_bytes(req.into_body(), MAX_BODY)
        .await
        .unwrap_or_default();
    if !check_digest(&creds, &passwd, &method, &uri, &body) {
        let mut r = digest_challenge(&algorithm, qop.as_deref(), false, &addr.ip().to_string());
        set_cookie_hdr(&mut r, "stale_after", &stale_after);
        set_cookie_hdr(&mut r, "last_nonce", &current_nonce);
        set_cookie_hdr(&mut r, "fake", "fake_value");
        return r;
    }

    let mut r = jsonify(obj(&[
        ("authenticated", Value::Bool(true)),
        ("user", s(&user)),
    ]));
    set_cookie_hdr(&mut r, "fake", "fake_value");
    if let Some(sa) = stale_after_value {
        set_cookie_hdr(&mut r, "stale_after", &next_stale_after(&sa));
    }
    r
}

async fn digest_auth_3(
    Path((qop, user, passwd)): Path<(String, String, String)>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    digest_auth_handler(qop, user, passwd, "MD5".into(), "never".into(), addr, req).await
}

async fn digest_auth_4(
    Path((qop, user, passwd, algorithm)): Path<(String, String, String, String)>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    digest_auth_handler(qop, user, passwd, algorithm, "never".into(), addr, req).await
}

async fn digest_auth_5(
    Path((qop, user, passwd, algorithm, stale_after)): Path<(
        String,
        String,
        String,
        String,
        String,
    )>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    digest_auth_handler(qop, user, passwd, algorithm, stale_after, addr, req).await
}

// ---------------------------------------------------------------------------
// Dynamic data
// ---------------------------------------------------------------------------

async fn stream_n(
    Path(n): Path<String>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
) -> Result<Response, Response> {
    let Ok(n) = n.parse::<u32>() else {
        return Ok(not_found());
    };
    let n = n.min(100);
    let info = req_info(req, addr).await?;
    let stream = async_stream::stream! {
        for i in 0..n {
            let mut m = match dict(&info, &["url", "args", "headers", "origin"]) {
                Value::Object(m) => m,
                _ => unreachable!(),
            };
            m.insert("id".into(), Value::Number(i.into()));
            yield Ok::<Bytes, std::convert::Infallible>(Bytes::from(format!(
                "{}\n",
                compact(&Value::Object(m))
            )));
        }
    };
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from_stream(stream))
        .unwrap())
}

async fn delay(
    Path(d): Path<String>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
) -> Result<Response, Response> {
    let Ok(d) = d.parse::<f64>() else {
        return Ok(internal_error());
    };
    if d.is_nan() || d < 0.0 {
        return Ok(internal_error());
    }
    tokio::time::sleep(Duration::from_secs_f64(d.min(10.0))).await;
    let info = req_info(req, addr).await?;
    Ok(jsonify(dict(
        &info,
        &["url", "args", "form", "data", "origin", "headers", "files"],
    )))
}

async fn drip(req: Request) -> Response {
    let args = parse_query(req.uri().query().unwrap_or(""));
    let f = |name: &str, default: f64| -> Result<f64, Response> {
        match ci_arg(&args, name) {
            Some(v) => v.trim().parse::<f64>().map_err(|_| internal_error()),
            None => Ok(default),
        }
    };
    let i = |name: &str, default: i64| -> Result<i64, Response> {
        match ci_arg(&args, name) {
            Some(v) => v.trim().parse::<i64>().map_err(|_| internal_error()),
            None => Ok(default),
        }
    };
    let Ok(duration) = f("duration", 2.0) else {
        return internal_error();
    };
    let Ok(numbytes) = i("numbytes", 10).map(|n| n.min(10 * 1024 * 1024)) else {
        return internal_error();
    };
    let Ok(code) = i("code", 200) else {
        return internal_error();
    };
    let Ok(delay) = f("delay", 0.0) else {
        return internal_error();
    };
    if numbytes <= 0 {
        return text_response(400, "number of bytes must be positive");
    }
    if delay > 0.0 {
        tokio::time::sleep(Duration::from_secs_f64(delay)).await;
    }
    let pause = duration / numbytes as f64;
    let status = StatusCode::from_u16(u16::try_from(code).unwrap_or(0))
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let stream = async_stream::stream! {
        for _ in 0..numbytes {
            yield Ok::<Bytes, std::convert::Infallible>(Bytes::from_static(b"*"));
            if pause > 0.0 {
                tokio::time::sleep(Duration::from_secs_f64(pause)).await;
            }
        }
    };
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_LENGTH, numbytes.to_string())
        .body(Body::from_stream(stream))
        .unwrap()
}

async fn base64(Path(value): Path<String>) -> Response {
    match URL_SAFE
        .decode(value.as_bytes())
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
    {
        Some(decoded) => text_response(200, &decoded),
        None => text_response(200, "Incorrect Base64 data try: SFRUUEJJTiBpcyBhd2Vzb21l"),
    }
}

async fn cache(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
) -> Result<Response, Response> {
    let conditional = req
        .headers()
        .contains_key("If-Modified-Since")
        .then_some(())
        .or_else(|| req.headers().contains_key("If-None-Match").then_some(()));
    if conditional.is_some() {
        return Ok(status_response(304));
    }
    let info = req_info(req, addr).await?;
    let mut r = jsonify(dict(&info, &["url", "args", "headers", "origin"]));
    if let Ok(v) = HeaderValue::from_str(&http_date_now()) {
        r.headers_mut().insert("Last-Modified", v);
    }
    r.headers_mut().insert(
        "ETag",
        HeaderValue::from_str(&Uuid::new_v4().simple().to_string()).unwrap(),
    );
    Ok(r)
}

fn parse_multi(h: &str) -> Vec<String> {
    h.split(',')
        .map(|p| {
            let p = p.trim();
            let p = p.strip_prefix("W/").unwrap_or(p);
            p.trim().trim_matches('"').to_string()
        })
        .collect()
}

async fn etag(
    Path(etag): Path<String>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
) -> Result<Response, Response> {
    let if_none_match = req
        .headers()
        .get("If-None-Match")
        .and_then(|v| v.to_str().ok())
        .map(parse_multi);
    let if_match = req
        .headers()
        .get("If-Match")
        .and_then(|v| v.to_str().ok())
        .map(parse_multi);

    let etag_hdr = |r: &mut Response| {
        if let Ok(v) = HeaderValue::from_str(&etag) {
            r.headers_mut().insert("ETag", v);
        }
    };

    if let Some(inm) = &if_none_match {
        if inm.contains(&etag) || inm.contains(&"*".to_string()) {
            let mut r = status_response(304);
            etag_hdr(&mut r);
            return Ok(r);
        }
    } else if let Some(ifm) = &if_match
        && !ifm.contains(&etag)
        && !ifm.contains(&"*".to_string())
    {
        return Ok(status_response(412));
    }

    let info = req_info(req, addr).await?;
    let mut r = jsonify(dict(&info, &["url", "args", "headers", "origin"]));
    etag_hdr(&mut r);
    Ok(r)
}

async fn cache_control(
    Path(value): Path<String>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
) -> Result<Response, Response> {
    let Ok(value) = value.parse::<i64>() else {
        return Ok(not_found());
    };
    let info = req_info(req, addr).await?;
    let mut r = jsonify(dict(&info, &["url", "args", "headers", "origin"]));
    if let Ok(v) = HeaderValue::from_str(&format!("public, max-age={value}")) {
        r.headers_mut().insert("Cache-Control", v);
    }
    Ok(r)
}

async fn bytes_n(Path(n): Path<String>, req: Request) -> Result<Response, Response> {
    let Ok(n) = n.parse::<u32>() else {
        return Ok(not_found());
    };
    let n = n.min(100 * 1024) as usize;
    let args = parse_query(req.uri().query().unwrap_or(""));
    let mut data = vec![0u8; n];
    match ci_arg(&args, "seed") {
        Some(seed) => {
            let Ok(seed) = seed.trim().parse::<i64>() else {
                return Ok(internal_error());
            };
            StdRng::seed_from_u64(seed as u64).fill_bytes(&mut data);
        }
        None => rand::rng().fill_bytes(&mut data),
    }
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(Body::from(data))
        .unwrap())
}

async fn stream_bytes(Path(n): Path<String>, req: Request) -> Result<Response, Response> {
    let Ok(n) = n.parse::<u32>() else {
        return Ok(not_found());
    };
    let n = n.min(100 * 1024);
    let args = parse_query(req.uri().query().unwrap_or(""));
    let seed = ci_arg(&args, "seed").map(String::from);
    let chunk_size = match ci_arg(&args, "chunk_size") {
        Some(cs) => {
            let Ok(cs) = cs.trim().parse::<i64>() else {
                return Ok(internal_error());
            };
            cs.max(1) as usize
        }
        None => 10 * 1024,
    };
    let stream = async_stream::stream! {
        let mut rng = match seed {
            Some(s) => match s.trim().parse::<i64>() {
                Ok(v) => StdRng::seed_from_u64(v as u64),
                Err(_) => { yield Err(std::io::Error::other("bad seed")); return; }
            },
            None => StdRng::seed_from_u64(rand::rng().random()),
        };
        let mut remaining = n;
        while remaining > 0 {
            let take = remaining.min(chunk_size as u32);
            let mut buf = vec![0u8; take as usize];
            rng.fill_bytes(&mut buf);
            yield Ok::<Bytes, std::io::Error>(Bytes::from(buf));
            remaining -= take;
        }
    };
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(Body::from_stream(stream))
        .unwrap())
}

fn parse_range_header(txt: Option<&str>) -> (Option<i64>, Option<i64>) {
    let Some(t) = txt else { return (None, None) };
    let t = t.trim();
    if !t.starts_with("bytes") {
        return (None, None);
    }
    let Some((_, spec)) = t.split_once('=') else {
        return (None, None);
    };
    let parts: Vec<&str> = spec.split('-').collect();
    let right = parts.get(1).and_then(|s| s.trim().parse::<i64>().ok());
    let left = parts.first().and_then(|s| s.trim().parse::<i64>().ok());
    (left, right)
}

fn get_request_range(h: Option<&str>, upper: u32) -> (i64, i64) {
    let (left, right) = parse_range_header(h);
    match (left, right) {
        (None, None) => (0, upper as i64 - 1),
        (None, Some(r)) => ((upper as i64 - r).max(0), upper as i64 - 1),
        (Some(l), None) => (l, upper as i64 - 1),
        (Some(l), Some(r)) => (l, r),
    }
}

async fn range(Path(numbytes): Path<String>, req: Request) -> Result<Response, Response> {
    let Ok(numbytes) = numbytes.parse::<u32>() else {
        return Ok(not_found());
    };
    if numbytes == 0 || numbytes > 100 * 1024 {
        return Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header("ETag", format!("range{numbytes}"))
            .header("Accept-Ranges", "bytes")
            .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
            .body(Body::from(
                "number of bytes must be in the range (0, 102400]",
            ))
            .unwrap());
    }
    let args = parse_query(req.uri().query().unwrap_or(""));
    let chunk_size = match ci_arg(&args, "chunk_size") {
        Some(cs) => {
            let Ok(cs) = cs.trim().parse::<i64>() else {
                return Ok(internal_error());
            };
            cs.max(1) as usize
        }
        None => 10 * 1024,
    };
    let duration = match ci_arg(&args, "duration") {
        Some(d) => {
            let Ok(d) = d.trim().parse::<f64>() else {
                return Ok(internal_error());
            };
            d
        }
        None => 0.0,
    };
    let range_hdr = req
        .headers()
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok());
    let (first, last) = get_request_range(range_hdr, numbytes);
    if first > last || first < 0 || first >= numbytes as i64 || last >= numbytes as i64 {
        return Ok(Response::builder()
            .status(StatusCode::RANGE_NOT_SATISFIABLE)
            .header("ETag", format!("range{numbytes}"))
            .header("Accept-Ranges", "bytes")
            .header("Content-Range", format!("bytes */{numbytes}"))
            .header(header::CONTENT_LENGTH, "0")
            .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
            .body(Body::empty())
            .unwrap());
    }
    let pause = duration / numbytes as f64;
    let stream = async_stream::stream! {
        let mut i = first;
        while i <= last {
            let take = ((last - i + 1) as usize).min(chunk_size);
            let bytes: Vec<u8> = (i..i + take as i64)
                .map(|j| b'a' + (j % 26) as u8)
                .collect();
            yield Ok::<Bytes, std::convert::Infallible>(Bytes::from(bytes));
            i += take as i64;
            if pause > 0.0 {
                tokio::time::sleep(Duration::from_secs_f64(pause * take as f64)).await;
            }
        }
    };
    let status = if first == 0 && last == numbytes as i64 - 1 {
        StatusCode::OK
    } else {
        StatusCode::PARTIAL_CONTENT
    };
    Ok(Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header("ETag", format!("range{numbytes}"))
        .header("Accept-Ranges", "bytes")
        .header(header::CONTENT_LENGTH, (last - first + 1).to_string())
        .header("Content-Range", format!("bytes {first}-{last}/{numbytes}"))
        .body(Body::from_stream(stream))
        .unwrap())
}

async fn links(Path(n): Path<String>) -> Result<Response, Response> {
    let Ok(n) = n.parse::<u32>() else {
        return Ok(not_found());
    };
    Ok(redirect(&format!("/links/{n}/0")))
}

async fn link_page(Path((n, offset)): Path<(String, String)>) -> Result<Response, Response> {
    let (Ok(n), Ok(offset)) = (n.parse::<u32>(), offset.parse::<u32>()) else {
        return Ok(not_found());
    };
    let n = n.clamp(1, 200);
    let mut html = String::from("<html><head><title>Links</title></head><body>");
    for i in 0..n {
        if i == offset {
            html.push_str(&format!("{i} "));
        } else {
            html.push_str(&format!("<a href='/links/{n}/{i}'>{i}</a> "));
        }
    }
    html.push_str("</body></html>");
    Ok(html_response(html))
}

// ---------------------------------------------------------------------------
// Images
// ---------------------------------------------------------------------------

fn img(ct: &'static str, data: &'static [u8]) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, ct)
        .body(Body::from(Bytes::from_static(data)))
        .unwrap()
}

async fn image_png() -> Response {
    img("image/png", include_bytes!("../assets/images/pig_icon.png"))
}

async fn image_jpeg() -> Response {
    img("image/jpeg", include_bytes!("../assets/images/jackal.jpg"))
}

async fn image_webp() -> Response {
    img("image/webp", include_bytes!("../assets/images/wolf_1.webp"))
}

async fn image_svg() -> Response {
    img(
        "image/svg+xml",
        include_bytes!("../assets/images/svg_logo.svg"),
    )
}

async fn image(req: Request) -> Response {
    let Some(accept) = req
        .headers()
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_lowercase())
    else {
        return image_png().await;
    };
    if accept.contains("image/webp") {
        image_webp().await
    } else if accept.contains("image/svg+xml") {
        image_svg().await
    } else if accept.contains("image/jpeg") {
        image_jpeg().await
    } else if accept.contains("image/png") || accept.contains("image/*") {
        image_png().await
    } else {
        status_response(406)
    }
}

// ---------------------------------------------------------------------------
// CORS middleware (after_request equivalent)
// ---------------------------------------------------------------------------

async fn cors(req: Request, next: Next) -> Response {
    let origin = req.headers().get(header::ORIGIN).cloned();
    let req_hdrs = req.headers().get("access-control-request-headers").cloned();
    if req.method() == "OPTIONS" {
        // Flask auto-handles OPTIONS for every route: 200 + Allow.
        let mut res = Response::builder()
            .status(StatusCode::OK)
            .header(
                header::ALLOW,
                "HEAD, GET, POST, PUT, DELETE, PATCH, OPTIONS",
            )
            .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
            .body(Body::empty())
            .unwrap();
        apply_cors(&mut res, origin, req_hdrs, true);
        return res;
    }
    let mut res = next.run(req).await;
    apply_cors(&mut res, origin, req_hdrs, false);
    res
}

fn apply_cors(
    res: &mut Response,
    origin: Option<HeaderValue>,
    req_hdrs: Option<HeaderValue>,
    options: bool,
) {
    let h = res.headers_mut();
    h.insert(
        "Access-Control-Allow-Origin",
        origin.unwrap_or(HeaderValue::from_static("*")),
    );
    h.insert(
        "Access-Control-Allow-Credentials",
        HeaderValue::from_static("true"),
    );
    if options {
        h.insert(
            "Access-Control-Allow-Methods",
            HeaderValue::from_static("GET, POST, PUT, DELETE, PATCH, OPTIONS"),
        );
        h.insert("Access-Control-Max-Age", HeaderValue::from_static("3600"));
        if let Some(rh) = req_hdrs {
            h.insert("Access-Control-Allow-Headers", rh);
        }
    }
}

async fn fallback_404() -> Response {
    not_found()
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

fn http_methods() -> MethodFilter {
    MethodFilter::GET
        .or(MethodFilter::POST)
        .or(MethodFilter::PUT)
        .or(MethodFilter::DELETE)
        .or(MethodFilter::PATCH)
        .or(MethodFilter::TRACE)
}

fn router() -> Router {
    Router::new()
        .route("/ip", get(ip))
        .route("/uuid", get(view_uuid))
        .route("/headers", get(view_headers))
        .route("/user-agent", get(user_agent))
        .route("/get", get(view_get))
        .route("/anything", on(http_methods(), anything))
        .route("/anything/{*anything}", on(http_methods(), anything))
        .route("/post", post(post_))
        .route("/put", put(put_))
        .route("/patch", patch(patch_))
        .route("/delete", delete(delete_))
        .route("/gzip", get(gzip))
        .route("/deflate", get(deflate))
        .route("/brotli", get(brotli))
        .route("/redirect/{n}", get(redirect_n))
        .route("/redirect-to", on(http_methods(), redirect_to))
        .route("/relative-redirect/{n}", get(relative_redirect_n))
        .route("/absolute-redirect/{n}", get(absolute_redirect_n))
        .route("/stream/{n}", get(stream_n))
        .route("/status/{codes}", on(http_methods(), status))
        .route(
            "/response-headers",
            get(response_headers).post(response_headers),
        )
        .route("/cookies", get(cookies))
        .route("/forms/post", get(forms_post))
        .route("/cookies/set/{name}/{value}", get(set_cookie_one))
        .route("/cookies/set", get(set_cookies))
        .route("/cookies/delete", get(delete_cookies))
        .route("/basic-auth/{user}/{passwd}", get(basic_auth))
        .route("/hidden-basic-auth/{user}/{passwd}", get(hidden_basic_auth))
        .route("/bearer", get(bearer))
        .route("/digest-auth/{qop}/{user}/{passwd}", get(digest_auth_3))
        .route(
            "/digest-auth/{qop}/{user}/{passwd}/{algorithm}",
            get(digest_auth_4),
        )
        .route(
            "/digest-auth/{qop}/{user}/{passwd}/{algorithm}/{stale_after}",
            get(digest_auth_5),
        )
        .route("/delay/{delay}", on(http_methods(), delay))
        .route("/drip", get(drip))
        .route("/base64/{value}", get(base64))
        .route("/cache", get(cache))
        .route("/etag/{etag}", get(etag))
        .route("/cache/{value}", get(cache_control))
        .route("/encoding/utf8", get(utf8))
        .route("/bytes/{n}", get(bytes_n))
        .route("/stream-bytes/{n}", get(stream_bytes))
        .route("/range/{numbytes}", get(range))
        .route("/links/{n}", get(links))
        .route("/links/{n}/{offset}", get(link_page))
        .route("/image", get(image))
        .route("/image/png", get(image_png))
        .route("/image/jpeg", get(image_jpeg))
        .route("/image/webp", get(image_webp))
        .route("/image/svg", get(image_svg))
        .route("/xml", get(view_xml))
        .route("/json", get(json_doc))
        .route("/html", get(view_html))
        .route("/robots.txt", get(robots))
        .route("/deny", get(deny))
        .fallback(fallback_404)
        .layer(middleware::from_fn(cors))
}

#[tokio::main]
async fn main() {
    let host = std::env::var("HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(5000);
    let app = router();
    let listener = tokio::net::TcpListener::bind((host.as_str(), port))
        .await
        .unwrap();
    println!("Listening on http://{host}:{port}");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}
