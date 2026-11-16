//! A deliberately small HTTP/1.1 server, pure std, thread-per-
//! connection — ported from the Waterfront (harbor-portal). The board
//! never dials out.
//!
//! Admission law: bound to loopback, no token is required (the machine
//! is the boundary). Bound beyond loopback (--lan), a bearer token is
//! required on every request, carried in headers only — the ?token=
//! query parameter is refused (it leaks into history and logs).

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

pub const MAX_BODY: usize = 32 * 1024 * 1024 + 4096;

#[derive(Debug)]
pub struct Request {
    pub method: String,
    pub path: String,     // percent-decoded, without query
    pub raw_target: String,
    pub query: HashMap<String, String>,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

pub struct Response {
    pub status: u16,
    pub content_type: String,
    pub body: Vec<u8>,
    pub headers: Vec<(String, String)>,
}

impl Response {
    pub fn json(status: u16, body: String) -> Response {
        Response { status, content_type: "application/json; charset=utf-8".into(), body: body.into_bytes(), headers: vec![] }
    }
    pub fn text(status: u16, body: String) -> Response {
        Response { status, content_type: "text/plain; charset=utf-8".into(), body: body.into_bytes(), headers: vec![] }
    }
    pub fn new_html(body: String) -> Response {
        Response { status: 200, content_type: "text/html; charset=utf-8".into(), body: body.into_bytes(), headers: vec![] }
    }
    pub fn new_md(body: String) -> Response {
        Response { status: 200, content_type: "text/markdown; charset=utf-8".into(), body: body.into_bytes(), headers: vec![] }
    }
    pub fn new_text(body: &str, content_type: &str) -> Response {
        Response { status: 200, content_type: content_type.into(), body: body.as_bytes().to_vec(), headers: vec![] }
    }
    pub fn with_status(mut self, status: u16) -> Response {
        self.status = status;
        self
    }
    pub fn binary(status: u16, content_type: &str, body: Vec<u8>, name: &str) -> Response {
        Response {
            status,
            content_type: content_type.to_string(),
            body,
            headers: vec![(
                "Content-Disposition".to_string(),
                format!("attachment; filename=\"{}\"", name.replace('"', "")),
            )],
        }
    }
}

pub fn status_text(code: u16) -> &'static str {
    match code {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        500 => "Internal Server Error",
        _ => "Status",
    }
}

pub type Handler = Arc<dyn Fn(&Request) -> Response + Send + Sync + 'static>;

/// The admission state: loopback mode (token None — the machine is the
/// boundary) or LAN mode (bearer token, headers only).
pub struct Admission {
    pub token: Option<String>,
    pub token_fp: Option<String>,
}

/// Run until the process is stopped. Binding is the caller's choice;
/// loopback is the default everywhere in this crate.
pub fn serve(addr: &str, admission: Admission, handler: Handler) -> Result<(), String> {
    let listener = TcpListener::bind(addr).map_err(|e| format!("bind {}: {}", addr, e))?;
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };
        let handler = handler.clone();
        let adm = Admission { token: admission.token.clone(), token_fp: admission.token_fp.clone() };
        std::thread::spawn(move || {
            let _ = handle_conn(stream, &adm, handler);
        });
    }
    Ok(())
}

fn handle_conn(stream: TcpStream, admission: &Admission, handler: Handler)
    -> Result<(), String> {
    let mut reader = BufReader::new(stream.try_clone().map_err(|e| e.to_string())?);
    loop {
        let req = match read_request(&mut reader) {
            Ok(Some(r)) => r,
            Ok(None) => return Ok(()), // closed
            Err(_) => return Ok(()),
        };
        // admission: in LAN mode every request carries the token, in
        // headers only — the query parameter is refused by law
        if let Some(tok) = admission.token.as_deref() {
            let ok = req
                .header("authorization")
                .map(|v| v == format!("Bearer {}", tok))
                .unwrap_or(false)
                || req.header("x-harbor-token").map(|v| v == tok).unwrap_or(false);
            if !ok {
                let resp = Response::json(
                    401,
                    r#"{"error":"unauthorized: token required (headers only)"}"#.into(),
                );
                write_response(&stream, &resp)?;
                return Ok(()); // close: no second chances on a refused token
            }
        }
        let resp = handler(&req);
        write_response(&stream, &resp)?;
        if req.header("connection").map(|v| v.eq_ignore_ascii_case("close")).unwrap_or(true) {
            return Ok(());
        }
    }
}

fn read_request(reader: &mut BufReader<TcpStream>) -> Result<Option<Request>, String> {
    let mut line = String::new();
    let n = reader.read_line(&mut line).map_err(|e| e.to_string())?;
    if n == 0 {
        return Ok(None);
    }
    let line = line.trim_end();
    if line.is_empty() {
        return Ok(None);
    }
    let mut parts = line.split_whitespace();
    let method = parts.next().ok_or("bad request line")?.to_string();
    let target = parts.next().ok_or("bad request line")?.to_string();
    let _version = parts.next().unwrap_or("HTTP/1.1");

    let mut headers = Vec::new();
    let mut content_length = 0usize;
    loop {
        let mut h = String::new();
        let n = reader.read_line(&mut h).map_err(|e| e.to_string())?;
        if n == 0 {
            return Ok(None);
        }
        let h = h.trim_end();
        if h.is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            let k = k.trim().to_string();
            let v = v.trim().to_string();
            if k.eq_ignore_ascii_case("content-length") {
                content_length = v.parse().map_err(|_| "bad content-length")?;
            }
            headers.push((k, v));
        }
        if headers.len() > 100 {
            return Err("too many headers".into());
        }
    }
    if content_length > MAX_BODY {
        return Err("body too large".into());
    }
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body).map_err(|e| e.to_string())?;
    }

    let (raw_path, raw_query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target.clone(), String::new()),
    };
    let path = percent_decode(&raw_path);
    let mut query = HashMap::new();
    for pair in raw_query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        query.insert(percent_decode(k), percent_decode(v));
    }
    Ok(Some(Request { method, path, raw_target: target, query, headers, body }))
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(slice) = std::str::from_utf8(&b[i + 1..i + 3]) {
                if let Ok(h) = u8::from_str_radix(slice, 16) {
                    out.push(h);
                    i += 3;
                    continue;
                }
            }
        }
        if b[i] == b'+' {
            out.push(b' ');
            i += 1;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn write_response(mut stream: &TcpStream, resp: &Response) -> Result<(), String> {
    let mut head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\n",
        resp.status,
        status_text(resp.status),
        resp.content_type,
        resp.body.len()
    );
    // the posture headers, on every response: nothing by default, no
    // framing, no referrer — the board never dials out
    head.push_str("Content-Security-Policy: default-src 'none'; style-src 'self'; img-src 'self'\r\n");
    head.push_str("X-Content-Type-Options: nosniff\r\n");
    head.push_str("X-Frame-Options: DENY\r\n");
    head.push_str("Referrer-Policy: no-referrer\r\nConnection: close\r\n");
    for (k, v) in &resp.headers {
        head.push_str(&format!("{}: {}\r\n", k, v));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).map_err(|e| e.to_string())?;
    stream.write_all(&resp.body).map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())?;
    Ok(())
}

// ---------- tests: in-process request/response over loopback ----------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};
    #[allow(unused_imports)]

    fn start(token: Option<&'static str>) -> (u16, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(s) = stream else { break };
                let t = token;
                let h: Handler = Arc::new(move |req: &Request| {
                    if req.path == "/api/echo" {
                        let body = String::from_utf8_lossy(&req.body).into_owned();
                        Response::json(200, format!("{{\"echo\":\"{}\"}}", body))
                    } else {
                        Response::text(404, "no".into())
                    }
                });
                let _ = handle_conn(s, t, h);
            }
        });
        (port, handle)
    }

    fn get(port: u16, path: &str, tok: Option<&str>) -> (u16, String) {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let mut req = format!("GET {} HTTP/1.1\r\nHost: x\r\n", path);
        if let Some(t) = tok {
            req.push_str(&format!("Authorization: Bearer {}\r\n", t));
        }
        req.push_str("Connection: close\r\n\r\n");
        s.write_all(req.as_bytes()).unwrap();
        let mut buf = String::new();
        s.read_to_string(&mut buf).unwrap();
        let status: u16 = buf.split_whitespace().nth(1).unwrap().parse().unwrap();
        let body = buf.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
        (status, body)
    }

    #[test]
    fn serves_and_token_gates() {
        let (port, _h) = start(Some("sekrit"));
        let (st, _) = get(port, "/api/echo", None);
        assert_eq!(st, 401);
        let (st, body) = get(port, "/api/echo", Some("sekrit"));
        assert_eq!(st, 200);
        assert!(body.contains("echo"));
    }

    #[test]
    fn no_token_when_loopback_mode() {
        let (port, _h) = start(None);
        let (st, _) = get(port, "/api/echo", None);
        assert_eq!(st, 200);
    }

    #[test]
    fn percent_decoding() {
        assert_eq!(percent_decode("a%20b+c"), "a b c");
        assert_eq!(percent_decode("%2Fpath%3Fq%3D1"), "/path?q=1");
        assert_eq!(percent_decode("plain"), "plain");
    }

    #[test]
    fn malformed_percent_tolerated() {
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("a%zzb"), "a%zzb");
    }
}
