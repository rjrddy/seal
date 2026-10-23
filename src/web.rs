use ed25519_dalek::{SigningKey, VerifyingKey};
use seal_log::{Consistency, Error, Inclusion, Result, hash_from, require, storage::Store};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{env, fs, io::Read, path::PathBuf};
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};
fn header(name: &str, value: &str) -> Header {
    Header::from_bytes(name.as_bytes(), value.as_bytes()).expect("static HTTP header")
}
fn send(request: Request, status: u16, body: Vec<u8>, mime: &str) {
    let response=Response::from_data(body).with_status_code(StatusCode(status))
        .with_header(header("Content-Type",mime)).with_header(header("Cache-Control","no-store"))
        .with_header(header("X-Content-Type-Options","nosniff"))
        .with_header(header("Content-Security-Policy","default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'"));
    let _ = request.respond(response);
    println!("{}", json!({"event":"http","status":status}));
}
fn json_response(request: Request, value: Value) {
    send(
        request,
        200,
        serde_json::to_vec(&value).expect("JSON serializes"),
        "application/json",
    );
}
fn text_header(request: &Request, name: &'static str) -> Option<String> {
    request
        .headers()
        .iter()
        .find(|h| h.field.equiv(name))
        .map(|h| h.value.as_str().to_owned())
}
fn equal_token(a: &str, b: &str) -> bool {
    let mut difference = a.len() ^ b.len();
    for (x, y) in a.bytes().zip(b.bytes()) {
        difference |= (x ^ y) as usize;
    }
    difference == 0
}
fn body(request: &mut Request) -> Result<Value> {
    require(
        request.body_length().is_some_and(|n| n <= 65536),
        "body length limit",
    )?;
    let mut data = vec![];
    request.as_reader().take(65537).read_to_end(&mut data)?;
    require(data.len() <= 65536, "body limit")?;
    Ok(serde_json::from_slice(&data)?)
}
fn state(store: &Store) -> Result<Value> {
    let _guard = store.lock()?;
    let (entries, cps) = store.checked()?;
    let last = cps.last().cloned().ok_or(Error("no checkpoint".into()))?;
    let displayed = entries
        .iter()
        .rev()
        .take(16)
        .map(|e| {
            json!({"seq":e.seq,"hash":e.hash,
        "payload_text":String::from_utf8_lossy(&hex::decode(&e.payload).unwrap_or_default())})
        })
        .collect::<Vec<_>>();
    Ok(
        json!({"size":entries.len(),"checkpoint":last,"checkpoints":cps,
        "public_key":hex::encode(store.key.verifying_key().to_bytes()),"log_id":hex::encode(store.log_id),
        "entries":displayed,"demo":true,"key_notice":"Public deterministic demo key. Not a private signing identity."}),
    )
}
fn bundle(store: &Store, index: usize, old_size: usize) -> Result<Value> {
    let _guard = store.lock()?;
    let (entries, cps) = store.checked()?;
    let new = cps.last().cloned().ok_or(Error("no checkpoint".into()))?;
    let old = cps
        .iter()
        .find(|c| c.size == old_size as u64)
        .cloned()
        .ok_or(Error("unknown retained checkpoint".into()))?;
    Ok(
        json!({"inclusion":Inclusion::create(&entries,index,new.clone())?,
              "consistency":Consistency::create(&entries,old,new)?}),
    )
}
fn verify(value: Value) -> Result<Value> {
    let key = value["public_key"]
        .as_str()
        .ok_or(Error("public key required".into()))?;
    let key = VerifyingKey::from_bytes(&hash_from(key)?).map_err(|_| Error("public key".into()))?;
    let id = hash_from(
        value["log_id"]
            .as_str()
            .ok_or(Error("log identity required".into()))?,
    )?;
    let result = match value["kind"].as_str() {
        Some("inclusion") => {
            serde_json::from_value::<Inclusion>(value["bundle"].clone())?.verify(&key, id)
        }
        Some("consistency") => {
            serde_json::from_value::<Consistency>(value["bundle"].clone())?.verify(&key, id)
        }
        _ => return Err(Error("unknown proof kind".into())),
    };
    Ok(match result {
        Ok(()) => {
            json!({"verified":true,"reason":"Signature and Merkle path match the supplied trust anchor."})
        }
        Err(e) => json!({"verified":false,"reason":e.to_string()}),
    })
}
pub fn serve(dir: PathBuf) -> Result<()> {
    let store = Store::create(
        &dir,
        SigningKey::from_bytes(&[0x53; 32]),
        Sha256::digest(b"seal-synthetic-demo-v1").into(),
    )?;
    if store.read()?.is_empty() {
        let payloads = (0..96)
            .map(|i| format!("{{\"event\":\"synthetic-build\",\"ordinal\":{i}}}").into_bytes())
            .collect::<Vec<_>>();
        store.append_many(&payloads, true)?;
    }
    store.checkpoint()?;
    let addr = env::var("SEAL_ADDR").unwrap_or("127.0.0.1:8093".into());
    let token = env::var("SEAL_TOKEN").unwrap_or_default();
    require(
        addr.starts_with("127.0.0.1:") || addr.starts_with("localhost:") || token.len() >= 24,
        "non-loopback requires a long SEAL_TOKEN",
    )?;
    let server = Server::http(&addr).map_err(|_| Error("HTTP bind failed".into()))?;
    let local = server
        .server_addr()
        .to_ip()
        .ok_or(Error("IP socket required".into()))?;
    println!(
        "{}",
        json!({"event":"ready","url":format!("http://{local}"),"demo_key":true})
    );
    let web = PathBuf::from(
        env::var("SEAL_WEB").unwrap_or(format!("{}/web", env!("CARGO_MANIFEST_DIR"))),
    );
    for mut request in server.incoming_requests() {
        let url = request.url().to_owned();
        let mut parts = url.splitn(2, '?');
        let path = parts.next().unwrap_or("/");
        let query = parts.next().unwrap_or("");
        let host = text_header(&request, "Host").unwrap_or_default();
        if token.is_empty()
            && host != local.to_string()
            && host != format!("localhost:{}", local.port())
        {
            send(
                request,
                403,
                b"{\"error\":\"host rejected\"}".to_vec(),
                "application/json",
            );
            continue;
        }
        if path.starts_with("/api/")
            && path != "/api/health"
            && !token.is_empty()
            && !equal_token(
                &text_header(&request, "Authorization").unwrap_or_default(),
                &format!("Bearer {token}"),
            )
        {
            send(
                request,
                401,
                b"{\"error\":\"authentication required\"}".to_vec(),
                "application/json",
            );
            continue;
        }
        if let Some(origin) = text_header(&request, "Origin") {
            let origin_host = origin
                .strip_prefix("http://")
                .or_else(|| origin.strip_prefix("https://"))
                .unwrap_or("");
            if origin_host != host {
                send(
                    request,
                    403,
                    b"{\"error\":\"origin rejected\"}".to_vec(),
                    "application/json",
                );
                continue;
            }
        }
        let result = match (request.method(), path) {
            (&Method::Get, "/api/health") => Ok(json!({"status":"ready"})),
            (&Method::Get, "/api/state") => state(&store),
            (&Method::Get, "/api/bundle") => {
                let mut index = 37;
                let mut old = 64;
                let mut valid = true;
                for field in query.split('&').filter(|s| !s.is_empty()) {
                    if let Some((key, value)) = field.split_once('=') {
                        if let Ok(n) = value.parse::<usize>() {
                            match key {
                                "index" => index = n,
                                "old" => old = n,
                                _ => valid = false,
                            }
                        } else {
                            valid = false;
                        }
                    } else {
                        valid = false;
                    }
                }
                if valid {
                    bundle(&store, index, old)
                } else {
                    Err(Error("query rejected".into()))
                }
            }
            (&Method::Post, "/api/verify") => body(&mut request).and_then(verify),
            (&Method::Post, "/api/append") => body(&mut request).and_then(|_| {
                let size = store.read()?.len();
                let payload = format!("{{\"event\":\"synthetic-review\",\"ordinal\":{size}}}");
                store.append_many(&[payload.into_bytes()], true)?;
                store.checkpoint()?;
                state(&store)
            }),
            (&Method::Get, "/") | (&Method::Get, "/style.css") | (&Method::Get, "/app.js") => {
                let (file, mime) = match path {
                    "/style.css" => ("style.css", "text/css"),
                    "/app.js" => ("app.js", "text/javascript"),
                    _ => ("index.html", "text/html; charset=utf-8"),
                };
                match fs::read(web.join(file)) {
                    Ok(bytes) => send(request, 200, bytes, mime),
                    Err(_) => send(request, 404, b"Not found".to_vec(), "text/plain"),
                };
                continue;
            }
            _ => {
                send(
                    request,
                    404,
                    b"{\"error\":\"not found\"}".to_vec(),
                    "application/json",
                );
                continue;
            }
        };
        match result {
            Ok(value) => json_response(request, value),
            Err(_) => send(
                request,
                400,
                b"{\"error\":\"invalid request or proof encoding\"}".to_vec(),
                "application/json",
            ),
        }
    }
    Ok(())
}
