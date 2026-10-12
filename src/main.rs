use mimalloc::MiMalloc;
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

mod config;
mod crypto;
mod statics;
mod tokens;

use std::{collections::HashMap, fs, io, path::PathBuf, time::Duration};

use actix_web::{
    delete, get,
    http::{header, StatusCode},
    post, web, App, HttpRequest, HttpResponse, HttpServer,
};
use serde::Deserialize;
use serde_json::json;

use config::{Config, MAX_TOKENS_PER_REQUEST};
use tokens::{AuthError, Op, Token};

fn error(status: StatusCode, msg: &str) -> HttpResponse {
    HttpResponse::build(status).json(json!({ "error": msg }))
}

fn internal(e: impl std::fmt::Display) -> HttpResponse {
    eprintln!("internal error: {e}");
    error(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
}

/// Runs blocking work (file IO, crypto, argon2) off the async workers.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, HttpResponse> {
    web::block(f).await.map_err(internal)
}

// ---- admin ----

async fn is_admin(pwd: Vec<u8>) -> bool {
    blocking(move || crypto::verify_admin_password(&pwd)).await.unwrap_or(false)
}

/// Older routes take the admin password as the raw request body.
fn body_password(body: &web::Bytes) -> Vec<u8> {
    String::from_utf8_lossy(body).trim().as_bytes().to_vec()
}

#[derive(Deserialize)]
struct MakeTokenRequest {
    pwd: String,
    count: Option<usize>,
    /// absolute expiry in unix seconds
    exp: Option<u64>,
    /// expiry in seconds from now, used if exp is not given
    ttl: Option<u64>,
    /// how many requests the token can be used for (default 1)
    uses: Option<u32>,
    /// restrict the token to a single file name
    file: Option<String>,
    /// restrict the token to some of: read, write, delete, list
    ops: Option<Vec<Op>>,
    /// any JSON, handed back by GET /token
    payload: Option<serde_json::Value>,
}

async fn make_tokens(count: usize, spec: Token) -> HttpResponse {
    if count == 0 || count > MAX_TOKENS_PER_REQUEST {
        return error(StatusCode::BAD_REQUEST, &format!("count must be between 1 and {MAX_TOKENS_PER_REQUEST}"));
    }
    match blocking(move || tokens::create(&spec, count)).await {
        Ok(Ok(tokens)) => HttpResponse::Ok().json(tokens),
        Ok(Err(e)) => internal(e),
        Err(res) => res,
    }
}

#[post("/make-tokens/{count}")]
async fn make_tokens_simple(cfg: web::Data<Config>, count: web::Path<usize>, body: web::Bytes) -> HttpResponse {
    if !is_admin(body_password(&body)).await {
        return error(StatusCode::UNAUTHORIZED, "wrong admin password");
    }
    let spec = Token { exp: config::now() + cfg.token_ttl_secs, uses: 1, file: None, ops: None, payload: None };
    make_tokens(count.into_inner(), spec).await
}

#[post("/mktn")]
async fn make_tokens_custom(cfg: web::Data<Config>, req: web::Json<MakeTokenRequest>) -> HttpResponse {
    let req = req.into_inner();
    if !is_admin(req.pwd.into_bytes()).await {
        return error(StatusCode::UNAUTHORIZED, "wrong admin password");
    }
    let exp = req.exp.unwrap_or_else(|| config::now().saturating_add(req.ttl.unwrap_or(cfg.token_ttl_secs)));
    if exp <= config::now() {
        return error(StatusCode::BAD_REQUEST, "exp must be in the future");
    }
    let uses = req.uses.unwrap_or(1);
    if uses == 0 {
        return error(StatusCode::BAD_REQUEST, "uses must be at least 1");
    }
    if let Some(file) = &req.file {
        if !config::valid_filename(file) {
            return error(StatusCode::BAD_REQUEST, "invalid file name");
        }
    }
    let payload = req.payload.map(|p| p.to_string());
    let spec = Token { exp, uses, file: req.file, ops: req.ops, payload };
    make_tokens(req.count.unwrap_or(1), spec).await
}

#[post("/expire-tokens")]
async fn expire_tokens(body: web::Bytes) -> HttpResponse {
    if !is_admin(body_password(&body)).await {
        return error(StatusCode::UNAUTHORIZED, "wrong admin password");
    }
    match blocking(tokens::remove_expired).await {
        Ok(removed) => HttpResponse::Ok().json(json!({ "removed": removed })),
        Err(res) => res,
    }
}

#[post("/revoke-tokens")]
async fn revoke_tokens(body: web::Bytes) -> HttpResponse {
    if !is_admin(body_password(&body)).await {
        return error(StatusCode::UNAUTHORIZED, "wrong admin password");
    }
    match blocking(tokens::revoke_all).await {
        Ok(removed) => HttpResponse::Ok().json(json!({ "removed": removed })),
        Err(res) => res,
    }
}

#[post("/remove-gz-files")]
async fn remove_gz_files(body: web::Bytes) -> HttpResponse {
    if !is_admin(body_password(&body)).await {
        return error(StatusCode::UNAUTHORIZED, "wrong admin password");
    }
    HttpResponse::Ok().json(json!({ "cleared": statics::clear_cache() }))
}

#[derive(Deserialize)]
struct ChangePassword {
    pwd: String,
    new_pwd: String,
}

#[post("/admin/change-password")]
async fn change_password(req: web::Json<ChangePassword>) -> HttpResponse {
    let ChangePassword { pwd, new_pwd } = req.into_inner();
    if !is_admin(pwd.into_bytes()).await {
        return error(StatusCode::UNAUTHORIZED, "wrong admin password");
    }
    let new_pwd = new_pwd.trim().to_string();
    if new_pwd.len() < 8 {
        return error(StatusCode::BAD_REQUEST, "new password must be at least 8 characters");
    }
    match blocking(move || crypto::set_admin_password(&new_pwd)).await {
        Ok(Ok(())) => HttpResponse::Ok().json(json!({ "ok": true })),
        Ok(Err(e)) => internal(e),
        Err(res) => res,
    }
}

// ---- token holders ----

/// The token comes from `?tk=` or the `x-paka-token` header.
fn token_of(req: &HttpRequest) -> Option<String> {
    web::Query::<HashMap<String, String>>::from_query(req.query_string())
        .ok()
        .and_then(|q| q.get("tk").cloned())
        .or_else(|| req.headers().get("x-paka-token").and_then(|v| v.to_str().ok()).map(str::to_string))
        .filter(|t| !t.is_empty())
}

fn auth_error(e: AuthError) -> HttpResponse {
    match e {
        AuthError::Invalid => error(StatusCode::UNAUTHORIZED, "invalid or used up token"),
        AuthError::Expired => error(StatusCode::UNAUTHORIZED, "token expired"),
        AuthError::OutOfScope => error(StatusCode::FORBIDDEN, "token not valid for this request"),
    }
}

/// Spends a token for `op` on `file`, or returns the error response.
async fn authorize(req: &HttpRequest, op: Op, file: Option<&str>) -> Result<Token, HttpResponse> {
    let Some(tk) = token_of(req) else {
        return Err(error(StatusCode::UNAUTHORIZED, "missing token, pass ?tk=TOKEN"));
    };
    let file = file.map(str::to_string);
    blocking(move || tokens::consume(&tk, op, file.as_deref())).await?.map_err(auth_error)
}

fn file_path(name: &str) -> Result<PathBuf, HttpResponse> {
    if config::valid_filename(name) {
        Ok(PathBuf::from(config::DIST_DIR).join(name))
    } else {
        Err(error(StatusCode::BAD_REQUEST, "invalid file name"))
    }
}

fn file_json(name: &str, meta: &fs::Metadata) -> serde_json::Value {
    let modified = meta.modified().ok().and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs());
    json!({ "filename": name, "size": crypto::plaintext_len(meta.len()), "modified": modified })
}

#[get("/token")]
async fn token_info(req: HttpRequest) -> HttpResponse {
    let Some(tk) = token_of(&req) else {
        return error(StatusCode::UNAUTHORIZED, "missing token, pass ?tk=TOKEN");
    };
    match blocking(move || tokens::peek(&tk)).await {
        Ok(Ok(t)) => HttpResponse::Ok().json(json!({
            "exp": t.exp,
            "uses": t.uses,
            "file": t.file,
            "ops": t.ops,
            "payload": t.payload.and_then(|p| serde_json::from_str::<serde_json::Value>(&p).ok()),
        })),
        Ok(Err(e)) => auth_error(e),
        Err(res) => res,
    }
}

#[get("/files")]
async fn list_files(req: HttpRequest) -> HttpResponse {
    if let Err(res) = authorize(&req, Op::List, None).await {
        return res;
    }
    let listed = blocking(|| -> io::Result<Vec<serde_json::Value>> {
        let mut files: Vec<_> = fs::read_dir(config::DIST_DIR)?
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().into_string().ok().filter(|n| config::valid_filename(n))?;
                let meta = e.metadata().ok().filter(|m| m.is_file())?;
                Some(file_json(&name, &meta))
            })
            .collect();
        files.sort_by(|a, b| a["filename"].as_str().cmp(&b["filename"].as_str()));
        Ok(files)
    })
    .await;
    match listed {
        Ok(Ok(files)) => HttpResponse::Ok().json(files),
        Ok(Err(e)) => internal(e),
        Err(res) => res,
    }
}

#[get("/file-info/{filename}")]
async fn file_info(req: HttpRequest, filename: web::Path<String>) -> HttpResponse {
    let path = match file_path(&filename) {
        Ok(p) => p,
        Err(res) => return res,
    };
    if let Err(res) = authorize(&req, Op::Read, Some(&filename)).await {
        return res;
    }
    match tokio::fs::metadata(&path).await {
        Ok(meta) if meta.is_file() => HttpResponse::Ok().json(file_json(&filename, &meta)),
        _ => error(StatusCode::NOT_FOUND, "file not found"),
    }
}

#[post("/file/{filename}")]
async fn upload_file(req: HttpRequest, filename: web::Path<String>, body: web::Bytes) -> HttpResponse {
    let path = match file_path(&filename) {
        Ok(p) => p,
        Err(res) => return res,
    };
    if let Err(res) = authorize(&req, Op::Write, Some(&filename)).await {
        return res;
    }
    let size = body.len();
    match blocking(move || crypto::encrypt(&body).and_then(|enc| crypto::write_atomic(&path, &enc))).await {
        Ok(Ok(())) => HttpResponse::Ok().json(json!({ "filename": filename.as_str(), "size": size })),
        Ok(Err(e)) => internal(e),
        Err(res) => res,
    }
}

#[get("/file/{filename}")]
async fn download_file(req: HttpRequest, filename: web::Path<String>) -> HttpResponse {
    let path = match file_path(&filename) {
        Ok(p) => p,
        Err(res) => return res,
    };
    if let Err(res) = authorize(&req, Op::Read, Some(&filename)).await {
        return res;
    }
    let data = match tokio::fs::read(&path).await {
        Ok(d) => d,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return error(StatusCode::NOT_FOUND, "file not found"),
        Err(e) => return internal(e),
    };
    match blocking(move || crypto::decrypt(&data)).await {
        Ok(Some(plain)) => HttpResponse::Ok()
            .content_type(mime_guess::from_path(&path).first_or_octet_stream())
            // uploads are untrusted: never let them run as pages on this origin
            .insert_header((header::CONTENT_DISPOSITION, "attachment"))
            .insert_header((header::CONTENT_SECURITY_POLICY, "sandbox"))
            .insert_header((header::X_CONTENT_TYPE_OPTIONS, "nosniff"))
            .body(plain),
        Ok(None) => internal(format!("could not decrypt {}", path.display())),
        Err(res) => res,
    }
}

#[delete("/file/{filename}")]
async fn delete_file(req: HttpRequest, filename: web::Path<String>) -> HttpResponse {
    let path = match file_path(&filename) {
        Ok(p) => p,
        Err(res) => return res,
    };
    if let Err(res) = authorize(&req, Op::Delete, Some(&filename)).await {
        return res;
    }
    match tokio::fs::remove_file(&path).await {
        Ok(()) => HttpResponse::Ok().json(json!({ "deleted": filename.as_str() })),
        Err(e) if e.kind() == io::ErrorKind::NotFound => error(StatusCode::NOT_FOUND, "file not found"),
        Err(e) => internal(e),
    }
}

// ---- static ----

#[get("/")]
async fn index(req: HttpRequest) -> HttpResponse {
    statics::serve_static(&req, "index.html").await
}

#[get("/static/{filename}")]
async fn static_file(req: HttpRequest, filename: web::Path<String>) -> HttpResponse {
    statics::serve_static(&req, &filename).await
}

async fn fallback(req: HttpRequest) -> HttpResponse {
    statics::not_found(&req).await
}

// ---- startup ----

fn load_tls_config(cfg: &Config) -> io::Result<Option<rustls::ServerConfig>> {
    let (cert_path, key_path) = (PathBuf::from(&cfg.cert), PathBuf::from(&cfg.key));
    if !cert_path.exists() && !key_path.exists() {
        return Ok(None);
    }
    let bad = |msg: String| io::Error::new(io::ErrorKind::InvalidData, msg);
    let certs = rustls_pemfile::certs(&mut io::BufReader::new(fs::File::open(&cert_path)?))
        .collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        return Err(bad(format!("no certificates in {}", cert_path.display())));
    }
    let key = rustls_pemfile::private_key(&mut io::BufReader::new(fs::File::open(&key_path)?))?
        .ok_or_else(|| bad(format!("no private key in {}", key_path.display())))?;
    let _ = rustls::crypto::ring::default_provider().install_default();
    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map(Some)
        .map_err(|e| bad(format!("invalid certificate/key: {e}")))
}

#[actix_web::main]
async fn main() -> io::Result<()> {
    for dir in [config::SECRETS_DIR, config::TOKENS_DIR, config::DIST_DIR] {
        fs::create_dir_all(dir)?;
    }
    crypto::init_master_key()?;
    crypto::init_admin_password()?;

    let cfg = Config::from_env();
    let tls = load_tls_config(&cfg)?;
    let addr = (cfg.addr.clone(), cfg.port);
    let max_upload = cfg.max_upload_bytes;
    let (cfg_cert, cfg_key) = (cfg.cert.clone(), cfg.key.clone());
    let cfg = web::Data::new(cfg);

    // sweep expired tokens every hour
    actix_web::rt::spawn(async {
        let mut tick = actix_web::rt::time::interval(Duration::from_secs(60 * 60));
        loop {
            tick.tick().await;
            let _ = web::block(tokens::remove_expired).await;
        }
    });

    let server = HttpServer::new(move || {
        App::new()
            .app_data(cfg.clone())
            .app_data(web::PayloadConfig::new(max_upload))
            .app_data(web::JsonConfig::default().limit(1024 * 1024).error_handler(|err, _| {
                let res = error(StatusCode::BAD_REQUEST, &err.to_string());
                actix_web::error::InternalError::from_response(err, res).into()
            }))
            .service(make_tokens_simple)
            .service(make_tokens_custom)
            .service(expire_tokens)
            .service(revoke_tokens)
            .service(remove_gz_files)
            .service(change_password)
            .service(token_info)
            .service(list_files)
            .service(file_info)
            .service(upload_file)
            .service(download_file)
            .service(delete_file)
            .service(index)
            .service(static_file)
            .default_service(web::to(fallback))
    });

    match tls {
        Some(tls) => {
            println!("paka listening on https://{}:{}", addr.0, addr.1);
            server.bind_rustls_0_23(addr, tls)?.run().await
        }
        None => {
            println!("no TLS cert/key at {} / {}, serving plain http", cfg_cert, cfg_key);
            println!("paka listening on http://{}:{}", addr.0, addr.1);
            server.bind(addr)?.run().await
        }
    }
}
