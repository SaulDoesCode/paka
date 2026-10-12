use mimalloc::MiMalloc;
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

mod config;
mod crypto;
mod statics;
mod tokens;

use std::{fs, io, path::PathBuf, time::Duration};

use salvo::{
    catcher::Catcher,
    conn::rustls::{Keycert, RustlsConfig},
    http::{header, ParseError, StatusCode},
    hyper::body::Bytes,
    prelude::*,
};
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::{json, Value};

use config::MAX_TOKENS_PER_REQUEST;
use tokens::{AuthError, Op, Token};

/// Admin passwords and JSON bodies are small; only uploads get the big limit.
const SMALL_BODY: usize = 1024 * 1024;

/// An error response: `{"error": "..."}` with a status code.
struct ApiError(StatusCode, String);

impl ApiError {
    fn new(status: StatusCode, msg: impl Into<String>) -> Self {
        ApiError(status, msg.into())
    }

    fn internal(e: impl std::fmt::Display) -> Self {
        eprintln!("internal error: {e}");
        ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
    }
}

impl From<ParseError> for ApiError {
    fn from(e: ParseError) -> Self {
        match e {
            ParseError::PayloadTooLarge => ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "request body too large"),
            e => ApiError::new(StatusCode::BAD_REQUEST, e.to_string()),
        }
    }
}

impl From<AuthError> for ApiError {
    fn from(e: AuthError) -> Self {
        match e {
            AuthError::Invalid => ApiError::new(StatusCode::UNAUTHORIZED, "invalid or used up token"),
            AuthError::Expired => ApiError::new(StatusCode::UNAUTHORIZED, "token expired"),
            AuthError::OutOfScope => ApiError::new(StatusCode::FORBIDDEN, "token not valid for this request"),
        }
    }
}

impl Scribe for ApiError {
    fn render(self, res: &mut Response) {
        res.status_code(self.0);
        res.render(Json(json!({ "error": self.1 })));
    }
}

type ApiResult = Result<Json<Value>, ApiError>;

/// Runs blocking work (file IO, crypto, argon2) off the async workers.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, ApiError> {
    tokio::task::spawn_blocking(f).await.map_err(ApiError::internal)
}

/// Parses a JSON body regardless of its Content-Type.
async fn json_body<T: DeserializeOwned>(req: &mut Request) -> Result<T, ApiError> {
    let body = req.payload_with_max_size(SMALL_BODY).await?;
    serde_json::from_slice(body).map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, format!("invalid JSON: {e}")))
}

// ---- admin ----

async fn check_admin(pwd: Vec<u8>) -> Result<(), ApiError> {
    if blocking(move || crypto::verify_admin_password(&pwd)).await? {
        Ok(())
    } else {
        Err(ApiError::new(StatusCode::UNAUTHORIZED, "wrong admin password"))
    }
}

/// Older routes take the admin password as the raw request body.
async fn check_body_admin(req: &mut Request) -> Result<(), ApiError> {
    let body = req.payload_with_max_size(SMALL_BODY).await?;
    check_admin(String::from_utf8_lossy(body).trim().as_bytes().to_vec()).await
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
    payload: Option<Value>,
}

async fn make_tokens(count: usize, spec: Token) -> ApiResult {
    if count == 0 || count > MAX_TOKENS_PER_REQUEST {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            format!("count must be between 1 and {MAX_TOKENS_PER_REQUEST}"),
        ));
    }
    let tokens = blocking(move || tokens::create(&spec, count)).await?.map_err(ApiError::internal)?;
    Ok(Json(json!(tokens)))
}

#[handler]
async fn make_tokens_simple(req: &mut Request) -> ApiResult {
    check_body_admin(req).await?;
    let count = req.param::<usize>("count").ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "count must be a number"))?;
    let spec = Token { exp: config::now() + config::get().token_ttl_secs, uses: 1, file: None, ops: None, payload: None };
    make_tokens(count, spec).await
}

#[handler]
async fn make_tokens_custom(req: &mut Request) -> ApiResult {
    let req: MakeTokenRequest = json_body(req).await?;
    check_admin(req.pwd.into_bytes()).await?;
    let bad = |msg: &str| Err(ApiError::new(StatusCode::BAD_REQUEST, msg));
    let exp = req.exp.unwrap_or_else(|| config::now().saturating_add(req.ttl.unwrap_or(config::get().token_ttl_secs)));
    if exp <= config::now() {
        return bad("exp must be in the future");
    }
    let uses = req.uses.unwrap_or(1);
    if uses == 0 {
        return bad("uses must be at least 1");
    }
    if req.file.as_deref().is_some_and(|f| !config::valid_filename(f)) {
        return bad("invalid file name");
    }
    let payload = req.payload.map(|p| p.to_string());
    let spec = Token { exp, uses, file: req.file, ops: req.ops, payload };
    make_tokens(req.count.unwrap_or(1), spec).await
}

#[handler]
async fn expire_tokens(req: &mut Request) -> ApiResult {
    check_body_admin(req).await?;
    Ok(Json(json!({ "removed": blocking(tokens::remove_expired).await? })))
}

#[handler]
async fn revoke_tokens(req: &mut Request) -> ApiResult {
    check_body_admin(req).await?;
    Ok(Json(json!({ "removed": blocking(tokens::revoke_all).await? })))
}

#[handler]
async fn remove_gz_files(req: &mut Request) -> ApiResult {
    check_body_admin(req).await?;
    Ok(Json(json!({ "cleared": statics::clear_cache() })))
}

#[derive(Deserialize)]
struct ChangePassword {
    pwd: String,
    new_pwd: String,
}

#[handler]
async fn change_password(req: &mut Request) -> ApiResult {
    let ChangePassword { pwd, new_pwd } = json_body(req).await?;
    check_admin(pwd.into_bytes()).await?;
    let new_pwd = new_pwd.trim().to_string();
    if new_pwd.len() < 8 {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "new password must be at least 8 characters"));
    }
    blocking(move || crypto::set_admin_password(&new_pwd)).await?.map_err(ApiError::internal)?;
    Ok(Json(json!({ "ok": true })))
}

// ---- token holders ----

/// The token comes from `?tk=` or the `x-paka-token` header.
fn token_of(req: &Request) -> Result<String, ApiError> {
    req.query::<String>("tk")
        .or_else(|| req.header::<String>("x-paka-token"))
        .filter(|t| !t.is_empty())
        .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "missing token, pass ?tk=TOKEN"))
}

/// Spends a token for `op` on `file`.
async fn authorize(req: &Request, op: Op, file: Option<&str>) -> Result<Token, ApiError> {
    let tk = token_of(req)?;
    let file = file.map(str::to_string);
    Ok(blocking(move || tokens::consume(&tk, op, file.as_deref())).await??)
}

/// The `{filename}` route param, validated, and its path in `dist/`.
fn file_param(req: &Request) -> Result<(String, PathBuf), ApiError> {
    req.param::<String>("filename")
        .filter(|name| config::valid_filename(name))
        .map(|name| {
            let path = PathBuf::from(config::DIST_DIR).join(&name);
            (name, path)
        })
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "invalid file name"))
}

fn not_found_file() -> ApiError {
    ApiError::new(StatusCode::NOT_FOUND, "file not found")
}

fn file_json(name: &str, meta: &fs::Metadata) -> Value {
    let modified = meta.modified().ok().and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs());
    json!({ "filename": name, "size": crypto::plaintext_len(meta.len()), "modified": modified })
}

#[handler]
async fn token_info(req: &mut Request) -> ApiResult {
    let tk = token_of(req)?;
    let t = blocking(move || tokens::peek(&tk)).await??;
    Ok(Json(json!({
        "exp": t.exp,
        "uses": t.uses,
        "file": t.file,
        "ops": t.ops,
        "payload": t.payload.and_then(|p| serde_json::from_str::<Value>(&p).ok()),
    })))
}

#[handler]
async fn list_files(req: &mut Request) -> ApiResult {
    authorize(req, Op::List, None).await?;
    let files = blocking(|| -> io::Result<Vec<Value>> {
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
    .await?
    .map_err(ApiError::internal)?;
    Ok(Json(json!(files)))
}

#[handler]
async fn file_info(req: &mut Request) -> ApiResult {
    let (name, path) = file_param(req)?;
    authorize(req, Op::Read, Some(&name)).await?;
    match tokio::fs::metadata(&path).await {
        Ok(meta) if meta.is_file() => Ok(Json(file_json(&name, &meta))),
        _ => Err(not_found_file()),
    }
}

#[handler]
async fn upload_file(req: &mut Request) -> ApiResult {
    let (name, path) = file_param(req)?;
    let max = config::get().max_upload_bytes;
    // reject declared oversize uploads before spending the token
    if req.header::<usize>(header::CONTENT_LENGTH).is_some_and(|len| len > max) {
        return Err(ParseError::PayloadTooLarge.into());
    }
    authorize(req, Op::Write, Some(&name)).await?;
    let body = req.payload_with_max_size(max).await?.clone();
    let size = body.len();
    blocking(move || crypto::encrypt(&body).and_then(|enc| crypto::write_atomic(&path, &enc)))
        .await?
        .map_err(ApiError::internal)?;
    Ok(Json(json!({ "filename": name, "size": size })))
}

#[handler]
async fn download_file(req: &mut Request, res: &mut Response) -> Result<(), ApiError> {
    let (name, path) = file_param(req)?;
    authorize(req, Op::Read, Some(&name)).await?;
    let data = match tokio::fs::read(&path).await {
        Ok(d) => d,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(not_found_file()),
        Err(e) => return Err(ApiError::internal(e)),
    };
    let plain = blocking(move || crypto::decrypt(&data))
        .await?
        .ok_or_else(|| ApiError::internal(format!("could not decrypt {}", path.display())))?;
    let mime = mime_guess::from_path(&name).first_or_octet_stream();
    let headers = res.headers_mut();
    headers.insert(header::CONTENT_TYPE, mime.essence_str().parse().map_err(ApiError::internal)?);
    // uploads are untrusted: never let them run as pages on this origin
    headers.insert(header::CONTENT_DISPOSITION, header::HeaderValue::from_static("attachment"));
    headers.insert(header::CONTENT_SECURITY_POLICY, header::HeaderValue::from_static("sandbox"));
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, header::HeaderValue::from_static("nosniff"));
    res.body(Bytes::from(plain));
    Ok(())
}

#[handler]
async fn delete_file(req: &mut Request) -> ApiResult {
    let (name, path) = file_param(req)?;
    authorize(req, Op::Delete, Some(&name)).await?;
    match tokio::fs::remove_file(&path).await {
        Ok(()) => Ok(Json(json!({ "deleted": name }))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Err(not_found_file()),
        Err(e) => Err(ApiError::internal(e)),
    }
}

// ---- static ----

#[handler]
async fn index(req: &mut Request, res: &mut Response) {
    statics::serve_static(req, res, "index.html").await
}

#[handler]
async fn static_file(req: &mut Request, res: &mut Response) {
    let name = req.param::<String>("filename").unwrap_or_default();
    statics::serve_static(req, res, &name).await
}

/// Serves the 404 page for routes that don't exist.
#[handler]
async fn catch_not_found(req: &mut Request, res: &mut Response, ctrl: &mut FlowCtrl) {
    if res.status_code == Some(StatusCode::NOT_FOUND) {
        statics::not_found(req, res).await;
        ctrl.skip_rest();
    }
}

// ---- startup ----

fn router() -> Router {
    Router::new()
        .get(index)
        .push(Router::with_path("make-tokens/{count}").post(make_tokens_simple))
        .push(Router::with_path("mktn").post(make_tokens_custom))
        .push(Router::with_path("expire-tokens").post(expire_tokens))
        .push(Router::with_path("revoke-tokens").post(revoke_tokens))
        .push(Router::with_path("remove-gz-files").post(remove_gz_files))
        .push(Router::with_path("admin/change-password").post(change_password))
        .push(Router::with_path("token").get(token_info))
        .push(Router::with_path("files").get(list_files))
        .push(Router::with_path("file-info/{filename}").get(file_info))
        .push(
            Router::with_path("file/{filename}")
                .get(download_file)
                .post(upload_file)
                .delete(delete_file),
        )
        .push(Router::with_path("static/{filename}").get(static_file))
}

fn service() -> Service {
    Service::new(router()).catcher(Catcher::default().hoop(catch_not_found))
}

#[tokio::main]
async fn main() -> io::Result<()> {
    for dir in [config::SECRETS_DIR, config::TOKENS_DIR, config::DIST_DIR] {
        fs::create_dir_all(dir)?;
    }
    crypto::init_master_key()?;
    crypto::init_admin_password()?;

    let cfg = config::get();
    let addr = format!("{}:{}", cfg.addr, cfg.port);

    // sweep expired tokens every hour
    tokio::spawn(async {
        let mut tick = tokio::time::interval(Duration::from_secs(60 * 60));
        loop {
            tick.tick().await;
            let _ = tokio::task::spawn_blocking(tokens::remove_expired).await;
        }
    });

    let (cert, key) = (PathBuf::from(&cfg.cert), PathBuf::from(&cfg.key));
    if cert.exists() || key.exists() {
        let tls = RustlsConfig::new(Keycert::new().cert_from_path(&cert)?.key_from_path(&key)?);
        let acceptor = TcpListener::new(addr.clone()).rustls(tls).try_bind().await.map_err(io::Error::other)?;
        println!("paka listening on https://{addr}");
        Server::new(acceptor).try_serve(service()).await
    } else {
        println!("no TLS cert/key at {} / {}, serving plain http", cfg.cert, cfg.key);
        let acceptor = TcpListener::new(addr.clone()).try_bind().await.map_err(io::Error::other)?;
        println!("paka listening on http://{addr}");
        Server::new(acceptor).try_serve(service()).await
    }
}

#[cfg(test)]
mod tests {
    use salvo::test::{ResponseExt, TestClient};

    use super::*;

    #[tokio::test]
    async fn routes_without_auth() {
        let svc = service();
        let url = |p: &str| format!("http://127.0.0.1{p}");

        let res = TestClient::get(url("/file/x.txt")).send(&svc).await;
        assert_eq!(res.status_code, Some(StatusCode::UNAUTHORIZED));

        let mut res = TestClient::get(url("/file/..%2Fadmin_pwd.txt?tk=a")).send(&svc).await;
        assert_eq!(res.status_code, Some(StatusCode::BAD_REQUEST));
        assert!(res.take_string().await.unwrap().contains("invalid file name"));

        let res = TestClient::get(url("/no/such/route")).send(&svc).await;
        assert_eq!(res.status_code, Some(StatusCode::NOT_FOUND));
    }
}
