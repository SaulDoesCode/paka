//! Serves `./static`, gzipping compressible files on the fly and caching the result in memory
//! until the source file changes (or the cache is cleared).

use std::{
    collections::HashMap,
    io::Write,
    path::{Path, PathBuf},
    sync::Mutex,
    time::SystemTime,
};

use actix_files::NamedFile;
use actix_web::{
    http::{header, StatusCode},
    web::Bytes,
    HttpRequest, HttpResponse,
};
use flate2::{write::GzEncoder, Compression};

use crate::config;

const GZIPABLE_TYPES: [&str; 8] = [
    "text/html",
    "text/css",
    "text/javascript",
    "image/svg+xml",
    "application/javascript",
    "application/x-javascript",
    "application/xml",
    "application/json",
];

static GZ_CACHE: Mutex<Option<HashMap<PathBuf, (SystemTime, Bytes)>>> = Mutex::new(None);

pub fn clear_cache() -> usize {
    GZ_CACHE.lock().unwrap().take().map_or(0, |c| c.len())
}

fn accepts_gzip(req: &HttpRequest) -> bool {
    req.headers()
        .get(header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(',').any(|enc| enc.trim().starts_with("gzip")))
}

async fn gzipped(path: &Path, modified: SystemTime) -> Option<Bytes> {
    if let Some((m, bytes)) = GZ_CACHE.lock().unwrap().as_ref().and_then(|c| c.get(path)) {
        if *m == modified {
            return Some(bytes.clone());
        }
    }
    let content = tokio::fs::read(path).await.ok()?;
    let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(&content).ok()?;
    let bytes = Bytes::from(encoder.finish().ok()?);
    GZ_CACHE.lock().unwrap().get_or_insert_with(HashMap::new).insert(path.to_path_buf(), (modified, bytes.clone()));
    Some(bytes)
}

async fn serve(req: &HttpRequest, name: &str, status: StatusCode) -> Option<HttpResponse> {
    if !config::valid_filename(name) {
        return None;
    }
    let path = Path::new(config::STATIC_DIR).join(name);
    let meta = tokio::fs::metadata(&path).await.ok().filter(|m| m.is_file())?;
    let mime = mime_guess::from_path(&path).first_or_octet_stream();

    if accepts_gzip(req) && GZIPABLE_TYPES.contains(&mime.essence_str()) {
        if let Some(body) = gzipped(&path, meta.modified().ok()?).await {
            let content_type = if mime.type_() == mime_guess::mime::TEXT || mime.essence_str() == "application/javascript" {
                format!("{}; charset=utf-8", mime.essence_str())
            } else {
                mime.essence_str().to_string()
            };
            return Some(
                HttpResponse::build(status)
                    .insert_header((header::CONTENT_TYPE, content_type))
                    .insert_header((header::CONTENT_ENCODING, "gzip"))
                    .insert_header((header::VARY, "Accept-Encoding"))
                    .insert_header((header::CACHE_CONTROL, "no-cache"))
                    .body(body),
            );
        }
    }

    let mut res = NamedFile::open_async(&path).await.ok()?.into_response(req);
    *res.status_mut() = status;
    Some(res)
}

pub async fn serve_static(req: &HttpRequest, name: &str) -> HttpResponse {
    match serve(req, name, StatusCode::OK).await {
        Some(res) => res,
        None => not_found(req).await,
    }
}

pub async fn not_found(req: &HttpRequest) -> HttpResponse {
    match serve(req, "404.html", StatusCode::NOT_FOUND).await {
        Some(res) => res,
        None => HttpResponse::NotFound().body("404 Not Found"),
    }
}
