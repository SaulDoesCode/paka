//! Serves `./static`, gzipping compressible files on the fly and caching the result in memory
//! until the source file changes (or the cache is cleared).

use std::{
    collections::HashMap,
    io::Write,
    path::{Path, PathBuf},
    sync::Mutex,
    time::SystemTime,
};

use flate2::{write::GzEncoder, Compression};
use salvo::{
    fs::NamedFile,
    http::{header, Mime, StatusCode},
    hyper::body::Bytes,
    prelude::*,
};

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

fn accepts_gzip(req: &Request) -> bool {
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

fn content_type(mime: &Mime) -> String {
    if mime.type_() == "text" || mime.essence_str() == "application/javascript" {
        format!("{}; charset=utf-8", mime.essence_str())
    } else {
        mime.essence_str().to_string()
    }
}

/// Writes static file `name` into `res` with `status`, returns false if there is no such file.
async fn serve(req: &Request, res: &mut Response, name: &str, status: StatusCode) -> bool {
    if !config::valid_filename(name) {
        return false;
    }
    let path = Path::new(config::STATIC_DIR).join(name);
    let Some(meta) = tokio::fs::metadata(&path).await.ok().filter(|m| m.is_file()) else {
        return false;
    };
    let mime = mime_guess::from_path(&path).first_or_octet_stream();

    if accepts_gzip(req) && GZIPABLE_TYPES.contains(&mime.essence_str()) {
        if let Some(body) = gzipped(&path, meta.modified().unwrap_or(SystemTime::UNIX_EPOCH)).await {
            let _ = res.add_header(header::CONTENT_TYPE, content_type(&mime), true);
            let _ = res.add_header(header::CONTENT_ENCODING, "gzip", true);
            let _ = res.add_header(header::VARY, "Accept-Encoding", true);
            let _ = res.add_header(header::CACHE_CONTROL, "no-cache", true);
            res.status_code(status);
            res.body(body);
            return true;
        }
    }

    if status == StatusCode::OK {
        match NamedFile::builder(&path).build().await {
            Ok(file) => file.send(req.headers(), res).await,
            Err(_) => return false,
        }
    } else {
        let Ok(content) = tokio::fs::read(&path).await else { return false };
        let _ = res.add_header(header::CONTENT_TYPE, content_type(&mime), true);
        res.status_code(status);
        res.body(content);
    }
    true
}

pub async fn serve_static(req: &Request, res: &mut Response, name: &str) {
    if !serve(req, res, name, StatusCode::OK).await {
        not_found(req, res).await;
    }
}

pub async fn not_found(req: &Request, res: &mut Response) {
    if !serve(req, res, "404.html", StatusCode::NOT_FOUND).await {
        res.status_code(StatusCode::NOT_FOUND);
        res.render(Text::Plain("404 Not Found"));
    }
}
