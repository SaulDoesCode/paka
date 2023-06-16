use mimalloc::MiMalloc;
use tokio::io::AsyncWriteExt;
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

use std::{io::{self, Read, Write, BufReader}, fs, path::{Path, PathBuf}, sync::Mutex};
use actix_web::{get, delete, post, web, App, HttpResponse, HttpServer, HttpRequest, http::header::{ContentEncoding, self}};
use actix_files::NamedFile;
use base64::{Engine as _};
use cocoon::{Cocoon};
use flate2::{Compression, write::GzEncoder};
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tempfile::NamedTempFile;


const ADMIN_PWD_FILE_PATH: &str = "./admin_pwd.txt";
const TOKENS_DIR: &str = "./tokens";
const STATIC_FILES_DIR: &str = "./static/";
const CERT_PEM: &str = "./secrets/cert.pem";
const PRIV_PEM: &str = "./secrets/priv.pem";
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

lazy_static::lazy_static! {
    static ref ADMIN_PASSWORD: Mutex<String> = Mutex::new(get_admin_password().unwrap_or_else(|| generate_admin_password()));
    static ref HASHER: sthash::Hasher = {
        let key = get_admin_password().expect("could not get admin password for the hasher").as_bytes().to_vec();
        sthash::Hasher::new(sthash::Key::from_seed(key.as_slice(), None), None)
    };
    static ref B64: base64::engine::GeneralPurpose = {
        let abc = base64::alphabet::Alphabet::new("+_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789").expect("aplhabet was too much for base64, sorry");
        base64::engine::GeneralPurpose::new(&abc, base64::engine::general_purpose::GeneralPurposeConfig::new().with_encode_padding(false).with_decode_allow_trailing_bits(true))
    };
}

#[derive(Debug, Serialize, Deserialize)]
struct Token {
    exp: u64,
    bin: Option<Vec<u8>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct MakeTokenRequest{
    count: Option<u64>,
    pwd: String,
    exp: Option<u64>,
    payload: Option<Vec<u8>>,
}

#[post("/make-tokens/{count}")]
async fn generate_token(count: web::Path<usize>, pwd: web::Bytes) -> HttpResponse {
    let admin_password = get_admin_password().expect("could not get admin password for token generation");
    if pwd != admin_password.as_bytes() {
        return HttpResponse::Unauthorized().finish();
    }
    let count = count.into_inner();
    let mut tokens = Vec::new();
    while tokens.len() < count {
        // generate a random token and save it to ./dist/{token}
        let tkn = random_string(24);
        let token = Token {
            exp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + ((3600 * 24) * 1),
            bin: None,
        };
        let hash = HASHER.hash(tkn.as_bytes());
        let encoded_hash = B64.encode(&hash);
        let token_path: PathBuf = format!("{}/{}", TOKENS_DIR, encoded_hash).parse().expect("could not parse token path");
        match tokio::fs::File::create(&token_path).await {
            Ok(mut f) => {
                let bin = encrypt(&token).expect("could not encrypt token");
                match f.write_all(&bin).await {
                    Ok(_) => {
                        // println!("Generated tkn {}", tkn);
                        tokens.push(tkn);
                    },
                    Err(e) => {
                        println!("Failed to write token to file: {}", e);
                        if fs::remove_file(&token_path).is_ok() {
                            println!("Removed failed token file");
                        }
                    }
                }
            },
            Err(e) => {
                println!("Failed to create token file at path {:?} : {}", token_path, e);
                return HttpResponse::InternalServerError().finish();
            }
        }
    }
    HttpResponse::Ok().json(tokens)
}

#[post("/mktn")]
async fn make_token_request(mtr: web::Json<MakeTokenRequest>) -> HttpResponse {
    let admin_password = get_admin_password().expect("could not get admin password for token generation");
    if mtr.pwd != admin_password {
        return HttpResponse::Unauthorized().finish();
    }
    let count = mtr.count.unwrap_or(1) as usize;
    let payload = mtr.payload.clone();
    let exp = mtr.exp.unwrap_or_else(|| std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + ((3600 * 24) * 1));
    std::mem::forget(mtr);
    let mut tokens = Vec::new();
    while tokens.len() < count {
        let tkn = random_string(24);
        // generate a random token and save it to ./dist/{token}
        let token = Token {exp, bin: payload.clone()};
        let hash = HASHER.hash(tkn.as_bytes());
        let encoded_hash = B64.encode(&hash);
        let token_path: PathBuf = format!("{}/{}", TOKENS_DIR, encoded_hash).parse().expect("could not parse token path");
        match tokio::fs::File::create(&token_path).await {
            Ok(mut f) => {
                let bin = encrypt(&token).expect("could not encrypt token");
                match f.write_all(&bin).await {
                    Ok(_) => {
                        // println!("Generated tkn {}", tkn);
                        tokens.push(tkn);
                    },
                    Err(e) => {
                        println!("Failed to write token to file: {}", e);
                        if fs::remove_file(&token_path).is_ok() {
                            println!("Removed failed token file");
                        }
                    }
                }
            },
            Err(e) => {
                println!("Failed to create token file at path {:?} : {}", token_path, e);
                return HttpResponse::InternalServerError().finish();
            }
        }
    }
    HttpResponse::Ok().json(tokens)
}

#[post("/expire-tokens")]
async fn expire_tokens(pwd: web::Bytes) -> HttpResponse {
    let admin_password = ADMIN_PASSWORD.lock().unwrap();
    // validate admin password from bytes
    if pwd != admin_password.as_bytes() {
        return HttpResponse::Unauthorized().finish();
    }

    let mut expired_tokens = Vec::new();
    if let Ok(entries) = fs::read_dir(TOKENS_DIR) {
        for entry in entries {
            if let Ok(entry) = entry {
                let path = entry.path();
                if let Ok(metadata) = fs::metadata(&path) {
                    if metadata.is_file() {
                        let token = decrypt::<Token>(&fs::read(&path).unwrap());
                        if let Some(token) = token {
                            if token.exp < std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() {
                                if fs::remove_file(&path).is_ok() {
                                    expired_tokens.push(path.file_name().unwrap().to_str().unwrap().to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    HttpResponse::Ok().json(expired_tokens)
}

fn encrypt<T: Serialize>(payload: T) -> Option<Vec<u8>> {
    let admin_password = get_admin_password().unwrap();
    let mut serialized_payload = bincode::serialize(&payload).unwrap();
    let cocoon = Cocoon::new(admin_password.as_bytes());
    let detached_prefix = cocoon.encrypt(&mut serialized_payload).unwrap();
    let whole = bincode::serialize(&(serialized_payload.to_vec(), detached_prefix.to_vec())).unwrap();
    Some(whole)
}

fn decrypt<'a, T: serde::de::DeserializeOwned>(
    whole: &'a [u8]
) -> Option<T> {
    let admin_password = get_admin_password().unwrap();
    let (encrypted_payload, detached_prefix): (Vec<u8>, Vec<u8>) = bincode::deserialize(whole).unwrap();
    let mut decrypted_payload = encrypted_payload;
    let cocoon = Cocoon::new(admin_password.as_bytes());
    if cocoon.decrypt(decrypted_payload.as_mut_slice(), &detached_prefix).is_ok() {
        bincode::deserialize(&decrypted_payload).ok()
    } else {
        None
    }
}

#[post("/admin/change-password")]
async fn change_password(new_password: web::Json<String>) -> HttpResponse {
    let mut admin_password = ADMIN_PASSWORD.lock().unwrap();
    *admin_password = new_password.into_inner();
    set_admin_password(&admin_password).unwrap();
    HttpResponse::Ok().finish()
}

#[get("/file-info/{filename}")]
async fn get_file_info(req: HttpRequest, filename: web::Path<String>) -> HttpResponse {
    if !authenticate_token(&req) {
        return HttpResponse::Unauthorized().finish();
    }

    let path = format!("./dist/{}", filename);

    let file_info = fs::metadata(&path)
        .map(|metadata| {
            json!({
                "filename": filename.as_str(),
                "size": metadata.len(),
            })
        })
        .unwrap_or_else(|_| json!({"error": "File not found"}));

    HttpResponse::Ok().json(file_info)
}

#[post("/file/{filename}")]
async fn upload_file(req: HttpRequest, filename: web::Path<String>, payload: web::Bytes) -> HttpResponse {
    if !authenticate_token(&req) {
        return HttpResponse::Unauthorized().finish();
    }
    let path = format!("./dist/{}", filename);
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(&encrypt(&*payload).unwrap()).unwrap();
    file.persist(Path::new(&path)).unwrap();
    HttpResponse::Ok().finish()
}

#[get("/file/{filename}")]
async fn download_file(req: HttpRequest, filename: web::Path<String>) -> HttpResponse {
    if !authenticate_token(&req) {
        return HttpResponse::Unauthorized().finish();
    }

    let path = format!("./dist/{}", filename);

    match fs::read(&path) {
        Ok(data) => HttpResponse::Ok().body(decrypt::<Vec<u8>>(&data).expect("Failed to decrypt file, might be the pwd changed")),
        Err(_) => HttpResponse::NotFound().finish(),
    }
}

#[delete("/file/{filename}")]
async fn delete_file(req: HttpRequest, filename: web::Path<String>) -> HttpResponse {
    if !authenticate_token(&req) {
        return HttpResponse::Unauthorized().finish();
    }

    let path = format!("./dist/{}", filename);

    match fs::remove_file(&path) {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(_) => HttpResponse::NotFound().finish(),
    }
}

#[get("/static/{filename}")]
async fn srv_stc_files(req: HttpRequest, filename: web::Path<String>) -> HttpResponse {
    serve_static_files(req, filename.into_inner()).await
}

async fn serve_static_files(req: HttpRequest, filename: String) -> HttpResponse {
    if let Some(ae) = req.headers().get(header::ACCEPT_ENCODING) {
        if let Ok(accept_encoding) = ae.to_str() {
            if accept_encoding.contains("gzip") {
                return serve_gzipped_static_files(&req, filename.to_string());
            }
        }
    }

    let file_path = format!("{}{}", STATIC_FILES_DIR, filename);
    if let Ok(file) = NamedFile::open(&file_path) {
        return file.into_response(&req);
    }

    NamedFile::open(format!("{}404.html", STATIC_FILES_DIR)).expect("404 itself was lost").into_response(&req)
}

#[post("/remove-gz-files")]
async fn remove_gz_files(pwd: web::Bytes) -> HttpResponse {
    if let Some(ap) = get_admin_password() {
        if ap.as_bytes() != pwd {
            return HttpResponse::Unauthorized().finish();
        }
    } else {
        return HttpResponse::Unauthorized().finish();
    }
    // look in the ./static directory and remove all the files that end with .gz
    let static_dir = Path::new("./static");
    if let Ok(entries) = fs::read_dir(static_dir) {
        for entry in entries {
            if let Ok(entry) = entry {
                let path = entry.path();
                if let Some(ext) = path.extension() {
                    if ext == "gz" {
                        if let Err(e) = fs::remove_file(path) {
                            println!("Failed to remove file: {:?}", e);
                        }
                    }
                }
            }
        }
    }
    HttpResponse::Ok().finish()
}

fn serve_gzipped_static_files(req: &HttpRequest, filename: String) -> HttpResponse {
    let file_path = format!("{}{}", STATIC_FILES_DIR, filename);
    let gzipped_file_path = format!("{}.gz", &file_path);
    let ct = mime_guess::from_path(&file_path).first_or_octet_stream();
    if let Ok(file) = NamedFile::open(&gzipped_file_path) {
        let mut res = file.set_content_encoding(ContentEncoding::Gzip).into_response(req);
        res.headers_mut().insert(
            header::VARY,
            header::HeaderValue::from_static("Accept-Encoding")
        );
        res.headers_mut().insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_str(&ct.to_string()).unwrap()
        );
        if filename.starts_with("404") {
            res.head_mut().status = actix_web::http::StatusCode::NOT_FOUND;
        }
        res.headers_mut().insert(
            header::CONTENT_DISPOSITION,
            header::HeaderValue::from_static("inline")
        );
        return res;
    } else if Path::new(&file_path).exists() {
        if let Ok(file) = NamedFile::open(&file_path) {
            if should_compress(&file) {
                if let Some(compressed_content) = compress_content(&file) {
                    if let Err(err) = fs::write(&gzipped_file_path, compressed_content) {
                        eprintln!("Failed to write compressed file: {}", err);
                    } else {
                        return serve_gzipped_static_files(req, filename);
                    }
                }
            }
            return file.into_response(req);
        }
    }
    // serve_gzipped_static_files(req, "./static/404.html".to_string())
    let mut res = NamedFile::open(format!("{}404.html.gz", STATIC_FILES_DIR))
        .expect("404 gzipped not even found")
        .set_content_encoding(ContentEncoding::Gzip)
        .into_response(&req);
    res.head_mut().status = actix_web::http::StatusCode::NOT_FOUND;
    res.headers_mut().insert(
        header::VARY,
        header::HeaderValue::from_static("Accept-Encoding")
    );
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("text/html")
    );
    res.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        header::HeaderValue::from_static("inline")
    );
    res
}

fn should_compress(file: &NamedFile) -> bool {
    let mime_type = file.content_type();
    GZIPABLE_TYPES.contains(&mime_type.to_string().as_str())
}

fn compress_content(file: &NamedFile) -> Option<Vec<u8>> {
    let mut file = file.file();
    let mut content = Vec::new();
    if let Ok(_) = file.read_to_end(&mut content) {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        if let Ok(_) = encoder.write_all(&content) {
            if let Ok(compressed) = encoder.finish() {
                return Some(compressed);
            }
        }
    }
    None
}

#[get("/")]
async fn serve_index(req: HttpRequest) -> HttpResponse {
    serve_static_files(req, format!("{}index.html", STATIC_FILES_DIR)).await
}

fn get_query_param_value(query_string: &str, key: &str) -> Option<String> {
    let params: Vec<&str> = query_string.split('&').collect();
    for param in params {
        let parts: Vec<&str> = param.split('=').collect();
        if parts.len() == 2 && parts[0] == key {
            return Some(parts[1].to_string());
        }
    }
    None
}

fn authenticate_token(req: &HttpRequest) -> bool {
    let token = match get_query_param_value(&req.query_string(), "tk") {
        Some(tkn) => B64.encode(&HASHER.hash(tkn.as_bytes())),
        _ => return false,
    };
    
    let token_file_path = format!("{}/{}", TOKENS_DIR, token);
    if !Path::new(&token_file_path).exists() {
        return false;
    }
    
    match fs::read(&token_file_path) {
        Ok(token_file) => {
            let tkn = match decrypt::<Token>(&token_file) {
                Some(t) => t,
                None => return false,
            };
            
            if tkn.exp < std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() {
                return false;
            }
            if let Err(err) = fs::remove_file(&token_file_path) {
                eprintln!("Failed to remove token file: {}", err);
            }
            return true;
        }
        Err(err) => eprintln!("Failed to read token file: {}", err),
    }
    false
 }


fn generate_admin_password() -> String {
    let password = generate_random_password();
    set_admin_password(&password).unwrap();
    password
}

fn generate_random_password() -> String {
    random_string(32)
}

fn get_admin_password() -> Option<String> {
    match fs::read_to_string(ADMIN_PWD_FILE_PATH) {
        Ok(password) => Some(password.trim().to_string()),
        Err(_) => None,
    }
}

fn set_admin_password(password: &str) -> io::Result<()> {
    fs::write(ADMIN_PWD_FILE_PATH, password)
}

fn random_string(len: usize) -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .map(char::from)
        .take(len).collect()
}

#[allow(dead_code)]
fn random_bytes(len: usize) -> Vec<u8> {
    (0..len).map(|_| rand::random::<u8>()).collect()
}

#[actix_web::main]
async fn main() -> io::Result<()> {
    fs::create_dir_all(TOKENS_DIR)?;
    let _ampwd = get_admin_password().unwrap_or_else(|| {
        let password = random_string(32);
        set_admin_password(&password).unwrap();
        password
    });

    let tls_config = load_rustls_config();

    HttpServer::new(|| {
        App::new()
            .service(generate_token)
            .service(make_token_request)
            .service(change_password)
            .service(expire_tokens)
            .service(remove_gz_files)
            .service(get_file_info)
            .service(upload_file)
            .service(delete_file)
            .service(download_file)
            .service(serve_index)
            .service(srv_stc_files)
    })
    .bind_rustls(("0.0.0.0", 8000), tls_config)?
    .run().await
}

fn load_rustls_config() -> rustls::ServerConfig {
    // init server config builder with safe defaults
    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth();

    // load TLS key/cert files
    let cert_file = &mut BufReader::new(fs::File::open(CERT_PEM).expect(format!("Could not open cert file at {}.", CERT_PEM).as_str()));
    let key_file = &mut BufReader::new(fs::File::open(PRIV_PEM).expect(format!("Could not open priv/key file at {}.", PRIV_PEM).as_str()));

    // convert files to key/cert objects
    let cert_chain = certs(cert_file)
        .unwrap()
        .into_iter()
        .map(Certificate)
        .collect();
    let mut keys: Vec<PrivateKey> = pkcs8_private_keys(key_file)
        .unwrap()
        .into_iter()
        .map(PrivateKey)
        .collect();

    // exit if no keys could be parsed
    if keys.is_empty() {
        eprintln!("Could not locate PKCS 8 private keys.");
        std::process::exit(1);
    }

    config.with_single_cert(cert_chain, keys.remove(0)).unwrap()
}