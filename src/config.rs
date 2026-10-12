//! Paths and settings. Paths are relative to the working directory; the rest can be set by env vars.

use std::{env, str::FromStr};

pub const ADMIN_PWD_FILE: &str = "./admin_pwd.txt";
pub const MASTER_KEY_FILE: &str = "./secrets/master.key";
pub const SECRETS_DIR: &str = "./secrets";
pub const TOKENS_DIR: &str = "./tokens";
pub const DIST_DIR: &str = "./dist";
pub const STATIC_DIR: &str = "./static";

/// Most tokens a single request may create.
pub const MAX_TOKENS_PER_REQUEST: usize = 1000;

pub struct Config {
    pub addr: String,
    pub port: u16,
    pub cert: String,
    pub key: String,
    pub max_upload_bytes: usize,
    pub token_ttl_secs: u64,
}

fn var<T: FromStr>(name: &str, default: T) -> T {
    match env::var(name) {
        Ok(v) => v.parse().unwrap_or_else(|_| {
            eprintln!("ignoring invalid {name}={v}");
            default
        }),
        Err(_) => default,
    }
}

impl Config {
    pub fn from_env() -> Self {
        Config {
            addr: var("PAKA_ADDR", "0.0.0.0".to_string()),
            port: var("PAKA_PORT", 9797),
            cert: var("PAKA_CERT", "./secrets/cert.pem".to_string()),
            key: var("PAKA_KEY", "./secrets/priv.pem".to_string()),
            max_upload_bytes: var("PAKA_MAX_UPLOAD_MB", 64usize).saturating_mul(1024 * 1024),
            token_ttl_secs: var("PAKA_TOKEN_TTL", 60 * 60 * 24),
        }
    }
}

pub fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()
}

/// Accepts plain file names only: no paths, no hidden files, no control characters.
pub fn valid_filename(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && !name.starts_with('.')
        && !name.chars().any(|c| c == '/' || c == '\\' || c.is_control())
}

#[cfg(test)]
mod tests {
    use super::valid_filename;

    #[test]
    fn filenames() {
        for ok in ["a.txt", "music cool.mp3", "ünïcode", "a..b"] {
            assert!(valid_filename(ok), "{ok}");
        }
        for bad in ["", ".", "..", ".hidden", "../x", "a/b", "a\\b", "a\nb", &"x".repeat(256)] {
            assert!(!valid_filename(bad), "{bad}");
        }
    }
}
