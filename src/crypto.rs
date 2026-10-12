//! Key material, at-rest encryption, token hashing and the admin password.
//!
//! Everything on disk is encrypted with a random 32 byte master key kept in
//! `secrets/master.key`. The admin password is only stored as an argon2 hash,
//! so changing it never invalidates stored files or outstanding tokens.

use std::{
    fs,
    io::{self, Write},
    path::Path,
    sync::{OnceLock, RwLock},
};

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use cocoon::MiniCocoon;
use rand::{distributions::Alphanumeric, thread_rng, Rng, RngCore};
use tempfile::NamedTempFile;

use crate::config;

struct Keys {
    master: [u8; 32],
    hasher: sthash::Hasher,
}

static KEYS: OnceLock<Keys> = OnceLock::new();
static ADMIN_HASH: OnceLock<RwLock<String>> = OnceLock::new();

fn keys() -> &'static Keys {
    KEYS.get().expect("crypto::init_master_key was not called")
}

/// Loads the master key, creating it on first run. Returns true if it was created.
pub fn init_master_key() -> io::Result<bool> {
    let path = Path::new(config::MASTER_KEY_FILE);
    let (master, created) = match fs::read(path) {
        Ok(bytes) => {
            let master: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, format!("{} must contain exactly 32 bytes", path.display()))
            })?;
            (master, false)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let mut master = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut master);
            write_atomic(path, &master)?;
            (master, true)
        }
        Err(e) => return Err(e),
    };
    let hasher = sthash::Hasher::new(sthash::Key::from_seed(&master, Some(b"paka-token")), None);
    let _ = KEYS.set(Keys { master, hasher });
    Ok(created)
}

/// Encrypts `data` with the master key (ChaCha20-Poly1305, random nonce).
pub fn encrypt(data: &[u8]) -> io::Result<Vec<u8>> {
    let mut seed = [0u8; 32];
    thread_rng().fill_bytes(&mut seed);
    MiniCocoon::from_key(&keys().master, &seed)
        .wrap(data)
        .map_err(|e| io::Error::other(format!("encryption failed: {e:?}")))
}

/// Decrypts data produced by [`encrypt`], None if it was tampered with or uses another key.
pub fn decrypt(data: &[u8]) -> Option<Vec<u8>> {
    MiniCocoon::from_key(&keys().master, &[0u8; 32]).unwrap(data).ok()
}

/// Size of the plaintext inside an encrypted container of `len` bytes.
pub fn plaintext_len(len: u64) -> u64 {
    len.saturating_sub(cocoon::MINI_PREFIX_SIZE as u64)
}

/// The on-disk name for a token: a keyed hash, so token files can't be turned back into tokens.
pub fn hash_token(token: &str) -> String {
    URL_SAFE_NO_PAD.encode(keys().hasher.hash(token.as_bytes()))
}

pub fn random_string(len: usize) -> String {
    thread_rng().sample_iter(&Alphanumeric).map(char::from).take(len).collect()
}

/// Writes a file atomically (temp file in the same directory, then rename), owner-only permissions.
pub fn write_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let mut tmp = NamedTempFile::new_in(dir)?;
    tmp.write_all(data)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| e.error)?;
    Ok(())
}

// ---- admin password ----

fn admin_hash() -> &'static RwLock<String> {
    ADMIN_HASH.get_or_init(|| RwLock::new(String::new()))
}

pub fn set_admin_password(password: &str) -> io::Result<()> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| io::Error::other(format!("could not hash password: {e}")))?
        .to_string();
    write_atomic(Path::new(config::ADMIN_PWD_FILE), hash.as_bytes())?;
    *admin_hash().write().unwrap() = hash;
    Ok(())
}

/// Slow (argon2), call it from a blocking context.
pub fn verify_admin_password(password: &[u8]) -> bool {
    let hash = admin_hash().read().unwrap().clone();
    match PasswordHash::new(&hash) {
        Ok(parsed) => Argon2::default().verify_password(password, &parsed).is_ok(),
        Err(_) => false,
    }
}

/// Sets up the admin password on startup, in order of preference:
/// `PAKA_ADMIN_PWD` env var, the stored argon2 hash, a legacy plaintext password
/// (which is migrated), or a freshly generated password that is printed once.
pub fn init_admin_password() -> io::Result<()> {
    if let Ok(pwd) = std::env::var("PAKA_ADMIN_PWD") {
        if !pwd.trim().is_empty() {
            set_admin_password(pwd.trim())?;
            println!("admin password set from PAKA_ADMIN_PWD");
            return Ok(());
        }
    }
    match fs::read_to_string(config::ADMIN_PWD_FILE) {
        Ok(stored) if stored.trim().starts_with("$argon2") => {
            *admin_hash().write().unwrap() = stored.trim().to_string();
            Ok(())
        }
        Ok(stored) if !stored.trim().is_empty() => {
            let legacy = stored.trim().to_string();
            migrate_legacy(&legacy);
            set_admin_password(&legacy)?;
            println!("migrated plaintext {} to an argon2 hash, the password is unchanged", config::ADMIN_PWD_FILE);
            Ok(())
        }
        Ok(_) => generate_admin_password(),
        Err(e) if e.kind() == io::ErrorKind::NotFound => generate_admin_password(),
        Err(e) => Err(e),
    }
}

fn generate_admin_password() -> io::Result<()> {
    let pwd = random_string(32);
    set_admin_password(&pwd)?;
    println!("================================================================");
    println!(" generated admin password (shown once, only its hash is stored):");
    println!("   {pwd}");
    println!(" restart with PAKA_ADMIN_PWD=... to set a different one");
    println!("================================================================");
    Ok(())
}

/// Older versions encrypted files with a key derived from the plaintext admin password.
/// Re-encrypt those with the master key; old tokens can't be migrated and are dropped.
fn migrate_legacy(password: &str) {
    let legacy = cocoon::Cocoon::new(password.as_bytes());
    let (mut migrated, mut failed) = (0, 0);
    if let Ok(entries) = fs::read_dir(config::DIST_DIR) {
        for path in entries.flatten().map(|e| e.path()).filter(|p| p.is_file()) {
            let plain = fs::read(&path).ok().and_then(|whole| {
                let (mut data, prefix): (Vec<u8>, Vec<u8>) = bincode::deserialize(&whole).ok()?;
                legacy.decrypt(&mut data, &prefix).ok()?;
                bincode::deserialize::<Vec<u8>>(&data).ok()
            });
            match plain.map(|p| encrypt(&p).and_then(|enc| write_atomic(&path, &enc))) {
                Some(Ok(())) => migrated += 1,
                _ => {
                    eprintln!("could not migrate {}, leaving it as is", path.display());
                    failed += 1;
                }
            }
        }
    }
    if let Ok(entries) = fs::read_dir(config::TOKENS_DIR) {
        for entry in entries.flatten() {
            let _ = fs::remove_file(entry.path());
        }
    }
    println!("legacy migration: {migrated} files re-encrypted, {failed} failed, old tokens removed");
}
