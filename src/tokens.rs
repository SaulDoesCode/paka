//! Token storage. Each token is a file in `tokens/`, named by the keyed hash of the token
//! and holding its encrypted metadata. All functions do blocking IO.

use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::Mutex,
};

use serde::{Deserialize, Serialize};

use crate::{config, crypto};

/// Serialises every read-modify-write of token files, so a token can't be spent twice.
static LOCK: Mutex<()> = Mutex::new(());

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Op {
    /// download a file or read its info
    Read,
    /// upload / overwrite a file
    Write,
    Delete,
    /// list all files
    List,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    /// unix seconds after which the token is dead
    pub exp: u64,
    /// remaining uses
    pub uses: u32,
    /// only valid for this file name
    pub file: Option<String>,
    /// only valid for these operations, all if None
    pub ops: Option<Vec<Op>>,
    /// arbitrary JSON attached by the admin, readable by the token holder
    pub payload: Option<String>,
}

#[derive(Debug)]
pub enum AuthError {
    Invalid,
    Expired,
    OutOfScope,
}

impl Token {
    fn permits(&self, op: Op, file: Option<&str>) -> bool {
        let op_ok = self.ops.as_ref().is_none_or(|ops| ops.contains(&op));
        let file_ok = match (&self.file, file) {
            (None, _) => true,
            (Some(allowed), Some(f)) => allowed == f,
            (Some(_), None) => false,
        };
        op_ok && file_ok
    }

    fn expired(&self) -> bool {
        self.exp <= config::now()
    }
}

fn path_for(token: &str) -> PathBuf {
    PathBuf::from(config::TOKENS_DIR).join(crypto::hash_token(token))
}

fn load(path: &Path) -> Option<Token> {
    let data = fs::read(path).ok()?;
    bincode::deserialize(&crypto::decrypt(&data)?).ok()
}

fn store(path: &Path, token: &Token) -> io::Result<()> {
    let bin = bincode::serialize(token).map_err(io::Error::other)?;
    crypto::write_atomic(path, &crypto::encrypt(&bin)?)
}

/// Creates `count` tokens sharing the same metadata and returns them.
pub fn create(spec: &Token, count: usize) -> io::Result<Vec<String>> {
    let bin = bincode::serialize(spec).map_err(io::Error::other)?;
    let mut tokens = Vec::with_capacity(count);
    while tokens.len() < count {
        let token = crypto::random_string(32);
        // write to a temp file first so readers never see a half-written token,
        // and never overwrite an existing token on a (wildly unlikely) collision
        let mut tmp = tempfile::NamedTempFile::new_in(config::TOKENS_DIR)?;
        io::Write::write_all(&mut tmp, &crypto::encrypt(&bin)?)?;
        match tmp.persist_noclobber(path_for(&token)) {
            Ok(_) => {}
            Err(e) if e.error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.error),
        }
        tokens.push(token);
    }
    Ok(tokens)
}

/// Looks a token up without spending it.
pub fn peek(token: &str) -> Result<Token, AuthError> {
    let path = path_for(token);
    let _guard = LOCK.lock().unwrap();
    let tkn = load(&path).ok_or(AuthError::Invalid)?;
    if tkn.expired() {
        let _ = fs::remove_file(&path);
        return Err(AuthError::Expired);
    }
    Ok(tkn)
}

/// Spends one use of a token for `op` on `file`. Tokens are deleted when used up or expired;
/// an out-of-scope attempt does not spend the token.
pub fn consume(token: &str, op: Op, file: Option<&str>) -> Result<Token, AuthError> {
    let path = path_for(token);
    let _guard = LOCK.lock().unwrap();
    let mut tkn = load(&path).ok_or(AuthError::Invalid)?;
    if tkn.expired() {
        let _ = fs::remove_file(&path);
        return Err(AuthError::Expired);
    }
    if !tkn.permits(op, file) {
        return Err(AuthError::OutOfScope);
    }
    tkn.uses = tkn.uses.saturating_sub(1);
    let saved = if tkn.uses == 0 { fs::remove_file(&path) } else { store(&path, &tkn) };
    match saved {
        Ok(()) => Ok(tkn),
        Err(e) => {
            eprintln!("could not update token file: {e}");
            Err(AuthError::Invalid)
        }
    }
}

/// Deletes expired and unreadable token files, returns how many were removed.
pub fn remove_expired() -> usize {
    let _guard = LOCK.lock().unwrap();
    let Ok(entries) = fs::read_dir(config::TOKENS_DIR) else { return 0 };
    entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file() && !p.file_name().is_none_or(|n| n.to_string_lossy().starts_with('.')))
        .filter(|p| load(p).is_none_or(|t| t.expired()))
        .filter(|p| fs::remove_file(p).is_ok())
        .count()
}

/// Deletes every token, returns how many were removed.
pub fn revoke_all() -> usize {
    let _guard = LOCK.lock().unwrap();
    let Ok(entries) = fs::read_dir(config::TOKENS_DIR) else { return 0 };
    entries.flatten().filter(|e| e.path().is_file() && fs::remove_file(e.path()).is_ok()).count()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(file: Option<&str>, ops: Option<Vec<Op>>) -> Token {
        Token { exp: u64::MAX, uses: 1, file: file.map(String::from), ops, payload: None }
    }

    #[test]
    fn scopes() {
        let any = token(None, None);
        assert!(any.permits(Op::Write, Some("a")) && any.permits(Op::List, None));

        let read_only = token(None, Some(vec![Op::Read]));
        assert!(read_only.permits(Op::Read, Some("a")));
        assert!(!read_only.permits(Op::Delete, Some("a")));

        let one_file = token(Some("a"), None);
        assert!(one_file.permits(Op::Delete, Some("a")));
        assert!(!one_file.permits(Op::Read, Some("b")));
        assert!(!one_file.permits(Op::List, None));
    }

    #[test]
    fn ops_json() {
        let ops: Vec<Op> = serde_json::from_str(r#"["read","write","delete","list"]"#).unwrap();
        assert_eq!(ops, vec![Op::Read, Op::Write, Op::Delete, Op::List]);
    }
}
