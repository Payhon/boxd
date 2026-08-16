//! Tenant-bound envelope encryption.  Callers own master-key retrieval.

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroizing;

const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;

/// Supplies master-key bytes without coupling this crate to configuration or environment paths.
pub trait MasterKeySource: Send + Sync {
    fn master_key(&self) -> Result<Vec<u8>, SecretError>;
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretRef {
    pub account_id: String,
    pub tenant_id: String,
    pub box_id: String,
    pub kind: String,
    pub name: String,
}

impl SecretRef {
    fn aad(&self) -> Vec<u8> {
        // Length prefixes make this binding unambiguous even when ids contain separators.
        let mut out = b"boxd-secret-v1".to_vec();
        for part in [
            &self.account_id,
            &self.tenant_id,
            &self.box_id,
            &self.kind,
            &self.name,
        ] {
            out.extend_from_slice(&(part.len() as u32).to_be_bytes());
            out.extend_from_slice(part.as_bytes());
        }
        out
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedSecret {
    pub reference: SecretRef,
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
}

impl fmt::Debug for EncryptedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedSecret")
            .field("reference", &self.reference)
            .field("ciphertext", &"[REDACTED]")
            .field("nonce", &"[REDACTED]")
            .finish()
    }
}
impl fmt::Display for EncryptedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EncryptedSecret(reference={:?}, payload=[REDACTED])",
            self.reference
        )
    }
}
impl fmt::Debug for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretRef")
            .field("account_id", &self.account_id)
            .field("tenant_id", &self.tenant_id)
            .field("box_id", &self.box_id)
            .field("kind", &self.kind)
            .field("name", &self.name)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretError {
    InvalidMasterKey,
    EncryptFailed,
    DecryptFailed,
    RandomFailed,
}
impl fmt::Display for SecretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidMasterKey => "invalid master key",
            Self::EncryptFailed => "secret encryption failed",
            Self::DecryptFailed => "secret decryption failed",
            Self::RandomFailed => "secure randomness unavailable",
        })
    }
}
impl std::error::Error for SecretError {}

fn cipher(source: &dyn MasterKeySource) -> Result<XChaCha20Poly1305, SecretError> {
    let key = Zeroizing::new(source.master_key()?);
    if key.len() != KEY_LEN {
        return Err(SecretError::InvalidMasterKey);
    }
    XChaCha20Poly1305::new_from_slice(&key).map_err(|_| SecretError::InvalidMasterKey)
}

pub fn encrypt(
    source: &dyn MasterKeySource,
    reference: SecretRef,
    plaintext: &[u8],
) -> Result<EncryptedSecret, SecretError> {
    let cipher = cipher(source)?;
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|_| SecretError::RandomFailed)?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &reference.aad(),
            },
        )
        .map_err(|_| SecretError::EncryptFailed)?;
    Ok(EncryptedSecret {
        reference,
        ciphertext,
        nonce: nonce.to_vec(),
    })
}

pub fn decrypt(
    source: &dyn MasterKeySource,
    secret: &EncryptedSecret,
    expected: &SecretRef,
) -> Result<Zeroizing<Vec<u8>>, SecretError> {
    if &secret.reference != expected || secret.nonce.len() != NONCE_LEN {
        return Err(SecretError::DecryptFailed);
    }
    let cipher = cipher(source).map_err(|_| SecretError::DecryptFailed)?;
    cipher
        .decrypt(
            XNonce::from_slice(&secret.nonce),
            Payload {
                msg: &secret.ciphertext,
                aad: &expected.aad(),
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| SecretError::DecryptFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    struct K;
    impl MasterKeySource for K {
        fn master_key(&self) -> Result<Vec<u8>, SecretError> {
            Ok(vec![7; 32])
        }
    }
    fn r(t: &str) -> SecretRef {
        SecretRef {
            account_id: "a".into(),
            tenant_id: t.into(),
            box_id: "b".into(),
            kind: "env".into(),
            name: "TOKEN".into(),
        }
    }
    #[test]
    fn roundtrip_and_nonce_is_random() {
        let a = encrypt(&K, r("t"), b"fixture-secret").unwrap();
        let b = encrypt(&K, r("t"), b"fixture-secret").unwrap();
        assert_ne!(a.nonce, b.nonce);
        assert_eq!(&*decrypt(&K, &a, &r("t")).unwrap(), b"fixture-secret");
    }
    #[test]
    fn binding_and_tamper_fail_without_oracle() {
        let mut s = encrypt(&K, r("t"), b"x").unwrap();
        assert_eq!(
            decrypt(&K, &s, &r("other")).unwrap_err(),
            SecretError::DecryptFailed
        );
        s.ciphertext[0] ^= 1;
        assert_eq!(
            decrypt(&K, &s, &r("t")).unwrap_err(),
            SecretError::DecryptFailed
        );
    }
    #[test]
    fn redaction_does_not_log_plaintext() {
        let s = encrypt(&K, r("t"), b"fixture-secret").unwrap();
        let debug = format!("{s:?}");
        assert!(!debug.contains("fixture-secret"));
        assert!(!format!("{s}").contains("fixture-secret"));
        assert!(serde_json::to_string(&s).unwrap().contains("ciphertext"));
    }
}
