//! Preview route token issuance and authentication primitives.
//!
//! Raw route and optional HTTP credentials are returned only when a preview is
//! created. Persistence stores only a domain-separated HMAC of the route token.

use std::{fmt, time::Duration};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use box_core::{
    AccountContext, BoxId, DomainError, DomainErrorKind, Preview, PreviewAuth, PreviewId,
    UtcEpochMillis,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

const KEY_BYTES: usize = 32;
const DEFAULT_TTL: Duration = Duration::from_secs(30 * 60);
const CONTROL_PORT: u16 = 18_080;
const TERMINAL_PORT: u16 = 18_081;
const BASIC_USERNAME: &str = "boxd";

fn internal(message: impl Into<String>) -> DomainError {
    DomainError {
        kind: DomainErrorKind::Internal,
        code: "preview_error",
        message: message.into(),
    }
}

/// Server-side secret used for preview token digests and derived credentials.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PreviewSigningKey([u8; KEY_BYTES]);

impl PreviewSigningKey {
    pub fn from_slice(value: &[u8]) -> box_core::Result<Self> {
        let value: [u8; KEY_BYTES] = value
            .try_into()
            .map_err(|_| DomainError::validation("preview signing key must contain 32 bytes"))?;
        Ok(Self(value))
    }
}

impl fmt::Debug for PreviewSigningKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreviewSigningKey([REDACTED])")
    }
}

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct PreviewRouteToken(String);

impl PreviewRouteToken {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for PreviewRouteToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreviewRouteToken([REDACTED])")
    }
}

impl fmt::Display for PreviewRouteToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct PreviewCredential(String);

impl PreviewCredential {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for PreviewCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreviewCredential([REDACTED])")
    }
}

impl fmt::Display for PreviewCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssuedPreviewCredential {
    Public,
    Bearer {
        token: PreviewCredential,
    },
    Basic {
        username: String,
        password: PreviewCredential,
    },
}

pub struct IssuedPreview {
    pub preview: Preview,
    pub route_token: PreviewRouteToken,
    pub credential: IssuedPreviewCredential,
}

impl fmt::Debug for IssuedPreview {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuedPreview")
            .field("preview", &self.preview)
            .field("route_token", &"[REDACTED]")
            .field("credential", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone)]
pub struct PreviewTokenCodec {
    key: PreviewSigningKey,
    ttl: Duration,
}

impl PreviewTokenCodec {
    pub fn new(key: PreviewSigningKey) -> Self {
        Self {
            key,
            ttl: DEFAULT_TTL,
        }
    }

    pub fn with_ttl(mut self, ttl: Duration) -> box_core::Result<Self> {
        if ttl.is_zero() || ttl > DEFAULT_TTL {
            return Err(DomainError::validation(
                "preview TTL must be between 1 millisecond and 30 minutes",
            ));
        }
        self.ttl = ttl;
        Ok(self)
    }

    pub fn issue(
        &self,
        context: AccountContext,
        box_id: BoxId,
        port: u16,
        auth: PreviewAuth,
        at: UtcEpochMillis,
    ) -> box_core::Result<IssuedPreview> {
        validate_port(port)?;
        let id = PreviewId::new();
        let route_token = self.route_token_for_id(id);
        let token_hmac = self.route_digest(route_token.expose());
        let credential = self.credentials(auth, route_token.expose());
        let ttl_millis = i64::try_from(self.ttl.as_millis()).unwrap_or(i64::MAX);
        let expires_at = UtcEpochMillis::from_millis(at.as_millis().saturating_add(ttl_millis));
        Ok(IssuedPreview {
            preview: Preview {
                id,
                account_id: context.account_id,
                tenant_id: context.tenant_id,
                box_id,
                port,
                auth,
                token_hmac,
                expires_at,
                created_at: at,
                updated_at: at,
            },
            route_token,
            credential,
        })
    }

    pub fn route_digest(&self, route_token: &str) -> String {
        hex::encode(self.digest(b"boxd-preview-route-v1", route_token.as_bytes()))
    }

    pub fn route_token_for_preview(
        &self,
        preview: &Preview,
    ) -> box_core::Result<PreviewRouteToken> {
        let token = self.route_token_for_id(preview.id);
        if !constant_time_hex_eq(&preview.token_hmac, &self.route_digest(token.expose())) {
            return Err(internal("preview route identity is inconsistent"));
        }
        Ok(token)
    }

    pub fn is_expired(&self, preview: &Preview, at: UtcEpochMillis) -> bool {
        preview.expires_at <= at
    }

    pub fn authorize(
        &self,
        preview: &Preview,
        route_token: &str,
        authorization: Option<&str>,
        at: UtcEpochMillis,
    ) -> bool {
        if self.is_expired(preview, at)
            || !constant_time_hex_eq(&preview.token_hmac, &self.route_digest(route_token))
        {
            return false;
        }
        match preview.auth {
            PreviewAuth::Public => true,
            PreviewAuth::Bearer => {
                let Some(value) = authorization.and_then(|value| value.strip_prefix("Bearer "))
                else {
                    return false;
                };
                let expected = self.derived_credential(b"boxd-preview-bearer-v1", route_token);
                expected.as_bytes().ct_eq(value.as_bytes()).into()
            }
            PreviewAuth::Basic => {
                let Some(value) = authorization.and_then(|value| value.strip_prefix("Basic "))
                else {
                    return false;
                };
                let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(value) else {
                    return false;
                };
                let expected = format!(
                    "{BASIC_USERNAME}:{}",
                    self.derived_credential(b"boxd-preview-basic-v1", route_token)
                );
                expected.as_bytes().ct_eq(&decoded).into()
            }
        }
    }

    fn credentials(&self, auth: PreviewAuth, route_token: &str) -> IssuedPreviewCredential {
        match auth {
            PreviewAuth::Public => IssuedPreviewCredential::Public,
            PreviewAuth::Bearer => IssuedPreviewCredential::Bearer {
                token: PreviewCredential(
                    self.derived_credential(b"boxd-preview-bearer-v1", route_token),
                ),
            },
            PreviewAuth::Basic => IssuedPreviewCredential::Basic {
                username: BASIC_USERNAME.to_owned(),
                password: PreviewCredential(
                    self.derived_credential(b"boxd-preview-basic-v1", route_token),
                ),
            },
        }
    }

    fn route_token_for_id(&self, id: PreviewId) -> PreviewRouteToken {
        let id = id.to_string();
        let tag = self.digest(b"boxd-preview-route-id-v1", id.as_bytes());
        let mut value = Vec::with_capacity(id.len() + 1 + tag.len());
        value.extend_from_slice(id.as_bytes());
        value.push(0);
        value.extend_from_slice(&tag);
        PreviewRouteToken(URL_SAFE_NO_PAD.encode(value))
    }

    fn derived_credential(&self, domain: &[u8], route_token: &str) -> String {
        URL_SAFE_NO_PAD.encode(self.digest(domain, route_token.as_bytes()))
    }

    fn digest(&self, domain: &[u8], value: &[u8]) -> [u8; 32] {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key.0).expect("HMAC accepts any key");
        mac.update(domain);
        mac.update(&[0]);
        mac.update(value);
        mac.finalize().into_bytes().into()
    }
}

pub fn validate_port(port: u16) -> box_core::Result<()> {
    if port == 0 || matches!(port, CONTROL_PORT | TERMINAL_PORT) {
        return Err(DomainError::validation("invalid or reserved preview port"));
    }
    Ok(())
}

fn constant_time_hex_eq(left: &str, right: &str) -> bool {
    let (Ok(left), Ok(right)) = (hex::decode(left), hex::decode(right)) else {
        return false;
    };
    left.ct_eq(&right).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use box_core::{AccountId, TenantId};

    fn context() -> AccountContext {
        AccountContext {
            account_id: AccountId::new(),
            tenant_id: TenantId::new(),
        }
    }

    fn codec() -> PreviewTokenCodec {
        PreviewTokenCodec::new(PreviewSigningKey::from_slice(&[7; 32]).unwrap())
    }

    #[test]
    fn issues_random_route_tokens_and_stores_only_a_digest() {
        let first = codec()
            .issue(
                context(),
                BoxId::new(),
                3_000,
                PreviewAuth::Public,
                UtcEpochMillis::from_millis(10),
            )
            .unwrap();
        let second = codec()
            .issue(
                context(),
                BoxId::new(),
                3_000,
                PreviewAuth::Public,
                UtcEpochMillis::from_millis(10),
            )
            .unwrap();
        assert_ne!(first.route_token.expose(), second.route_token.expose());
        assert_ne!(first.preview.token_hmac, second.preview.token_hmac);
        assert!(
            !first
                .preview
                .token_hmac
                .contains(first.route_token.expose())
        );
        assert_eq!(first.preview.token_hmac.len(), 64);
        assert_eq!(first.preview.expires_at.as_millis(), 1_800_010);
    }

    #[test]
    fn bearer_and_basic_credentials_are_derived_and_constant_time_checked() {
        let bearer = codec()
            .issue(
                context(),
                BoxId::new(),
                3_001,
                PreviewAuth::Bearer,
                UtcEpochMillis::from_millis(0),
            )
            .unwrap();
        let IssuedPreviewCredential::Bearer { token } = &bearer.credential else {
            panic!("expected bearer credential");
        };
        assert!(codec().authorize(
            &bearer.preview,
            bearer.route_token.expose(),
            Some(&format!("Bearer {}", token.expose())),
            UtcEpochMillis::from_millis(1),
        ));
        assert!(!codec().authorize(
            &bearer.preview,
            bearer.route_token.expose(),
            Some("Bearer wrong"),
            UtcEpochMillis::from_millis(1),
        ));

        let basic = codec()
            .issue(
                context(),
                BoxId::new(),
                3_002,
                PreviewAuth::Basic,
                UtcEpochMillis::from_millis(0),
            )
            .unwrap();
        let IssuedPreviewCredential::Basic { username, password } = &basic.credential else {
            panic!("expected basic credential");
        };
        let header = base64::engine::general_purpose::STANDARD
            .encode(format!("{username}:{}", password.expose()));
        assert!(codec().authorize(
            &basic.preview,
            basic.route_token.expose(),
            Some(&format!("Basic {header}")),
            UtcEpochMillis::from_millis(1),
        ));
        assert!(!codec().authorize(
            &basic.preview,
            basic.route_token.expose(),
            Some("Basic bm9wZQ=="),
            UtcEpochMillis::from_millis(1),
        ));
    }

    #[test]
    fn tamper_expiry_reserved_port_and_redaction_fail_closed() {
        let issued = codec()
            .with_ttl(Duration::from_millis(5))
            .unwrap()
            .issue(
                context(),
                BoxId::new(),
                3_003,
                PreviewAuth::Public,
                UtcEpochMillis::from_millis(10),
            )
            .unwrap();
        assert!(!codec().authorize(
            &issued.preview,
            "tampered",
            None,
            UtcEpochMillis::from_millis(11),
        ));
        assert!(!codec().authorize(
            &issued.preview,
            issued.route_token.expose(),
            None,
            UtcEpochMillis::from_millis(15),
        ));
        assert!(validate_port(0).is_err());
        assert!(validate_port(CONTROL_PORT).is_err());
        assert!(validate_port(TERMINAL_PORT).is_err());
        assert!(!format!("{issued:?}").contains(issued.route_token.expose()));
        assert!(!format!("{:?}", codec().key).contains("0707"));
    }
}
