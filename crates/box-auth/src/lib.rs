//! Authentication primitives and composition adapters.
//!
//! Compatibility API keys and console sessions intentionally use separate
//! authenticators. Plaintext credentials are only returned at creation and
//! are represented by redacted, zeroizing types.

use std::{collections::BTreeSet, fmt};

use argon2::{
    Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version,
    password_hash::SaltString,
};
use async_trait::async_trait;
use box_core::{AccountContext, AuthScope, AuthorizedContext, DomainError, DomainErrorKind};
use box_db::{
    AdminSessionStore, ApiKeyStore, BootstrapSeed, BootstrapStore, DatabaseHandle,
    SessionCandidate, SessionInsert, UserRecord, UserStore,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use uuid::Uuid;
use zeroize::Zeroizing;

const PASSWORD_MEMORY_KIB: u32 = 65_536;
const PASSWORD_ITERATIONS: u32 = 3;
const PASSWORD_PARALLELISM: u32 = 1;
const PASSWORD_OUTPUT_BYTES: usize = 32;
const SESSION_TOKEN_BYTES: usize = 32;
const MAX_SESSION_TTL_MILLIS: i64 = 7 * 24 * 60 * 60 * 1_000;

fn unauthorized() -> DomainError {
    DomainError {
        kind: DomainErrorKind::Ownership,
        code: "unauthorized",
        message: "invalid credentials".to_owned(),
    }
}

fn internal(message: impl Into<String>) -> DomainError {
    DomainError {
        kind: DomainErrorKind::Internal,
        code: "authentication_error",
        message: message.into(),
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PasswordDigest(String);

impl PasswordDigest {
    pub fn as_phc(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for PasswordDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PasswordDigest([REDACTED])")
    }
}

impl fmt::Display for PasswordDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

#[derive(Clone)]
pub struct PasswordService {
    argon2: Argon2<'static>,
}

impl PasswordService {
    pub fn phase_one() -> box_core::Result<Self> {
        let params = Params::new(
            PASSWORD_MEMORY_KIB,
            PASSWORD_ITERATIONS,
            PASSWORD_PARALLELISM,
            Some(PASSWORD_OUTPUT_BYTES),
        )
        .map_err(|error| internal(format!("invalid Argon2 parameters: {error}")))?;
        Ok(Self {
            argon2: Argon2::new(Algorithm::Argon2id, Version::V0x13, params),
        })
    }

    pub fn hash(&self, password: &str) -> box_core::Result<PasswordDigest> {
        validate_password(password)?;
        let mut salt = [0_u8; 16];
        getrandom::fill(&mut salt)
            .map_err(|error| internal(format!("operating system randomness failed: {error}")))?;
        let salt = SaltString::encode_b64(&salt)
            .map_err(|error| internal(format!("password salt encoding failed: {error}")))?;
        let digest = self
            .argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|error| internal(format!("password hashing failed: {error}")))?;
        Ok(PasswordDigest(digest.to_string()))
    }

    pub fn verify(&self, password: &str, stored_phc: &str) -> bool {
        let Ok(hash) = PasswordHash::new(stored_phc) else {
            return false;
        };
        self.argon2
            .verify_password(password.as_bytes(), &hash)
            .is_ok()
    }
}

fn validate_password(password: &str) -> box_core::Result<()> {
    if !(12..=1_024).contains(&password.len()) {
        return Err(DomainError::validation(
            "administrator password must contain 12 to 1024 bytes",
        ));
    }
    Ok(())
}

#[derive(Clone, PartialEq, Eq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct SessionBearer(String);

impl SessionBearer {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SessionBearer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionBearer([REDACTED])")
    }
}

impl fmt::Display for SessionBearer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

#[derive(Clone, PartialEq, Eq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct CsrfToken(String);

impl CsrfToken {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for CsrfToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CsrfToken([REDACTED])")
    }
}

impl fmt::Display for CsrfToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct CreatedSession {
    pub id: String,
    pub account: AccountContext,
    pub user_id: String,
    pub expires_at: i64,
    bearer: SessionBearer,
    csrf: CsrfToken,
}

impl CreatedSession {
    pub fn bearer(&self) -> &SessionBearer {
        &self.bearer
    }

    pub fn csrf(&self) -> &CsrfToken {
        &self.csrf
    }
}

impl fmt::Debug for CreatedSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CreatedSession")
            .field("id", &self.id)
            .field("account", &self.account)
            .field("user_id", &self.user_id)
            .field("expires_at", &self.expires_at)
            .field("bearer", &"[REDACTED]")
            .field("csrf", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionPrincipal {
    pub session_id: String,
    pub account: AccountContext,
    pub user_id: String,
}

#[derive(Clone)]
pub struct SessionManager {
    users: UserStore,
    sessions: AdminSessionStore,
    password: PasswordService,
    pepper: Zeroizing<Vec<u8>>,
}

impl SessionManager {
    pub fn new(db: DatabaseHandle, pepper: impl AsRef<[u8]>) -> box_core::Result<Self> {
        if pepper.as_ref().len() < 32 {
            return Err(DomainError::validation(
                "session HMAC pepper must contain at least 32 bytes",
            ));
        }
        Ok(Self {
            users: UserStore::new(db.clone()),
            sessions: AdminSessionStore::new(db),
            password: PasswordService::phase_one()?,
            pepper: Zeroizing::new(pepper.as_ref().to_vec()),
        })
    }

    pub async fn login(
        &self,
        account: AccountContext,
        username: &str,
        password: &str,
        ttl_millis: i64,
        timestamp: i64,
    ) -> box_core::Result<CreatedSession> {
        let user = self
            .users
            .find_by_username(account, username)
            .await?
            .ok_or_else(unauthorized)?;
        if user.account != account || user.role != "admin" {
            return Err(unauthorized());
        }
        if !self.password.verify(password, user.password_hash()) {
            return Err(unauthorized());
        }
        self.create_for_user(&user, ttl_millis, timestamp).await
    }

    pub async fn login_local(
        &self,
        username: &str,
        password: &str,
        ttl_millis: i64,
        timestamp: i64,
    ) -> box_core::Result<CreatedSession> {
        let user = self
            .users
            .find_unique_local_admin(username)
            .await?
            .ok_or_else(unauthorized)?;
        if !self.password.verify(password, user.password_hash()) {
            return Err(unauthorized());
        }
        self.create_for_user(&user, ttl_millis, timestamp).await
    }

    async fn create_for_user(
        &self,
        user: &UserRecord,
        ttl_millis: i64,
        timestamp: i64,
    ) -> box_core::Result<CreatedSession> {
        if !(1..=MAX_SESSION_TTL_MILLIS).contains(&ttl_millis) {
            return Err(DomainError::validation("invalid session TTL"));
        }
        let token_secret = random_hex(SESSION_TOKEN_BYTES)?;
        let csrf_secret = random_hex(SESSION_TOKEN_BYTES)?;
        let prefix_entropy = random_hex(8)?;
        let token_prefix = format!("boxd_session_{prefix_entropy}");
        let bearer = SessionBearer(format!("{token_prefix}_{token_secret}"));
        let csrf = CsrfToken(format!("boxd_csrf_{csrf_secret}"));
        let id = Uuid::now_v7().to_string();
        let expires_at = timestamp
            .checked_add(ttl_millis)
            .ok_or_else(|| DomainError::validation("session expiry overflow"))?;
        self.sessions
            .insert(&SessionInsert {
                id: id.clone(),
                account: user.account,
                user_id: user.id.clone(),
                token_prefix,
                token_hmac: self.digest("session", bearer.expose()),
                csrf_hmac: self.digest("csrf", csrf.expose()),
                expires_at,
                created_at: timestamp,
            })
            .await?;
        Ok(CreatedSession {
            id,
            account: user.account,
            user_id: user.id.clone(),
            expires_at,
            bearer,
            csrf,
        })
    }

    pub async fn authenticate(
        &self,
        bearer: &str,
        csrf: &str,
        timestamp: i64,
    ) -> box_core::Result<SessionPrincipal> {
        let prefix = session_prefix(bearer).ok_or_else(unauthorized)?;
        if !valid_csrf(csrf) {
            return Err(unauthorized());
        }
        let candidates = self.sessions.candidates(prefix).await?;
        let mut matched: Option<SessionCandidate> = None;
        for candidate in candidates {
            let token_matches = self.verify_digest("session", bearer, &candidate.token_hmac);
            let csrf_matches = self.verify_digest("csrf", csrf, &candidate.csrf_hmac);
            let active = candidate.revoked_at.is_none() && candidate.expires_at > timestamp;
            if token_matches && csrf_matches && active && matched.is_none() {
                matched = Some(candidate);
            }
        }
        let candidate = matched.ok_or_else(unauthorized)?;
        if !self.sessions.touch_if_active(&candidate, timestamp).await? {
            return Err(unauthorized());
        }
        Ok(SessionPrincipal {
            session_id: candidate.id,
            account: candidate.account,
            user_id: candidate.user_id,
        })
    }

    pub async fn revoke(
        &self,
        principal: &SessionPrincipal,
        timestamp: i64,
    ) -> box_core::Result<bool> {
        self.sessions
            .revoke(principal.account, &principal.session_id, timestamp)
            .await
    }

    fn digest(&self, domain: &str, value: &str) -> String {
        digest_with_domain(&self.pepper, domain, value)
    }

    fn verify_digest(&self, domain: &str, value: &str, expected: &str) -> bool {
        let Some(bytes) = decode_digest(expected) else {
            return false;
        };
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.pepper).expect("HMAC accepts any key");
        mac.update(domain.as_bytes());
        mac.update(&[0]);
        mac.update(value.as_bytes());
        mac.verify_slice(&bytes).is_ok()
    }
}

#[async_trait]
impl box_api::SessionAuthenticator for SessionManager {
    async fn authenticate_session(
        &self,
        session: &str,
        csrf: &str,
    ) -> box_core::Result<AccountContext> {
        self.authenticate(session, csrf, unix_millis())
            .await
            .map(|principal| principal.account)
    }
}

#[derive(Clone)]
pub struct CompatibilityApiKeyAuthenticator {
    store: ApiKeyStore,
}

impl CompatibilityApiKeyAuthenticator {
    pub fn new(store: ApiKeyStore) -> Self {
        Self { store }
    }
}

#[async_trait]
impl box_api::Authenticator for CompatibilityApiKeyAuthenticator {
    async fn authenticate(&self, api_key: &str) -> box_core::Result<AuthorizedContext> {
        let prefix = api_key_prefix(api_key).ok_or_else(unauthorized)?;
        let authorized = self
            .store
            .authenticate(prefix, api_key)
            .await?
            .ok_or_else(unauthorized)?;
        if authorized.scopes.contains(&AuthScope::Admin) {
            return Err(unauthorized());
        }
        Ok(authorized)
    }
}

#[derive(Clone, PartialEq, Eq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct OneTimeApiKey(String);

impl OneTimeApiKey {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for OneTimeApiKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OneTimeApiKey([REDACTED])")
    }
}

impl fmt::Display for OneTimeApiKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct BootstrapResult {
    pub account: AccountContext,
    pub user_id: String,
    pub username: String,
    api_key: OneTimeApiKey,
}

impl BootstrapResult {
    pub fn api_key(&self) -> &OneTimeApiKey {
        &self.api_key
    }
}

impl fmt::Debug for BootstrapResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BootstrapResult")
            .field("account", &self.account)
            .field("user_id", &self.user_id)
            .field("username", &self.username)
            .field("api_key", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone)]
pub struct BootstrapService {
    store: BootstrapStore,
    passwords: PasswordService,
    api_key_pepper: Zeroizing<Vec<u8>>,
}

impl BootstrapService {
    pub fn new(db: DatabaseHandle, api_key_pepper: impl AsRef<[u8]>) -> box_core::Result<Self> {
        if api_key_pepper.as_ref().len() < 32 {
            return Err(DomainError::validation(
                "API key HMAC pepper must contain at least 32 bytes",
            ));
        }
        Ok(Self {
            store: BootstrapStore::new(db),
            passwords: PasswordService::phase_one()?,
            api_key_pepper: Zeroizing::new(api_key_pepper.as_ref().to_vec()),
        })
    }

    pub async fn initialize(
        &self,
        account_name: &str,
        username: &str,
        password: &str,
        timestamp: i64,
    ) -> box_core::Result<BootstrapResult> {
        if account_name.trim().is_empty() || username.trim().is_empty() || username.len() > 128 {
            return Err(DomainError::validation(
                "account name and administrator username are required",
            ));
        }
        let password_hash = self.passwords.hash(password)?;
        let prefix = format!("boxd_compat_{}", random_hex(8)?);
        let api_key = OneTimeApiKey(format!("{prefix}_{}", random_hex(SESSION_TOKEN_BYTES)?));
        let account = AccountContext {
            account_id: box_core::AccountId::new(),
            tenant_id: box_core::TenantId::new(),
        };
        let user_id = Uuid::now_v7().to_string();
        self.store
            .initialize(&BootstrapSeed {
                account,
                account_name: account_name.to_owned(),
                user_id: user_id.clone(),
                username: username.to_owned(),
                password_hash: password_hash.as_phc().to_owned(),
                role: "admin".to_owned(),
                api_key_id: Uuid::now_v7().to_string(),
                api_key_prefix: prefix,
                api_key_hmac: api_key_digest(&self.api_key_pepper, api_key.expose()),
                api_key_scopes: BTreeSet::from([
                    AuthScope::BoxesRead,
                    AuthScope::BoxesWrite,
                    AuthScope::RunsWrite,
                    AuthScope::SecretsRead,
                ]),
                created_at: timestamp,
            })
            .await?;
        Ok(BootstrapResult {
            account,
            user_id,
            username: username.to_owned(),
            api_key,
        })
    }
}

fn random_hex(bytes: usize) -> box_core::Result<String> {
    let mut value = Zeroizing::new(vec![0_u8; bytes]);
    getrandom::fill(&mut value)
        .map_err(|error| internal(format!("operating system randomness failed: {error}")))?;
    Ok(hex::encode(&*value))
}

fn api_key_digest(pepper: &[u8], value: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(pepper).expect("HMAC accepts any key");
    mac.update(value.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn digest_with_domain(pepper: &[u8], domain: &str, value: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(pepper).expect("HMAC accepts any key");
    mac.update(domain.as_bytes());
    mac.update(&[0]);
    mac.update(value.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn decode_digest(value: &str) -> Option<Vec<u8>> {
    if value.len() != 64 {
        return None;
    }
    hex::decode(value).ok()
}

fn api_key_prefix(value: &str) -> Option<&str> {
    let (prefix, secret) = value.rsplit_once('_')?;
    if !prefix.starts_with("boxd_compat_") || prefix.len() > 64 || secret.len() != 64 {
        return None;
    }
    Some(prefix)
}

fn session_prefix(value: &str) -> Option<&str> {
    let (prefix, secret) = value.rsplit_once('_')?;
    if !prefix.starts_with("boxd_session_") || prefix.len() > 64 || secret.len() != 64 {
        return None;
    }
    Some(prefix)
}

fn valid_csrf(value: &str) -> bool {
    value.strip_prefix("boxd_csrf_").is_some_and(|secret| {
        secret.len() == 64 && secret.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

fn unix_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use box_api::{Authenticator, SessionAuthenticator};
    use box_db::{connect, migrate};
    use sea_orm::{ConnectionTrait, DatabaseBackend, Statement, TryGetable};

    const PASSWORD: &str = "correct horse battery staple";
    const PEPPER: [u8; 32] = [37; 32];

    async fn setup() -> (DatabaseHandle, BootstrapResult) {
        let db = connect("sqlite::memory:", 1).await.unwrap();
        migrate(&db).await.unwrap();
        let result = BootstrapService::new(db.clone(), PEPPER)
            .unwrap()
            .initialize("local", "admin", PASSWORD, 10_000)
            .await
            .unwrap();
        (db, result)
    }

    async fn column_values(db: &DatabaseHandle, query: &str) -> Vec<String> {
        db.query_all_raw(Statement::from_string(DatabaseBackend::Sqlite, query))
            .await
            .unwrap()
            .into_iter()
            .map(|row| String::try_get_by_index(&row, 0).unwrap())
            .collect()
    }

    #[test]
    fn argon2id_parameters_and_redaction_are_explicit() {
        let service = PasswordService::phase_one().unwrap();
        let digest = service.hash(PASSWORD).unwrap();
        assert!(
            digest
                .as_phc()
                .starts_with("$argon2id$v=19$m=65536,t=3,p=1$")
        );
        assert!(service.verify(PASSWORD, digest.as_phc()));
        assert!(!service.verify("wrong password value", digest.as_phc()));
        assert_eq!(format!("{digest:?}"), "PasswordDigest([REDACTED])");
        assert!(!format!("{digest:?}").contains(digest.as_phc()));
    }

    #[tokio::test]
    async fn bootstrap_returns_secret_once_and_compat_adapter_authenticates_it() {
        let (db, result) = setup().await;
        let raw = result.api_key().expose().to_owned();
        assert!(!format!("{result:?}").contains(&raw));
        let auth =
            CompatibilityApiKeyAuthenticator::new(ApiKeyStore::new(db.clone(), PEPPER).unwrap());
        let authorized = auth.authenticate(&raw).await.unwrap();
        assert_eq!(authorized.account, result.account);
        assert!(authorized.scopes.contains(&AuthScope::BoxesWrite));
        let stored_passwords = column_values(&db, "SELECT password_hash FROM users").await;
        let stored_api_keys = column_values(&db, "SELECT key_hmac FROM api_keys").await;
        assert!(
            stored_passwords
                .iter()
                .all(|value| !value.contains(PASSWORD))
        );
        assert!(stored_api_keys.iter().all(|value| !value.contains(&raw)));
        assert_eq!(
            BootstrapService::new(db, PEPPER)
                .unwrap()
                .initialize("other", "admin", PASSWORD, 20_000)
                .await
                .unwrap_err()
                .code,
            "state_conflict"
        );
    }

    #[tokio::test]
    async fn admin_scoped_key_is_rejected_by_compatibility_chain() {
        let (db, result) = setup().await;
        let raw =
            "boxd_compat_deadbeef_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        ApiKeyStore::new(db.clone(), PEPPER)
            .unwrap()
            .store(
                result.account,
                "boxd_compat_deadbeef",
                raw,
                BTreeSet::from([AuthScope::Admin]),
                None,
            )
            .await
            .unwrap();
        let auth = CompatibilityApiKeyAuthenticator::new(ApiKeyStore::new(db, PEPPER).unwrap());
        assert_eq!(
            auth.authenticate(raw).await.unwrap_err().code,
            "unauthorized"
        );
    }

    #[tokio::test]
    async fn sessions_enforce_csrf_expiry_revocation_and_tenant_scope() {
        let (db, bootstrap) = setup().await;
        let manager = SessionManager::new(db.clone(), PEPPER).unwrap();
        assert_eq!(
            manager
                .login(
                    bootstrap.account,
                    "admin",
                    "wrong password value",
                    5_000,
                    20_000
                )
                .await
                .unwrap_err()
                .code,
            "unauthorized"
        );
        let session = manager
            .login(bootstrap.account, "admin", PASSWORD, 5_000, 20_000)
            .await
            .unwrap();
        assert!(!format!("{session:?}").contains(session.bearer().expose()));
        let stored_bearers = column_values(&db, "SELECT token_hmac FROM admin_sessions").await;
        let stored_csrf = column_values(&db, "SELECT csrf_hmac FROM admin_sessions").await;
        assert!(
            stored_bearers
                .iter()
                .all(|value| !value.contains(session.bearer().expose()))
        );
        assert!(
            stored_csrf
                .iter()
                .all(|value| !value.contains(session.csrf().expose()))
        );
        assert!(
            manager
                .authenticate(session.bearer().expose(), session.csrf().expose(), 24_999)
                .await
                .is_ok()
        );
        assert_eq!(
            manager
                .authenticate(
                    session.bearer().expose(),
                    "boxd_csrf_ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                    24_999
                )
                .await
                .unwrap_err()
                .code,
            "unauthorized"
        );
        assert_eq!(
            manager
                .authenticate(session.bearer().expose(), session.csrf().expose(), 25_000)
                .await
                .unwrap_err()
                .code,
            "unauthorized"
        );

        let active = manager
            .login(bootstrap.account, "admin", PASSWORD, 5_000, 30_000)
            .await
            .unwrap();
        let principal = manager
            .authenticate(active.bearer().expose(), active.csrf().expose(), 30_001)
            .await
            .unwrap();
        let other_tenant = AccountContext {
            account_id: principal.account.account_id,
            tenant_id: box_core::TenantId::new(),
        };
        assert!(
            !manager
                .sessions
                .revoke(other_tenant, &principal.session_id, 30_002)
                .await
                .unwrap()
        );
        assert!(manager.revoke(&principal, 30_003).await.unwrap());
        assert_eq!(
            manager
                .authenticate(active.bearer().expose(), active.csrf().expose(), 30_004)
                .await
                .unwrap_err()
                .code,
            "unauthorized"
        );
    }

    #[tokio::test]
    async fn prefix_collision_checks_all_candidates_and_session_trait_is_wired() {
        let (db, bootstrap) = setup().await;
        let manager = SessionManager::new(db.clone(), PEPPER).unwrap();
        let timestamp = unix_millis();
        let session = manager
            .login(bootstrap.account, "admin", PASSWORD, 60_000, timestamp)
            .await
            .unwrap();
        let prefix = session_prefix(session.bearer().expose())
            .unwrap()
            .to_owned();
        AdminSessionStore::new(db)
            .insert(&SessionInsert {
                id: Uuid::now_v7().to_string(),
                account: bootstrap.account,
                user_id: bootstrap.user_id,
                token_prefix: prefix,
                token_hmac: "00".repeat(32),
                csrf_hmac: "11".repeat(32),
                expires_at: timestamp + 60_000,
                created_at: timestamp,
            })
            .await
            .unwrap();
        manager
            .authenticate_session(session.bearer().expose(), session.csrf().expose())
            .await
            .unwrap();
        assert!(
            manager
                .authenticate(
                    session.bearer().expose(),
                    session.csrf().expose(),
                    timestamp + 1,
                )
                .await
                .is_ok()
        );
    }
}
