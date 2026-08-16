use std::sync::Arc;

use async_trait::async_trait;
use box_api::{AdminLoginResult, AdminLoginService};
use box_auth::SessionManager;
use box_core::DomainError;

pub struct LocalAdminLogin {
    sessions: Arc<SessionManager>,
    ttl_millis: i64,
}

impl LocalAdminLogin {
    pub fn new(sessions: Arc<SessionManager>, ttl_seconds: u64) -> Result<Self, String> {
        let ttl_millis = i64::try_from(ttl_seconds)
            .ok()
            .and_then(|value| value.checked_mul(1_000))
            .ok_or_else(|| "administrator session TTL is too large".to_string())?;
        Ok(Self {
            sessions,
            ttl_millis,
        })
    }
}

#[async_trait]
impl AdminLoginService for LocalAdminLogin {
    async fn login(&self, username: &str, password: &str) -> Result<AdminLoginResult, DomainError> {
        let created = self
            .sessions
            .login_local(username, password, self.ttl_millis, unix_millis())
            .await?;
        Ok(AdminLoginResult {
            session: created.bearer().expose().to_owned(),
            csrf: created.csrf().expose().to_owned(),
            expires_at_millis: created.expires_at,
        })
    }

    async fn logout(&self, session: &str, csrf: &str) -> Result<(), DomainError> {
        let timestamp = unix_millis();
        let principal = self.sessions.authenticate(session, csrf, timestamp).await?;
        if !self.sessions.revoke(&principal, timestamp).await? {
            return Err(DomainError::state_conflict(
                "administrator session was already revoked",
            ));
        }
        Ok(())
    }
}

fn unix_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
