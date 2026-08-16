use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use box_api::{ApiKeyFingerprint, RequestQuota, RequestQuotaDecision};
use box_core::{AccountId, AuthorizedContext, DomainError, TenantId};

use crate::config::QuotasConfig;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct QuotaKey {
    account_id: AccountId,
    tenant_id: TenantId,
    credential: [u8; 32],
}

#[derive(Clone, Copy, Debug)]
struct Bucket {
    request_tokens: f64,
    traffic_tokens: f64,
    updated_at: Instant,
}

#[derive(Debug)]
struct QuotaState {
    buckets: HashMap<QuotaKey, Bucket>,
    last_sweep: Instant,
}

pub struct ApiKeyRequestQuota {
    requests_per_minute: u32,
    burst: u32,
    traffic_bytes_per_minute: u64,
    traffic_burst_bytes: u64,
    max_tracked_api_keys: usize,
    idle_ttl: Duration,
    state: Mutex<QuotaState>,
}

impl ApiKeyRequestQuota {
    pub fn new(config: &QuotasConfig) -> Self {
        let now = Instant::now();
        Self {
            requests_per_minute: config.api_key_requests_per_minute,
            burst: config.api_key_request_burst,
            traffic_bytes_per_minute: config
                .api_key_traffic_mib_per_minute
                .saturating_mul(1024 * 1024),
            traffic_burst_bytes: config.api_key_traffic_burst_mib.saturating_mul(1024 * 1024),
            max_tracked_api_keys: config.max_tracked_api_keys,
            idle_ttl: Duration::from_secs(config.idle_entry_ttl_seconds),
            state: Mutex::new(QuotaState {
                buckets: HashMap::new(),
                last_sweep: now,
            }),
        }
    }

    fn check_at(
        &self,
        context: &AuthorizedContext,
        credential: ApiKeyFingerprint,
        now: Instant,
    ) -> RequestQuotaDecision {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if now.saturating_duration_since(state.last_sweep) >= self.idle_ttl {
            let idle_ttl = self.idle_ttl;
            state
                .buckets
                .retain(|_, bucket| now.saturating_duration_since(bucket.updated_at) < idle_ttl);
            state.last_sweep = now;
        }
        let key = QuotaKey {
            account_id: context.account.account_id,
            tenant_id: context.account.tenant_id,
            credential: credential.bytes(),
        };
        if !state.buckets.contains_key(&key) && state.buckets.len() >= self.max_tracked_api_keys {
            return RequestQuotaDecision::Rejected {
                retry_after_seconds: self.idle_ttl.as_secs().max(1),
            };
        }
        let rate_per_second = f64::from(self.requests_per_minute) / 60.0;
        let burst = f64::from(self.burst);
        let traffic_burst = self.traffic_burst_bytes as f64;
        let bucket = state.buckets.entry(key).or_insert(Bucket {
            request_tokens: burst,
            traffic_tokens: traffic_burst,
            updated_at: now,
        });
        let elapsed = now
            .saturating_duration_since(bucket.updated_at)
            .as_secs_f64();
        bucket.request_tokens = (bucket.request_tokens + elapsed * rate_per_second).min(burst);
        bucket.traffic_tokens = (bucket.traffic_tokens
            + elapsed * (self.traffic_bytes_per_minute as f64 / 60.0))
            .min(traffic_burst);
        bucket.updated_at = now;
        if bucket.traffic_tokens < 1.0 {
            return RequestQuotaDecision::Rejected {
                retry_after_seconds: (1.0 / (self.traffic_bytes_per_minute as f64 / 60.0))
                    .ceil()
                    .max(1.0) as u64,
            };
        }
        if bucket.request_tokens >= 1.0 {
            bucket.request_tokens -= 1.0;
            RequestQuotaDecision::Allowed
        } else {
            RequestQuotaDecision::Rejected {
                retry_after_seconds: ((1.0 - bucket.request_tokens) / rate_per_second)
                    .ceil()
                    .max(1.0) as u64,
            }
        }
    }

    fn charge_traffic_at(
        &self,
        context: &AuthorizedContext,
        credential: ApiKeyFingerprint,
        bytes: u64,
        now: Instant,
    ) -> RequestQuotaDecision {
        if bytes == 0 {
            return RequestQuotaDecision::Allowed;
        }
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let key = QuotaKey {
            account_id: context.account.account_id,
            tenant_id: context.account.tenant_id,
            credential: credential.bytes(),
        };
        if !state.buckets.contains_key(&key) && state.buckets.len() >= self.max_tracked_api_keys {
            return RequestQuotaDecision::Rejected {
                retry_after_seconds: self.idle_ttl.as_secs().max(1),
            };
        }
        let traffic_rate_per_second = self.traffic_bytes_per_minute as f64 / 60.0;
        let traffic_burst = self.traffic_burst_bytes as f64;
        let request_burst = f64::from(self.burst);
        let bucket = state.buckets.entry(key).or_insert(Bucket {
            request_tokens: request_burst,
            traffic_tokens: traffic_burst,
            updated_at: now,
        });
        let elapsed = now
            .saturating_duration_since(bucket.updated_at)
            .as_secs_f64();
        bucket.request_tokens = (bucket.request_tokens
            + elapsed * (f64::from(self.requests_per_minute) / 60.0))
            .min(request_burst);
        bucket.traffic_tokens =
            (bucket.traffic_tokens + elapsed * traffic_rate_per_second).min(traffic_burst);
        bucket.updated_at = now;
        let bytes = bytes as f64;
        if bucket.traffic_tokens >= bytes {
            bucket.traffic_tokens -= bytes;
            RequestQuotaDecision::Allowed
        } else {
            bucket.traffic_tokens = 0.0;
            RequestQuotaDecision::Rejected {
                retry_after_seconds: ((bytes - bucket.traffic_tokens) / traffic_rate_per_second)
                    .ceil()
                    .max(1.0) as u64,
            }
        }
    }
}

#[async_trait]
impl RequestQuota for ApiKeyRequestQuota {
    async fn check(
        &self,
        context: &AuthorizedContext,
        credential: ApiKeyFingerprint,
    ) -> Result<RequestQuotaDecision, DomainError> {
        Ok(self.check_at(context, credential, Instant::now()))
    }

    async fn charge_traffic(
        &self,
        context: &AuthorizedContext,
        credential: ApiKeyFingerprint,
        bytes: u64,
    ) -> Result<RequestQuotaDecision, DomainError> {
        Ok(self.charge_traffic_at(context, credential, bytes, Instant::now()))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use box_core::{AccountContext, AuthScope};

    use super::*;

    fn context() -> AuthorizedContext {
        AuthorizedContext {
            account: AccountContext {
                account_id: AccountId::new(),
                tenant_id: TenantId::new(),
            },
            scopes: BTreeSet::from([AuthScope::BoxesRead]),
        }
    }

    fn fingerprint(byte: u8) -> ApiKeyFingerprint {
        ApiKeyFingerprint::from_api_key(&format!("test-api-key-{byte}"))
    }

    #[test]
    fn token_bucket_isolated_by_key_refills_and_bounds_cardinality() {
        let quota = ApiKeyRequestQuota::new(&QuotasConfig {
            api_key_requests_per_minute: 60,
            api_key_request_burst: 2,
            api_key_traffic_mib_per_minute: 1,
            api_key_traffic_burst_mib: 1,
            max_tracked_api_keys: 2,
            idle_entry_ttl_seconds: 10,
            tenant_max_boxes: 4,
            tenant_max_disk_gib: 80,
            tenant_max_concurrent_runs: 4,
        });
        let account = context();
        let start = Instant::now();
        assert_eq!(
            quota.check_at(&account, fingerprint(1), start),
            RequestQuotaDecision::Allowed
        );
        assert_eq!(
            quota.check_at(&account, fingerprint(1), start),
            RequestQuotaDecision::Allowed
        );
        assert_eq!(
            quota.check_at(&account, fingerprint(1), start),
            RequestQuotaDecision::Rejected {
                retry_after_seconds: 1
            }
        );
        assert_eq!(
            quota.check_at(&account, fingerprint(2), start),
            RequestQuotaDecision::Allowed
        );
        assert!(matches!(
            quota.check_at(&account, fingerprint(3), start),
            RequestQuotaDecision::Rejected { .. }
        ));
        assert_eq!(
            quota.check_at(&account, fingerprint(1), start + Duration::from_secs(1)),
            RequestQuotaDecision::Allowed
        );
        assert_eq!(
            quota.check_at(&account, fingerprint(3), start + Duration::from_secs(11)),
            RequestQuotaDecision::Allowed
        );
        assert_eq!(
            quota.charge_traffic_at(&account, fingerprint(3), 1024 * 1024, start),
            RequestQuotaDecision::Allowed
        );
        assert!(matches!(
            quota.charge_traffic_at(&account, fingerprint(3), 1, start),
            RequestQuotaDecision::Rejected { .. }
        ));
    }
}
