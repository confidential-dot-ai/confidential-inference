//! Per-key request rate limits and token budgets.
//!
//! The admin sets both limits on one key row of the key snapshot
//! (`crate::key_registry`). An absent or `null` limit means "no limit", so a
//! snapshot from an older admin keeps every key unlimited.
//!
//! ## Request rate limit (`rateLimit`)
//!
//! A token bucket per key: it holds at most `burst` requests (default:
//! `requestsPerMinute`) and refills at `requestsPerMinute / 60` requests per
//! second. Each gateway replica holds its own buckets in memory. The gateway
//! has no shared state, so `N` replicas admit up to `N` times the limit. A
//! restart refills the bucket.
//!
//! ## Token budget (`tokenBudget`)
//!
//! The largest number of tokens (input plus output, as the usage events
//! report them) one key may use in one UTC calendar window (`day` or
//! `month`). The gateway refuses a new request when the key has used the
//! whole budget. It does not stop a request in flight, so the last requests
//! of a window can go over the budget.
//!
//! The gateway learns the spend from two sources:
//!
//! - The admin: the `tokenUsage` part of each snapshot holds, per key, the
//!   tokens of all usage events the admin stored for the current window at
//!   time `asOf`. This includes the events of all replicas and of earlier
//!   gateway processes, so the count survives restarts and is the same on
//!   every replica.
//! - This replica: the tokens of each request it finished, so the count
//!   moves between two pulls (30 s). After the gateway applies a newer
//!   `asOf`, it forgets its own tokens from before `asOf` minus
//!   [`USAGE_GRACE_SECONDS`]: the admin counts them now. The grace keeps
//!   events that were still in the usage queue at `asOf`. An event in both
//!   counts makes the spend too high for a short time, never too low.
//!
//! The spend of other replicas since the last pull is not visible. The
//! overshoot is at most the tokens all replicas use in one pull interval
//! plus one usage delivery interval, plus the requests in flight.
//! Without usage events (`GATEWAY_USAGE_ENABLED=false`) the admin has no
//! data and this replica counts nothing, so the budget is not enforced.

use std::{
    collections::{HashMap, VecDeque},
    sync::Mutex,
};

use serde::{Deserialize, Serialize};

/// The largest `requestsPerMinute` and `burst` the gateway accepts.
pub const MAX_REQUESTS_PER_MINUTE: u32 = 1_000_000;
/// The largest token budget: it stays a safe integer in JavaScript.
pub const MAX_BUDGET_TOKENS: u64 = 1_000_000_000_000_000;
/// Local tokens recorded up to this many seconds before the admin's `asOf`
/// stay in the local count. The gateway sends usage every 5 s.
pub const USAGE_GRACE_SECONDS: i64 = 30;
/// Local tokens older than this merge into one total per key.
const RECENT_SECONDS: i64 = 600;
const DAY_SECONDS: i64 = 86_400;

/// The request rate limit of one key.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RateLimit {
    pub requests_per_minute: u32,
    /// The largest number of requests the key can send at once after an
    /// idle period. Absent: `requests_per_minute`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub burst: Option<u32>,
}

/// The calendar window of a token budget, in UTC.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum BudgetWindow {
    Day,
    Month,
}

/// The token budget of one key.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TokenBudget {
    pub tokens: u64,
    pub window: BudgetWindow,
}

/// The spend the admin measured, in the snapshot envelope.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TokenUsage {
    /// The admin's time of the count (RFC 3339).
    pub as_of: String,
    pub keys: Vec<KeyTokenUsage>,
}

/// The tokens one key used in its current budget window.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct KeyTokenUsage {
    pub id: String,
    /// The start of the window the count is for (RFC 3339).
    pub window_start: String,
    pub tokens: u64,
}

/// The limits of one key.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KeyPolicy {
    pub rate_limit: Option<RateLimit>,
    pub token_budget: Option<TokenBudget>,
}

impl KeyPolicy {
    /// Check the value ranges.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        let rate = self.rate_limit.is_none_or(|rate| {
            (1..=MAX_REQUESTS_PER_MINUTE).contains(&rate.requests_per_minute)
                && rate
                    .burst
                    .is_none_or(|burst| (1..=MAX_REQUESTS_PER_MINUTE).contains(&burst))
        });
        let budget = self
            .token_budget
            .is_none_or(|budget| (1..=MAX_BUDGET_TOKENS).contains(&budget.tokens));
        rate && budget
    }

    fn is_unlimited(&self) -> bool {
        self.rate_limit.is_none() && self.token_budget.is_none()
    }
}

/// The admin spend in a form the gateway can use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedTokenUsage {
    pub as_of_unix: i64,
    pub keys: Vec<(String, i64, u64)>,
}

/// Why the gateway refused a request before it went upstream. Each answer
/// is `429` with `Retry-After`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LimitRejection {
    /// The request rate limit refused the request.
    RateLimited { retry_after_seconds: u64 },
    /// The key used its whole token budget for this window.
    TokenBudgetExhausted { retry_after_seconds: u64 },
}

struct Bucket {
    level: f64,
    updated_ms: u64,
}

#[derive(Default)]
struct LocalSpend {
    window_start: i64,
    /// Tokens per second, newest at the back.
    recent: VecDeque<(i64, u64)>,
    older: u64,
    older_until: i64,
}

impl LocalSpend {
    fn total(&self) -> u64 {
        self.recent
            .iter()
            .fold(self.older, |sum, (_, tokens)| sum.saturating_add(*tokens))
    }
}

#[derive(Default)]
struct Inner {
    policies: HashMap<String, KeyPolicy>,
    buckets: HashMap<String, Bucket>,
    local: HashMap<String, LocalSpend>,
    admin: HashMap<String, (i64, u64)>,
    usage_as_of: Option<i64>,
}

/// The limit state of one gateway replica.
#[derive(Default)]
pub struct KeyLimits {
    inner: Mutex<Inner>,
}

impl KeyLimits {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the limits of every key. Keys without limits are not kept.
    /// A key whose rate limit stays keeps its bucket level, capped at the
    /// new burst, so a new snapshot does not refill a bucket.
    pub fn replace_policies(&self, policies: HashMap<String, KeyPolicy>) {
        let mut inner = self.lock();
        let policies: HashMap<_, _> = policies
            .into_iter()
            .filter(|(_, policy)| !policy.is_unlimited())
            .collect();
        inner.buckets.retain(|id, bucket| {
            let Some(rate) = policies.get(id).and_then(|policy| policy.rate_limit) else {
                return false;
            };
            bucket.level = bucket.level.min(capacity(rate));
            true
        });
        inner
            .local
            .retain(|id, _| policies.get(id).is_some_and(|p| p.token_budget.is_some()));
        inner.policies = policies;
    }

    /// Apply the admin spend when it is newer than the spend held.
    /// Returns `false` for an older or equal `asOf`.
    pub fn apply_usage(&self, usage: &ParsedTokenUsage) -> bool {
        let mut inner = self.lock();
        if inner
            .usage_as_of
            .is_some_and(|held| held >= usage.as_of_unix)
        {
            return false;
        }
        inner.usage_as_of = Some(usage.as_of_unix);
        inner.admin = usage
            .keys
            .iter()
            .map(|(id, window_start, tokens)| (id.clone(), (*window_start, *tokens)))
            .collect();
        let cutoff = usage.as_of_unix - USAGE_GRACE_SECONDS;
        for spend in inner.local.values_mut() {
            spend.recent.retain(|(second, _)| *second >= cutoff);
            if spend.older_until < cutoff {
                spend.older = 0;
            }
        }
        true
    }

    /// Admit or refuse one request of `key_id` at `now_ms` (Unix ms).
    /// The budget is checked first, so a refused request takes no rate
    /// token.
    ///
    /// # Errors
    ///
    /// Returns the limit that refused the request.
    pub fn admit(&self, key_id: &str, now_ms: u64) -> Result<(), LimitRejection> {
        let mut inner = self.lock();
        let Some(policy) = inner.policies.get(key_id).copied() else {
            return Ok(());
        };
        let now = i64::try_from(now_ms / 1_000).unwrap_or(i64::MAX);
        if let Some(budget) = policy.token_budget {
            let window_start = window_start(budget.window, now);
            if inner.spent(key_id, window_start) >= budget.tokens {
                let end = window_end(budget.window, now);
                return Err(LimitRejection::TokenBudgetExhausted {
                    retry_after_seconds: u64::try_from(end - now).unwrap_or(1).max(1),
                });
            }
        }
        if let Some(rate) = policy.rate_limit {
            let capacity = capacity(rate);
            let per_ms = f64::from(rate.requests_per_minute) / 60_000.0;
            let bucket = inner.buckets.entry(key_id.to_owned()).or_insert(Bucket {
                level: capacity,
                updated_ms: now_ms,
            });
            #[allow(clippy::cast_precision_loss)]
            let elapsed = now_ms.saturating_sub(bucket.updated_ms) as f64;
            bucket.level = elapsed.mul_add(per_ms, bucket.level).min(capacity);
            bucket.updated_ms = bucket.updated_ms.max(now_ms);
            if bucket.level >= 1.0 {
                bucket.level -= 1.0;
            } else {
                let wait_ms = (1.0 - bucket.level) / per_ms;
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                let seconds = (wait_ms / 1_000.0).ceil().max(1.0) as u64;
                return Err(LimitRejection::RateLimited {
                    retry_after_seconds: seconds,
                });
            }
        }
        Ok(())
    }

    /// Count the tokens of one finished request of `key_id`.
    pub fn record_tokens(&self, key_id: &str, tokens: u64, now_ms: u64) {
        if tokens == 0 {
            return;
        }
        let mut inner = self.lock();
        let Some(budget) = inner
            .policies
            .get(key_id)
            .and_then(|policy| policy.token_budget)
        else {
            return;
        };
        let now = i64::try_from(now_ms / 1_000).unwrap_or(i64::MAX);
        let window_start = window_start(budget.window, now);
        let spend = inner.local.entry(key_id.to_owned()).or_default();
        if spend.window_start != window_start {
            *spend = LocalSpend {
                window_start,
                ..LocalSpend::default()
            };
        }
        match spend.recent.back_mut() {
            Some((second, value)) if *second == now => *value = value.saturating_add(tokens),
            _ => spend.recent.push_back((now, tokens)),
        }
        while let Some(&(second, value)) = spend.recent.front() {
            if second >= now - RECENT_SECONDS {
                break;
            }
            spend.recent.pop_front();
            spend.older = spend.older.saturating_add(value);
            spend.older_until = spend.older_until.max(second);
        }
    }

    /// The tokens `key_id` used in its current window, as this replica
    /// sees them.
    #[must_use]
    pub fn spent_tokens(&self, key_id: &str, now_ms: u64) -> Option<u64> {
        let inner = self.lock();
        let budget = inner.policies.get(key_id)?.token_budget?;
        let now = i64::try_from(now_ms / 1_000).unwrap_or(i64::MAX);
        Some(inner.spent(key_id, window_start(budget.window, now)))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Inner {
    fn spent(&self, key_id: &str, window_start: i64) -> u64 {
        let admin = self
            .admin
            .get(key_id)
            .filter(|(start, _)| *start == window_start)
            .map_or(0, |(_, tokens)| *tokens);
        let local = self
            .local
            .get(key_id)
            .filter(|spend| spend.window_start == window_start)
            .map_or(0, LocalSpend::total);
        admin.saturating_add(local)
    }
}

fn capacity(rate: RateLimit) -> f64 {
    f64::from(rate.burst.unwrap_or(rate.requests_per_minute))
}

/// The start of the UTC window that holds `unix` (seconds).
#[must_use]
pub fn window_start(window: BudgetWindow, unix: i64) -> i64 {
    match window {
        BudgetWindow::Day => unix.div_euclid(DAY_SECONDS) * DAY_SECONDS,
        BudgetWindow::Month => {
            let Ok(moment) = time::OffsetDateTime::from_unix_timestamp(unix) else {
                return unix;
            };
            time::Date::from_calendar_date(moment.year(), moment.month(), 1)
                .map_or(unix, |date| date.midnight().assume_utc().unix_timestamp())
        }
    }
}

/// The end of the UTC window that holds `unix` (seconds).
#[must_use]
pub fn window_end(window: BudgetWindow, unix: i64) -> i64 {
    match window {
        BudgetWindow::Day => window_start(window, unix) + DAY_SECONDS,
        BudgetWindow::Month => {
            let Ok(moment) = time::OffsetDateTime::from_unix_timestamp(unix) else {
                return unix + DAY_SECONDS;
            };
            let (year, month) = if moment.month() == time::Month::December {
                (moment.year() + 1, time::Month::January)
            } else {
                (moment.year(), moment.month().next())
            };
            time::Date::from_calendar_date(year, month, 1).map_or(unix + DAY_SECONDS, |date| {
                date.midnight().assume_utc().unix_timestamp()
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "key_limited";
    /// 2026-11-13T12:00:00Z.
    const NOON: u64 = 1_794_571_200_000;

    fn limits(policy: KeyPolicy) -> KeyLimits {
        let limits = KeyLimits::new();
        limits.replace_policies(HashMap::from([(KEY.to_owned(), policy)]));
        limits
    }

    fn rate(requests_per_minute: u32, burst: Option<u32>) -> KeyPolicy {
        KeyPolicy {
            rate_limit: Some(RateLimit {
                requests_per_minute,
                burst,
            }),
            token_budget: None,
        }
    }

    fn budget(tokens: u64, window: BudgetWindow) -> KeyPolicy {
        KeyPolicy {
            rate_limit: None,
            token_budget: Some(TokenBudget { tokens, window }),
        }
    }

    #[test]
    fn a_key_without_limits_is_always_admitted() {
        let limits = limits(KeyPolicy::default());
        for _ in 0..1_000 {
            assert_eq!(limits.admit(KEY, NOON), Ok(()));
        }
        assert_eq!(limits.admit("key_other", NOON), Ok(()));
    }

    #[test]
    fn the_bucket_admits_the_burst_then_refills_at_the_rate() {
        let limits = limits(rate(60, Some(3)));
        for _ in 0..3 {
            assert_eq!(limits.admit(KEY, NOON), Ok(()));
        }
        assert_eq!(
            limits.admit(KEY, NOON),
            Err(LimitRejection::RateLimited {
                retry_after_seconds: 1
            })
        );
        // 60 per minute is one per second.
        assert_eq!(limits.admit(KEY, NOON + 1_000), Ok(()));
        assert!(limits.admit(KEY, NOON + 1_000).is_err());
    }

    #[test]
    fn retry_after_is_the_time_to_the_next_token() {
        let limits = limits(rate(2, Some(1)));
        assert_eq!(limits.admit(KEY, NOON), Ok(()));
        assert_eq!(
            limits.admit(KEY, NOON),
            Err(LimitRejection::RateLimited {
                retry_after_seconds: 30
            })
        );
    }

    #[test]
    fn a_new_snapshot_does_not_refill_the_bucket() {
        let limits = limits(rate(1, None));
        assert_eq!(limits.admit(KEY, NOON), Ok(()));
        limits.replace_policies(HashMap::from([(KEY.to_owned(), rate(1, None))]));
        assert!(limits.admit(KEY, NOON).is_err());
        // A removed limit removes the bucket.
        limits.replace_policies(HashMap::new());
        assert_eq!(limits.admit(KEY, NOON), Ok(()));
    }

    #[test]
    fn the_budget_adds_admin_and_local_spend() {
        let limits = limits(budget(100, BudgetWindow::Day));
        let day = window_start(BudgetWindow::Day, 1_794_571_200);
        assert!(limits.apply_usage(&ParsedTokenUsage {
            as_of_unix: 1_794_571_200,
            keys: vec![(KEY.to_owned(), day, 90)],
        }));
        assert_eq!(limits.admit(KEY, NOON), Ok(()));
        limits.record_tokens(KEY, 9, NOON + 1_000);
        assert_eq!(limits.admit(KEY, NOON + 2_000), Ok(()));
        limits.record_tokens(KEY, 1, NOON + 2_000);
        assert_eq!(
            limits.admit(KEY, NOON + 2_000),
            Err(LimitRejection::TokenBudgetExhausted {
                retry_after_seconds: 12 * 3_600 - 2
            })
        );
        // The next UTC day starts with an empty budget.
        assert_eq!(limits.admit(KEY, NOON + 12 * 3_600_000), Ok(()));
    }

    #[test]
    fn newer_admin_spend_replaces_old_local_tokens_but_keeps_the_grace() {
        let limits = limits(budget(1_000, BudgetWindow::Month));
        let month = window_start(BudgetWindow::Month, 1_794_571_200);
        limits.record_tokens(KEY, 100, NOON);
        limits.record_tokens(KEY, 7, NOON + 100_000);
        assert_eq!(limits.spent_tokens(KEY, NOON + 100_000), Some(107));
        // The admin counted both requests at noon + 110 s. The newer one is
        // inside the grace and stays counted locally.
        assert!(limits.apply_usage(&ParsedTokenUsage {
            as_of_unix: 1_794_571_310,
            keys: vec![(KEY.to_owned(), month, 107)],
        }));
        assert_eq!(limits.spent_tokens(KEY, NOON + 110_000), Some(114));
        // An older or equal count changes nothing.
        assert!(!limits.apply_usage(&ParsedTokenUsage {
            as_of_unix: 1_794_571_310,
            keys: vec![],
        }));
        assert_eq!(limits.spent_tokens(KEY, NOON + 110_000), Some(114));
    }

    #[test]
    fn admin_spend_of_another_window_counts_nothing() {
        let limits = limits(budget(10, BudgetWindow::Day));
        let yesterday = window_start(BudgetWindow::Day, 1_794_571_200) - DAY_SECONDS;
        limits.apply_usage(&ParsedTokenUsage {
            as_of_unix: 1_794_571_200,
            keys: vec![(KEY.to_owned(), yesterday, 1_000)],
        });
        assert_eq!(limits.admit(KEY, NOON), Ok(()));
    }

    #[test]
    fn a_refused_budget_takes_no_rate_token() {
        let limits = limits(KeyPolicy {
            rate_limit: Some(RateLimit {
                requests_per_minute: 1,
                burst: None,
            }),
            token_budget: Some(TokenBudget {
                tokens: 1,
                window: BudgetWindow::Day,
            }),
        });
        limits.record_tokens(KEY, 5, NOON);
        assert!(matches!(
            limits.admit(KEY, NOON),
            Err(LimitRejection::TokenBudgetExhausted { .. })
        ));
        limits.replace_policies(HashMap::from([(KEY.to_owned(), rate(1, None))]));
        assert_eq!(limits.admit(KEY, NOON), Ok(()));
    }

    #[test]
    fn old_local_tokens_merge_and_stay_counted() {
        let limits = limits(budget(1_000_000, BudgetWindow::Month));
        for minute in 0..30 {
            limits.record_tokens(KEY, 10, NOON + minute * 60_000);
        }
        assert_eq!(limits.spent_tokens(KEY, NOON + 1_800_000), Some(300));
    }

    #[test]
    fn calendar_windows_are_utc_days_and_months() {
        // 2026-12-31T23:00:00Z.
        let late = 1_798_758_000;
        assert_eq!(window_start(BudgetWindow::Day, late), 1_798_675_200);
        assert_eq!(window_end(BudgetWindow::Day, late), 1_798_761_600);
        // 2026-12-01T00:00:00Z and 2027-01-01T00:00:00Z.
        assert_eq!(window_start(BudgetWindow::Month, late), 1_796_083_200);
        assert_eq!(window_end(BudgetWindow::Month, late), 1_798_761_600);
    }

    #[test]
    fn out_of_range_values_are_invalid() {
        assert!(rate(60, Some(10)).is_valid());
        assert!(!rate(0, None).is_valid());
        assert!(!rate(60, Some(0)).is_valid());
        assert!(!rate(MAX_REQUESTS_PER_MINUTE + 1, None).is_valid());
        assert!(budget(1, BudgetWindow::Day).is_valid());
        assert!(!budget(0, BudgetWindow::Day).is_valid());
        assert!(!budget(MAX_BUDGET_TOKENS + 1, BudgetWindow::Day).is_valid());
    }
}
