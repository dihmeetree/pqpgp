//! Rate limiting for PM operations.
//!
//! This module provides rate limiting to prevent abuse of PM functionality:
//! - Creating encryption identities (prekey bundle spam)
//! - Sending messages (spam flooding)
//! - Scanning for messages (resource exhaustion)
//!
//! ## Security Considerations
//!
//! Rate limiting is essential for:
//! - Preventing DoS attacks on the PM system
//! - Reducing spam message flooding
//! - Protecting computational resources (expensive crypto operations)

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Rate limiter configuration for PM operations.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum number of operations allowed in the time window.
    pub max_requests: u32,
    /// Time window for rate limiting.
    pub window: Duration,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_requests: 10,
            window: Duration::from_secs(60),
        }
    }
}

/// Rate limiter for PM operations.
///
/// Uses a sliding window algorithm to track operations per identity.
#[derive(Debug, Clone)]
pub struct PmRateLimiter {
    config: RateLimitConfig,
    /// Maps identity fingerprint -> list of operation timestamps
    requests: Arc<RwLock<HashMap<String, Vec<Instant>>>>,
}

impl PmRateLimiter {
    /// Creates a new rate limiter with the given configuration.
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            requests: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Creates a rate limiter with default configuration.
    pub fn default_config() -> Self {
        Self::new(RateLimitConfig::default())
    }

    /// Creates rate limiters with recommended settings for different PM operations.
    pub fn recommended() -> PmRateLimiterSet {
        PmRateLimiterSet {
            // Identity creation: 3 per hour (generous for legitimate use)
            identity_creation: Self::new(RateLimitConfig {
                max_requests: 3,
                window: Duration::from_secs(3600),
            }),
            // Message sending: 30 per minute (allows rapid conversation)
            message_send: Self::new(RateLimitConfig {
                max_requests: 30,
                window: Duration::from_secs(60),
            }),
            // Message scanning: 10 per minute (prevent resource exhaustion)
            message_scan: Self::new(RateLimitConfig {
                max_requests: 10,
                window: Duration::from_secs(60),
            }),
        }
    }

    /// Checks if an operation is allowed for the given identity.
    ///
    /// Returns `true` if the operation is allowed, `false` if rate limited.
    pub fn check(&self, identity_fingerprint: &str) -> bool {
        let now = Instant::now();
        let cutoff = now - self.config.window;

        let requests = self.requests.read().unwrap();
        if let Some(timestamps) = requests.get(identity_fingerprint) {
            let recent_count = timestamps.iter().filter(|&&t| t > cutoff).count();
            recent_count < self.config.max_requests as usize
        } else {
            true
        }
    }

    /// Records an operation for the given identity.
    ///
    /// Should be called after successfully completing an operation.
    pub fn record(&self, identity_fingerprint: &str) {
        let now = Instant::now();
        let cutoff = now - self.config.window;

        let mut requests = self.requests.write().unwrap();
        let timestamps = requests
            .entry(identity_fingerprint.to_string())
            .or_default();

        // Remove old entries and add new one
        timestamps.retain(|&t| t > cutoff);
        timestamps.push(now);
    }

    /// Checks and records an operation atomically.
    ///
    /// Returns `true` if the operation was allowed and recorded.
    pub fn check_and_record(&self, identity_fingerprint: &str) -> bool {
        let now = Instant::now();
        let cutoff = now - self.config.window;

        let mut requests = self.requests.write().unwrap();
        let timestamps = requests
            .entry(identity_fingerprint.to_string())
            .or_default();

        // Remove old entries
        timestamps.retain(|&t| t > cutoff);

        // Check limit
        if timestamps.len() < self.config.max_requests as usize {
            timestamps.push(now);
            true
        } else {
            false
        }
    }

    /// Returns the remaining requests allowed for an identity.
    pub fn remaining(&self, identity_fingerprint: &str) -> u32 {
        let now = Instant::now();
        let cutoff = now - self.config.window;

        let requests = self.requests.read().unwrap();
        if let Some(timestamps) = requests.get(identity_fingerprint) {
            let recent_count = timestamps.iter().filter(|&&t| t > cutoff).count();
            self.config.max_requests.saturating_sub(recent_count as u32)
        } else {
            self.config.max_requests
        }
    }

    /// Returns the time until the rate limit resets (oldest entry expires).
    pub fn reset_time(&self, identity_fingerprint: &str) -> Option<Duration> {
        let now = Instant::now();
        let cutoff = now - self.config.window;

        let requests = self.requests.read().unwrap();
        if let Some(timestamps) = requests.get(identity_fingerprint) {
            let recent: Vec<_> = timestamps.iter().filter(|&&t| t > cutoff).collect();
            if recent.len() >= self.config.max_requests as usize {
                // Find the oldest timestamp that's still in the window
                if let Some(&&oldest) = recent.iter().min() {
                    let expires_at = oldest + self.config.window;
                    if expires_at > now {
                        return Some(expires_at - now);
                    }
                }
            }
        }
        None
    }

    /// Cleans up old entries from all identities.
    ///
    /// Should be called periodically to prevent memory growth.
    pub fn cleanup(&self) {
        let now = Instant::now();
        let cutoff = now - self.config.window;

        let mut requests = self.requests.write().unwrap();
        requests.retain(|_, timestamps| {
            timestamps.retain(|&t| t > cutoff);
            !timestamps.is_empty()
        });
    }
}

/// Set of rate limiters for different PM operations.
#[derive(Debug, Clone)]
pub struct PmRateLimiterSet {
    /// Rate limiter for creating encryption identities.
    pub identity_creation: PmRateLimiter,
    /// Rate limiter for sending messages.
    pub message_send: PmRateLimiter,
    /// Rate limiter for scanning messages.
    pub message_scan: PmRateLimiter,
}

impl PmRateLimiterSet {
    /// Cleans up old entries from all rate limiters.
    pub fn cleanup(&self) {
        self.identity_creation.cleanup();
        self.message_send.cleanup();
        self.message_scan.cleanup();
    }
}

impl Default for PmRateLimiterSet {
    fn default() -> Self {
        PmRateLimiter::recommended()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn test_basic_rate_limiting() {
        let limiter = PmRateLimiter::new(RateLimitConfig {
            max_requests: 3,
            window: Duration::from_secs(1),
        });

        // First 3 requests should succeed
        assert!(limiter.check_and_record("user1"));
        assert!(limiter.check_and_record("user1"));
        assert!(limiter.check_and_record("user1"));

        // 4th request should fail
        assert!(!limiter.check_and_record("user1"));

        // Different user should succeed
        assert!(limiter.check_and_record("user2"));
    }

    #[test]
    fn test_window_expiry() {
        let limiter = PmRateLimiter::new(RateLimitConfig {
            max_requests: 2,
            window: Duration::from_millis(100),
        });

        // Use up the limit
        assert!(limiter.check_and_record("user1"));
        assert!(limiter.check_and_record("user1"));
        assert!(!limiter.check_and_record("user1"));

        // Wait for window to expire
        sleep(Duration::from_millis(150));

        // Should be allowed again
        assert!(limiter.check_and_record("user1"));
    }

    #[test]
    fn test_remaining_requests() {
        let limiter = PmRateLimiter::new(RateLimitConfig {
            max_requests: 5,
            window: Duration::from_secs(60),
        });

        assert_eq!(limiter.remaining("user1"), 5);

        limiter.record("user1");
        assert_eq!(limiter.remaining("user1"), 4);

        limiter.record("user1");
        limiter.record("user1");
        assert_eq!(limiter.remaining("user1"), 2);
    }

    #[test]
    fn test_cleanup() {
        let limiter = PmRateLimiter::new(RateLimitConfig {
            max_requests: 10,
            window: Duration::from_millis(50),
        });

        limiter.record("user1");
        limiter.record("user2");

        // Wait for entries to expire
        sleep(Duration::from_millis(100));

        limiter.cleanup();

        // After cleanup, both users should have full quota
        assert_eq!(limiter.remaining("user1"), 10);
        assert_eq!(limiter.remaining("user2"), 10);
    }

    #[test]
    fn test_recommended_limits() {
        let limiters = PmRateLimiter::recommended();

        // Identity creation should be more restrictive
        assert!(
            limiters.identity_creation.config.max_requests
                < limiters.message_send.config.max_requests
        );

        // Message sending should allow more requests
        assert!(limiters.message_send.config.max_requests >= 30);
    }
}
