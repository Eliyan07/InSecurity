//! Rate Limiter Module
//! Provides reusable rate limiting for API calls with configurable windows and limits

use chrono::Utc;
use once_cell::sync::Lazy;
use std::collections::VecDeque;
use std::sync::Mutex;

#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub max_requests: usize,
    pub window_seconds: i64,
    pub name: String,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_requests: 10,
            window_seconds: 60,
            name: "default".to_string(),
        }
    }
}

struct RateLimiterInner {
    config: RateLimitConfig,
    request_times: VecDeque<i64>,
    warned: bool,
}

impl RateLimiterInner {
    fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            request_times: VecDeque::with_capacity(100),
            warned: false,
        }
    }

    fn check(&mut self) -> Option<i64> {
        let now = Utc::now().timestamp();

        // Remove old requests outside the window
        while let Some(&oldest) = self.request_times.front() {
            if now - oldest >= self.config.window_seconds {
                self.request_times.pop_front();
            } else {
                break;
            }
        }

        if self.request_times.len() >= self.config.max_requests {
            // Calculate how long to wait
            let oldest = self.request_times.front().copied().unwrap_or(now);
            let wait_time = self.config.window_seconds - (now - oldest);
            Some(wait_time.max(1))
        } else {
            None
        }
    }

    fn record(&mut self) {
        self.request_times.push_back(Utc::now().timestamp());
    }

    fn warn_once(&mut self, message: &str) {
        if !self.warned {
            log::warn!("[{}] {}", self.config.name, message);
            self.warned = true;
        }
    }
}

/// A thread-safe rate limiter that tracks request timestamps within a sliding window
pub struct RateLimiter {
    inner: Mutex<RateLimiterInner>,
}

impl RateLimiter {
    pub fn check(&self) -> Option<i64> {
        match self.inner.lock() {
            Ok(mut guard) => guard.check(),
            Err(_) => None,
        }
    }

    pub fn record(&self) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.record();
        }
    }

    /// Check and record in one operation
    pub fn acquire(&self) -> Option<i64> {
        match self.inner.lock() {
            Ok(mut guard) => {
                if let Some(wait) = guard.check() {
                    Some(wait)
                } else {
                    guard.record();
                    None
                }
            }
            Err(_) => None,
        }
    }

    pub fn warn_once(&self, message: &str) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.warn_once(message);
        }
    }
}

/// Global rate limiter for VirusTotal API (free tier: 4 requests/minute)
pub static VT_RATE_LIMITER: Lazy<RateLimiter> = Lazy::new(|| RateLimiter {
    inner: Mutex::new(RateLimiterInner::new(RateLimitConfig {
        max_requests: 4,
        window_seconds: 60,
        name: "VirusTotal".to_string(),
    })),
});

/// Global rate limiter for MalwareBazaar API (100 requests/minute)
pub static MALWARE_BAZAAR_RATE_LIMITER: Lazy<RateLimiter> = Lazy::new(|| RateLimiter {
    inner: Mutex::new(RateLimiterInner::new(RateLimitConfig {
        max_requests: 100,
        window_seconds: 60,
        name: "MalwareBazaar".to_string(),
    })),
});

/// Global rate limiter for scan operations (prevent DoS from rapid scan requests)
/// Allows 200 scans per minute
pub static SCAN_RATE_LIMITER: Lazy<RateLimiter> = Lazy::new(|| RateLimiter {
    inner: Mutex::new(RateLimiterInner::new(RateLimitConfig {
        max_requests: 200,
        window_seconds: 60,
        name: "ScanOperations".to_string(),
    })),
});

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_limiter(max_requests: usize) -> RateLimiter {
        RateLimiter {
            inner: Mutex::new(RateLimiterInner::new(RateLimitConfig {
                max_requests,
                window_seconds: 60,
                name: "test".to_string(),
            })),
        }
    }

    #[test]
    fn test_rate_limiter_allows_within_limit() {
        let limiter = create_test_limiter(3);

        assert!(limiter.acquire().is_none());
        assert!(limiter.acquire().is_none());
        assert!(limiter.acquire().is_none());
    }

    #[test]
    fn test_rate_limiter_blocks_over_limit() {
        let limiter = create_test_limiter(2);

        assert!(limiter.acquire().is_none());
        assert!(limiter.acquire().is_none());
        assert!(limiter.acquire().is_some()); // Should return wait time
    }

    #[test]
    fn test_check_without_record() {
        let limiter = create_test_limiter(2);

        // Check should not consume quota
        assert!(limiter.check().is_none());
        assert!(limiter.check().is_none());
        assert!(limiter.check().is_none());

        // Still should be able to acquire
        assert!(limiter.acquire().is_none());
        assert!(limiter.acquire().is_none());
    }

    #[test]
    fn test_rate_limiter_exact_limit() {
        let limiter = create_test_limiter(5);

        // Exactly 5 requests should succeed
        for _ in 0..5 {
            assert!(limiter.acquire().is_none(), "Should allow up to 5 requests");
        }
        // 6th should be blocked
        assert!(limiter.acquire().is_some(), "6th request should be blocked");
    }

    #[test]
    fn test_rate_limiter_check_does_not_consume() {
        let limiter = create_test_limiter(1);

        // Multiple checks should not consume quota
        for _ in 0..10 {
            assert!(limiter.check().is_none());
        }

        // First acquire should still work
        assert!(limiter.acquire().is_none());
        // Second should be blocked
        assert!(limiter.acquire().is_some());
    }

    #[test]
    fn test_rate_limiter_record_consumes_quota() {
        let limiter = create_test_limiter(2);

        limiter.record();
        limiter.record();

        // After 2 records, next acquire should be blocked
        assert!(limiter.acquire().is_some());
    }

    #[test]
    fn test_rate_limiter_default_config() {
        let config = RateLimitConfig::default();
        assert_eq!(config.max_requests, 10);
        assert_eq!(config.window_seconds, 60);
        assert_eq!(config.name, "default");
    }
}
