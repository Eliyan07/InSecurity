use serde::{Deserialize, Serialize};
/// In-memory cache with TTL support and O(log n) LRU eviction
use std::collections::{BTreeMap, HashMap};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedVerdict {
    pub verdict: String,
    pub confidence: f64,
    pub timestamp: u64,
    pub ttl_seconds: u64,
    #[serde(default)]
    pub last_accessed: u64,
    #[serde(default)]
    pub threat_name: Option<String>,
}

impl CachedVerdict {
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        now > self.timestamp + self.ttl_seconds
    }

    pub fn touch(&mut self) {
        self.last_accessed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
    }
}

pub struct HashCache {
    cache: HashMap<String, CachedVerdict>,
    /// Secondary index: (last_accessed, hash) → () for O(log n) LRU eviction.
    /// BTreeMap is sorted, so the first entry is always the least recently accessed.
    access_index: BTreeMap<(u64, String), ()>,
    max_size: usize,
}

impl HashCache {
    pub fn new(max_size: usize) -> Self {
        HashCache {
            cache: HashMap::with_capacity(max_size),
            access_index: BTreeMap::new(),
            max_size,
        }
    }

    pub fn get(&mut self, hash: &str) -> Option<CachedVerdict> {
        if let Some(verdict) = self.cache.get_mut(hash) {
            if !verdict.is_expired() {
                let old_accessed = verdict.last_accessed;
                verdict.touch();
                let new_accessed = verdict.last_accessed;
                // Update index only if last_accessed actually changed
                if old_accessed != new_accessed {
                    self.access_index.remove(&(old_accessed, hash.to_string()));
                    self.access_index
                        .insert((new_accessed, hash.to_string()), ());
                }
                return Some(verdict.clone());
            }
        }
        None
    }

    /// Cache a verdict
    pub fn set(&mut self, hash: String, verdict: CachedVerdict) {
        // If key already exists, remove its old index entry
        if let Some(old) = self.cache.get(&hash) {
            self.access_index.remove(&(old.last_accessed, hash.clone()));
        }

        // Evict expired entries if cache is full
        if self.cache.len() >= self.max_size {
            self.evict_expired();
        }

        // If still full, evict the least recently used entry via BTreeMap (O(log n))
        if self.cache.len() >= self.max_size {
            if let Some((&(_, ref lru_hash), _)) = self.access_index.iter().next() {
                let lru_hash = lru_hash.clone();
                self.cache.remove(&lru_hash);
                // Remove from index by finding the exact key
                // We need the exact last_accessed value; since we just got it from iter().next(), reconstruct
                let key_to_remove = self.access_index.keys().next().cloned();
                if let Some(key) = key_to_remove {
                    self.access_index.remove(&key);
                }
            }
        }

        self.access_index
            .insert((verdict.last_accessed, hash.clone()), ());
        self.cache.insert(hash, verdict);
    }

    pub fn clear(&mut self) {
        self.cache.clear();
        self.access_index.clear();
    }

    pub fn remove(&mut self, hash: &str) -> bool {
        if let Some(old) = self.cache.remove(hash) {
            self.access_index
                .remove(&(old.last_accessed, hash.to_string()));
            true
        } else {
            false
        }
    }

    pub fn stats(&self) -> CacheStats {
        CacheStats {
            total_entries: self.cache.len(),
            expired_entries: self.cache.values().filter(|v| v.is_expired()).count(),
            capacity: self.max_size,
        }
    }

    fn evict_expired(&mut self) {
        let expired_keys: Vec<String> = self
            .cache
            .iter()
            .filter(|(_, v)| v.is_expired())
            .map(|(k, _)| k.clone())
            .collect();
        for key in expired_keys {
            if let Some(old) = self.cache.remove(&key) {
                self.access_index.remove(&(old.last_accessed, key));
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStats {
    pub total_entries: usize,
    pub expired_entries: usize,
    pub capacity: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now_ts() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn make_verdict(verdict: &str, ttl: u64) -> CachedVerdict {
        let ts = now_ts();
        CachedVerdict {
            verdict: verdict.to_string(),
            confidence: 0.95,
            timestamp: ts,
            ttl_seconds: ttl,
            last_accessed: ts,
            threat_name: None,
        }
    }

    #[test]
    fn test_cache_get_set() {
        let mut cache = HashCache::new(100);
        cache.set("test_hash".to_string(), make_verdict("clean", 3600));
        let retrieved = cache.get("test_hash");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().verdict, "clean");
    }

    #[test]
    fn test_cache_get_nonexistent_returns_none() {
        let mut cache = HashCache::new(100);
        assert!(cache.get("missing").is_none());
    }

    #[test]
    fn test_cache_get_expired_returns_none() {
        let mut cache = HashCache::new(100);
        // Create an entry that's already expired (timestamp in the past, TTL=0)
        let expired = CachedVerdict {
            verdict: "malware".to_string(),
            confidence: 0.99,
            timestamp: 1000, // Far in the past
            ttl_seconds: 1,  // 1 second TTL
            last_accessed: 1000,
            threat_name: None,
        };
        cache.set("expired_hash".to_string(), expired);
        assert!(cache.get("expired_hash").is_none());
    }

    #[test]
    fn test_cache_eviction_lru() {
        let mut cache = HashCache::new(3); // Max 3 entries

        // Insert 3 entries with staggered last_accessed times
        for i in 0..3 {
            let mut v = make_verdict("clean", 3600);
            v.last_accessed = now_ts() + i; // Increasing access times
            cache.set(format!("hash_{}", i), v);
        }

        assert_eq!(cache.stats().total_entries, 3);

        // Insert 4th entry - should evict hash_0 (least recently accessed)
        cache.set("hash_3".to_string(), make_verdict("clean", 3600));
        assert_eq!(cache.stats().total_entries, 3);

        // hash_0 should be evicted (it had the lowest last_accessed)
        assert!(cache.get("hash_0").is_none());
        // hash_3 should be present
        assert!(cache.get("hash_3").is_some());
    }

    #[test]
    fn test_cache_remove() {
        let mut cache = HashCache::new(100);
        cache.set("to_remove".to_string(), make_verdict("suspicious", 3600));
        assert!(cache.get("to_remove").is_some());

        let removed = cache.remove("to_remove");
        assert!(removed);
        assert!(cache.get("to_remove").is_none());
    }

    #[test]
    fn test_cache_remove_nonexistent() {
        let mut cache = HashCache::new(100);
        assert!(!cache.remove("nonexistent"));
    }

    #[test]
    fn test_cache_clear() {
        let mut cache = HashCache::new(100);
        cache.set("a".to_string(), make_verdict("clean", 3600));
        cache.set("b".to_string(), make_verdict("malware", 3600));
        cache.set("c".to_string(), make_verdict("suspicious", 3600));
        assert_eq!(cache.stats().total_entries, 3);

        cache.clear();
        assert_eq!(cache.stats().total_entries, 0);
    }

    #[test]
    fn test_cache_stats_accuracy() {
        let mut cache = HashCache::new(100);
        cache.set("a".to_string(), make_verdict("clean", 3600));
        cache.set("b".to_string(), make_verdict("clean", 3600));

        let stats = cache.stats();
        assert_eq!(stats.total_entries, 2);
        assert_eq!(stats.capacity, 100);
        assert_eq!(stats.expired_entries, 0);
    }

    #[test]
    fn test_cache_stats_counts_expired() {
        let mut cache = HashCache::new(100);
        cache.set("fresh".to_string(), make_verdict("clean", 3600));
        // Expired entry
        let expired = CachedVerdict {
            verdict: "old".to_string(),
            confidence: 0.5,
            timestamp: 1000,
            ttl_seconds: 1,
            last_accessed: 1000,
            threat_name: None,
        };
        cache.set("stale".to_string(), expired);

        let stats = cache.stats();
        assert_eq!(stats.total_entries, 2);
        assert_eq!(stats.expired_entries, 1);
    }

    #[test]
    fn test_cache_update_existing_key() {
        let mut cache = HashCache::new(100);
        cache.set("hash".to_string(), make_verdict("clean", 3600));
        cache.set("hash".to_string(), make_verdict("malware", 3600));

        let retrieved = cache.get("hash").unwrap();
        assert_eq!(retrieved.verdict, "malware");
        assert_eq!(cache.stats().total_entries, 1);
    }

    #[test]
    fn test_cache_get_updates_last_accessed() {
        let mut cache = HashCache::new(100);
        let mut v = make_verdict("clean", 3600);
        v.last_accessed = 1000;
        v.timestamp = now_ts(); // Not expired
        cache.set("hash".to_string(), v);

        let retrieved = cache.get("hash").unwrap();
        // touch() should have updated last_accessed to current time
        assert!(retrieved.last_accessed > 1000);
    }

    #[test]
    fn test_cache_eviction_prefers_expired_first() {
        let mut cache = HashCache::new(2);

        // Fresh entry
        cache.set("fresh".to_string(), make_verdict("clean", 3600));
        // Expired entry
        let expired = CachedVerdict {
            verdict: "old".to_string(),
            confidence: 0.5,
            timestamp: 1000,
            ttl_seconds: 1,
            last_accessed: now_ts() + 100, // High access time but expired
            threat_name: None,
        };
        cache.set("expired".to_string(), expired);

        // Insert 3rd -> should evict the expired one via evict_expired()
        cache.set("new".to_string(), make_verdict("clean", 3600));
        assert_eq!(cache.stats().total_entries, 2);
        assert!(cache.get("fresh").is_some());
        assert!(cache.get("new").is_some());
    }

    #[test]
    fn test_cached_verdict_is_expired() {
        let fresh = make_verdict("clean", 3600);
        assert!(!fresh.is_expired());

        let expired = CachedVerdict {
            verdict: "old".to_string(),
            confidence: 0.5,
            timestamp: 1000,
            ttl_seconds: 1,
            last_accessed: 1000,
            threat_name: None,
        };
        assert!(expired.is_expired());
    }

    #[test]
    fn test_cached_verdict_touch() {
        let mut v = make_verdict("clean", 3600);
        v.last_accessed = 0;
        v.touch();
        assert!(v.last_accessed > 0);
    }

    #[test]
    fn test_cache_with_threat_name() {
        let mut cache = HashCache::new(100);
        let mut v = make_verdict("malware", 3600);
        v.threat_name = Some("Trojan.Generic".to_string());
        cache.set("threat".to_string(), v);

        let retrieved = cache.get("threat").unwrap();
        assert_eq!(retrieved.threat_name, Some("Trojan.Generic".to_string()));
    }

    #[test]
    fn test_access_index_consistency() {
        let mut cache = HashCache::new(100);
        cache.set("a".to_string(), make_verdict("clean", 3600));
        cache.set("b".to_string(), make_verdict("clean", 3600));
        assert_eq!(cache.access_index.len(), 2);

        cache.remove("a");
        assert_eq!(cache.access_index.len(), 1);

        cache.clear();
        assert_eq!(cache.access_index.len(), 0);
    }
}
