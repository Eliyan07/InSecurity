/// Cache management and eviction policies
use super::HashCache;
use serde::{Deserialize, Serialize};

pub struct CacheManager {
    cache: HashCache,
    max_age_seconds: u64,
    _eviction_interval_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    pub max_size: usize,
    pub ttl_seconds: u64,
    pub eviction_interval_seconds: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        CacheConfig {
            max_size: 10000,
            ttl_seconds: 86400,
            eviction_interval_seconds: 3600,
        }
    }
}

impl CacheManager {
    pub fn new(config: CacheConfig) -> Self {
        CacheManager {
            cache: HashCache::new(config.max_size),
            max_age_seconds: config.ttl_seconds,
            _eviction_interval_seconds: config.eviction_interval_seconds,
        }
    }

    pub fn get_cache_mut(&mut self) -> &mut HashCache {
        &mut self.cache
    }

    pub fn get_cache(&self) -> &HashCache {
        &self.cache
    }

    /// Remove a specific hash from the cache
    pub fn invalidate(&mut self, hash: &str) {
        self.cache.remove(hash);
        log::debug!("Invalidated cache entry for hash: {}", hash);
    }

    pub fn get_stats(&self) -> CacheStats {
        let stats = self.cache.stats();
        CacheStats {
            total_entries: stats.total_entries,
            expired_entries: stats.expired_entries,
            capacity: stats.capacity,
            hit_rate: 0.0, // Would track hits/misses
        }
    }

    pub fn get_or_sync_verdict(
        &mut self,
        hash: &str,
    ) -> Option<crate::cache::hash_cache::CachedVerdict> {
        if let Some(v) = self.cache.get(hash) {
            if !v.is_expired() {
                return Some(v.clone());
            }
        }

        // Try to read from DB
        if let Ok(db_lock) = crate::DB.lock() {
            if let Some(conn) = db_lock.as_ref() {
                if let Ok(Some(row)) =
                    crate::database::queries::DatabaseQueries::get_verdict_by_hash(conn, hash)
                {
                    let now_ts = row.scanned_at as u64;
                    let cached = crate::cache::hash_cache::CachedVerdict {
                        verdict: row.verdict.clone(),
                        confidence: row.confidence,
                        timestamp: now_ts,
                        ttl_seconds: self.max_age_seconds,
                        last_accessed: now_ts,
                        threat_name: row.threat_name.clone(),
                    };
                    // insert into cache
                    self.cache.set(hash.to_string(), cached.clone());
                    return Some(cached);
                }
            }
        }

        None
    }

    /// Sync cache with latest threat intelligence from DB
    pub fn sync_threat_intel(&mut self) -> Result<usize, String> {
        let mut synced = 0;

        if let Ok(db) = crate::DB.lock() {
            if let Some(conn) = db.as_ref() {
                let mut stmt = conn.prepare(
                    "SELECT file_hash, threat_name, severity FROM threat_intel WHERE last_updated > ?1"
                ).map_err(|e| e.to_string())?;

                let cutoff = chrono::Utc::now().timestamp() - (self.max_age_seconds as i64);
                let rows = stmt
                    .query_map([cutoff], |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                        ))
                    })
                    .map_err(|e| e.to_string())?;

                for (hash, threat_name, severity) in rows.flatten() {
                    let verdict = if severity == "CRITICAL" || severity == "HIGH" {
                        "Malware"
                    } else {
                        "Suspicious"
                    };

                    let now_ts = chrono::Utc::now().timestamp() as u64;
                    self.cache.set(
                        hash.clone(),
                        crate::cache::hash_cache::CachedVerdict {
                            verdict: verdict.to_string(),
                            confidence: 0.95,
                            timestamp: now_ts,
                            ttl_seconds: self.max_age_seconds,
                            last_accessed: now_ts,
                            threat_name: Some(threat_name.clone()),
                        },
                    );
                    log::debug!("sync_threat_intel added {} - {}", threat_name, hash);
                    synced += 1;
                }
            }
        }

        Ok(synced)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStats {
    pub total_entries: usize,
    pub expired_entries: usize,
    pub capacity: usize,
    pub hit_rate: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::models::Verdict as DbVerdict;
    use crate::database::schema::DatabaseSchema;
    use crate::DB;
    use rusqlite::Connection;

    #[test]
    #[ignore]
    fn test_get_or_sync_verdict_from_db() {
        // set up an in-memory DB and put into global DB
        let conn = Connection::open_in_memory().unwrap();
        DatabaseSchema::init(&conn).unwrap();

        {
            let mut guard = DB.lock().unwrap();
            *guard = Some(conn);
        }

        // insert a verdict row
        let rec = DbVerdict {
            id: 0,
            file_hash: "hash-sync".to_string(),
            file_path: "C:\\tmp\\x.exe".to_string(),
            verdict: "Malware".to_string(),
            confidence: 0.99,
            threat_level: "HIGH".to_string(),
            threat_name: None,
            scan_time_ms: 100,
            scanned_at: chrono::Utc::now().timestamp(),
            source: "realtime".to_string(),
        };

        crate::database::queries::DatabaseQueries::insert_verdict(
            DB.lock().unwrap().as_ref().unwrap(),
            &rec,
        )
        .unwrap();

        let guard = DB.lock().unwrap();
        let conn_ref = guard.as_ref().unwrap();
        let dbrow =
            crate::database::queries::DatabaseQueries::get_verdict_by_hash(conn_ref, "hash-sync")
                .unwrap();
        assert!(dbrow.is_some(), "DB row was not inserted successfully");

        let mut mgr = CacheManager::new(CacheConfig::default());
        let got = mgr.get_or_sync_verdict("hash-sync");
        assert!(got.is_some());
        let cache_val = got.unwrap();
        assert_eq!(cache_val.verdict, "Malware");
        assert!(cache_val.confidence > 0.5);
    }

    #[test]
    fn test_cache_manager_new_with_config() {
        let config = CacheConfig {
            max_size: 500,
            ttl_seconds: 7200,
            eviction_interval_seconds: 1800,
        };
        let mgr = CacheManager::new(config);
        let stats = mgr.get_stats();
        assert_eq!(stats.capacity, 500);
        assert_eq!(stats.total_entries, 0);
    }

    #[test]
    fn test_cache_config_default() {
        let config = CacheConfig::default();
        assert_eq!(config.max_size, 10000);
        assert_eq!(config.ttl_seconds, 86400);
        assert_eq!(config.eviction_interval_seconds, 3600);
    }

    #[test]
    fn test_cache_manager_invalidate() {
        let mut mgr = CacheManager::new(CacheConfig::default());
        let now_ts = chrono::Utc::now().timestamp() as u64;
        let v = crate::cache::hash_cache::CachedVerdict {
            verdict: "clean".to_string(),
            confidence: 0.95,
            timestamp: now_ts,
            ttl_seconds: 3600,
            last_accessed: now_ts,
            threat_name: None,
        };
        mgr.get_cache_mut().set("hash_to_invalidate".to_string(), v);
        assert!(mgr.get_cache_mut().get("hash_to_invalidate").is_some());

        mgr.invalidate("hash_to_invalidate");
        assert!(mgr.get_cache_mut().get("hash_to_invalidate").is_none());
    }

    #[test]
    fn test_cache_manager_stats() {
        let mut mgr = CacheManager::new(CacheConfig::default());
        let now_ts = chrono::Utc::now().timestamp() as u64;

        for i in 0..5 {
            mgr.get_cache_mut().set(
                format!("hash_{}", i),
                crate::cache::hash_cache::CachedVerdict {
                    verdict: "clean".to_string(),
                    confidence: 0.9,
                    timestamp: now_ts,
                    ttl_seconds: 3600,
                    last_accessed: now_ts,
                    threat_name: None,
                },
            );
        }

        let stats = mgr.get_stats();
        assert_eq!(stats.total_entries, 5);
        assert_eq!(stats.capacity, 10000);
        assert_eq!(stats.expired_entries, 0);
    }

    #[test]
    fn test_eviction_interval_field_is_unused() {
        // Different eviction_interval_seconds values should produce identical behavior
        let config_a = CacheConfig {
            max_size: 10,
            ttl_seconds: 100,
            eviction_interval_seconds: 1,
        };
        let config_b = CacheConfig {
            max_size: 10,
            ttl_seconds: 100,
            eviction_interval_seconds: 99999,
        };
        let mgr_a = CacheManager::new(config_a);
        let mgr_b = CacheManager::new(config_b);
        // Both should have the same stats since eviction_interval is not used
        assert_eq!(mgr_a.get_stats().capacity, mgr_b.get_stats().capacity);
        assert_eq!(
            mgr_a.get_stats().total_entries,
            mgr_b.get_stats().total_entries
        );
    }

    #[test]
    fn test_sync_threat_intel_populates_cache() {
        // Setup in-memory DB
        let conn = Connection::open_in_memory().unwrap();
        DatabaseSchema::init(&conn).unwrap();

        {
            let mut guard = DB.lock().unwrap();
            *guard = Some(conn);
        }

        // Insert a threat that is recent
        let now = chrono::Utc::now().timestamp();
        let rec = crate::database::models::ThreatIntelRecord {
            file_hash: "sync-hash-1".to_string(),
            threat_name: "Cloud Trojan".to_string(),
            severity: "HIGH".to_string(),
            family: Some("Trojan.Cloud".to_string()),
            first_seen: now - 10,
            last_updated: now,
            source: "manual".to_string(),
        };
        crate::database::queries::DatabaseQueries::insert_threat_intel(
            DB.lock().unwrap().as_ref().unwrap(),
            &rec,
        )
        .unwrap();

        let mut mgr = CacheManager::new(CacheConfig::default());
        let synced = mgr.sync_threat_intel().unwrap();
        assert!(synced >= 1);

        // Cache should have entry
        let entry = mgr.get_cache_mut().get("sync-hash-1");
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().verdict, "Malware");
    }
}
