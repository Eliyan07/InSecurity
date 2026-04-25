use super::models::*;
/// Database query helpers
use rusqlite::{params, Connection, OptionalExtension, Result};
use std::collections::HashSet;
use std::sync::RwLock;

/// In-memory cache for exclusion rules. Exclusions rarely change but are checked
/// on every real-time file event, so caching avoids repeated DB queries.
static EXCLUSION_CACHE: RwLock<Option<Vec<Exclusion>>> = RwLock::new(None);

/// Invalidate the in-memory exclusion cache. Call this after any mutation
/// (insert, update, toggle, delete) to exclusion rules.
pub fn invalidate_exclusion_cache() {
    if let Ok(mut guard) = EXCLUSION_CACHE.write() {
        *guard = None;
    }
}

pub struct DatabaseQueries;

impl DatabaseQueries {
    pub fn get_or_create_file(
        conn: &Connection,
        file_hash: &str,
        canonical_path: Option<&str>,
        file_size: Option<i64>,
        file_type: Option<&str>,
    ) -> Result<i64> {
        let mut stmt = conn.prepare("SELECT id FROM files WHERE file_hash = ?1")?;
        if let Ok(id) = stmt.query_row([file_hash], |r| r.get::<_, i64>(0)) {
            return Ok(id);
        }

        conn.execute(
            "INSERT INTO files (file_hash, canonical_path, file_size, file_type, first_seen, last_seen) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![file_hash, canonical_path, file_size, file_type, chrono::Utc::now().timestamp(), chrono::Utc::now().timestamp()],
        )?;

        Ok(conn.last_insert_rowid())
    }
    pub fn insert_verdict(conn: &Connection, verdict: &Verdict) -> Result<()> {
        let file_id = match DatabaseQueries::get_or_create_file(
            conn,
            &verdict.file_hash,
            Some(&verdict.file_path),
            Some(verdict.scan_time_ms as i64),
            Some(&verdict.file_path),
        ) {
            Ok(id) => id,
            Err(e) => {
                log::warn!(
                    "Failed to get/create file record for hash {}: {}",
                    &verdict.file_hash,
                    e
                );
                0
            }
        };

        conn.execute(
            "INSERT INTO verdicts
            (file_hash, file_path, verdict, confidence, threat_level, threat_name, scan_time_ms, scanned_at, file_id, source)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                &verdict.file_hash,
                &verdict.file_path,
                &verdict.verdict,
                verdict.confidence,
                &verdict.threat_level,
                &verdict.threat_name,
                verdict.scan_time_ms,
                verdict.scanned_at,
                file_id,
                &verdict.source,
            ],
        )?;
        Ok(())
    }

    pub fn get_verdict_by_hash(conn: &Connection, hash: &str) -> Result<Option<Verdict>> {
        let mut stmt = conn.prepare(
            "SELECT id, file_hash, file_path, verdict, confidence, threat_level, threat_name, scan_time_ms, scanned_at, source
             FROM verdicts WHERE file_hash = ?1
             ORDER BY scanned_at DESC, id DESC
             LIMIT 1"
        )?;

        let verdict = stmt
            .query_row([hash], |row| {
                Ok(Verdict {
                    id: row.get(0)?,
                    file_hash: row.get(1)?,
                    file_path: row.get(2)?,
                    verdict: row.get(3)?,
                    confidence: row.get(4)?,
                    threat_level: row.get(5)?,
                    threat_name: row.get(6)?,
                    scan_time_ms: row.get(7)?,
                    scanned_at: row.get(8)?,
                    source: row.get(9)?,
                })
            })
            .optional()?;

        Ok(verdict)
    }

    pub fn get_recent_verdicts(conn: &Connection, limit: u32) -> Result<Vec<Verdict>> {
        let mut stmt = conn.prepare(
            r#"SELECT v.id, v.file_hash, v.file_path, v.verdict, v.confidence, v.threat_level, v.threat_name, v.scan_time_ms, v.scanned_at, v.source
             FROM verdicts v
             WHERE v.id = (
                 SELECT v2.id
                 FROM verdicts v2
                 WHERE LOWER(REPLACE(v2.file_path, '/', '\')) = LOWER(REPLACE(v.file_path, '/', '\'))
                 ORDER BY v2.scanned_at DESC, v2.id DESC
                 LIMIT 1
             )
             ORDER BY v.scanned_at DESC
             LIMIT ?1"#
        )?;

        let verdicts = stmt
            .query_map([limit as i64], |row| {
                Ok(Verdict {
                    id: row.get(0)?,
                    file_hash: row.get(1)?,
                    file_path: row.get(2)?,
                    verdict: row.get(3)?,
                    confidence: row.get(4)?,
                    threat_level: row.get(5)?,
                    threat_name: row.get(6)?,
                    scan_time_ms: row.get(7)?,
                    scanned_at: row.get(8)?,
                    source: row.get(9)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(verdicts)
    }

    pub fn insert_quarantine(conn: &Connection, record: &QuarantineRecord) -> Result<()> {
        conn.execute(
            "INSERT INTO quarantine 
            (file_hash, original_path, quarantine_path, verdict, threat_level, reason, quarantined_at, restored_at, permanently_deleted, file_size, file_type)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                &record.file_hash,
                &record.original_path,
                &record.quarantine_path,
                &record.verdict,
                &record.threat_level,
                &record.reason,
                record.quarantined_at,
                &record.restored_at,
                record.permanently_deleted as i32,
                record.file_size,
                &record.file_type,
            ],
        )?;
        Ok(())
    }

    /// FIX: Filter out both permanently deleted AND restored entries.
    /// Previously only filtered permanently_deleted = 0, so restored files
    /// kept appearing in the quarantine tab.
    pub fn get_all_quarantined(conn: &Connection) -> Result<Vec<QuarantineRecord>> {
        let mut stmt = conn.prepare(
            "SELECT id, file_hash, original_path, quarantine_path, verdict, threat_level, reason,
                    quarantined_at, restored_at, permanently_deleted, file_size, file_type
             FROM quarantine WHERE permanently_deleted = 0 AND restored_at IS NULL",
        )?;

        let records = stmt
            .query_map([], |row| {
                Ok(QuarantineRecord {
                    id: row.get(0)?,
                    file_hash: row.get(1)?,
                    original_path: row.get(2)?,
                    quarantine_path: row.get(3)?,
                    verdict: row.get(4)?,
                    threat_level: row.get(5)?,
                    reason: row.get(6)?,
                    quarantined_at: row.get(7)?,
                    restored_at: row.get(8)?,
                    permanently_deleted: row.get::<_, i32>(9)? != 0,
                    file_size: row.get(10)?,
                    file_type: row.get(11)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(records)
    }

    pub fn insert_feature_record(
        conn: &Connection,
        hash: &str,
        features_json: &str,
        created_at: i64,
    ) -> Result<()> {
        let _ = conn.execute(
            "UPDATE files SET last_seen = ?1 WHERE file_hash = ?2",
            params![created_at, hash],
        );

        conn.execute(
            "INSERT OR REPLACE INTO features (file_hash, features_json, created_at) VALUES (?1, ?2, ?3)",
            params![hash, features_json, created_at],
        )?;
        Ok(())
    }

    pub fn get_features_by_hash(conn: &Connection, hash: &str) -> Result<Option<String>> {
        let mut stmt = conn.prepare("SELECT features_json FROM features WHERE file_hash = ?1")?;
        let result = stmt
            .query_row([hash], |row| row.get::<_, String>(0))
            .optional()?;
        Ok(result)
    }

    pub fn get_recent_features(conn: &Connection, limit: u32) -> Result<Vec<(String, String)>> {
        let mut stmt = conn
            .prepare("SELECT file_hash, features_json FROM features ORDER BY id DESC LIMIT ?1")?;
        let rows = stmt
            .query_map([limit as i64], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn insert_external_report(
        conn: &Connection,
        provider: &str,
        identifier: &str,
        data_json: &str,
        fetched_at: i64,
    ) -> Result<()> {
        conn.execute(
            "INSERT INTO external_reports (provider, identifier, data_json, fetched_at) VALUES (?1, ?2, ?3, ?4)",
            params![provider, identifier, data_json, fetched_at],
        )?;
        Ok(())
    }

    pub fn insert_threat_intel(
        conn: &Connection,
        record: &super::models::ThreatIntelRecord,
    ) -> Result<()> {
        conn.execute(
            "INSERT OR REPLACE INTO threat_intel (file_hash, threat_name, severity, family, first_seen, last_updated, source) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                &record.file_hash,
                &record.threat_name,
                &record.severity,
                record.family.as_deref(),
                record.first_seen,
                record.last_updated,
                &record.source,
            ],
        )?;
        Ok(())
    }

    pub fn get_threat_by_hash(conn: &Connection, hash: &str) -> Result<Option<ThreatIntel>> {
        let mut stmt = conn.prepare("SELECT id, file_hash, threat_name, severity, family, first_seen, last_updated, source FROM threat_intel WHERE file_hash = ?1 ORDER BY last_updated DESC LIMIT 1")?;
        let row = stmt
            .query_row([hash], |r| {
                Ok(ThreatIntel {
                    id: r.get(0)?,
                    file_hash: r.get(1)?,
                    threat_name: r.get(2)?,
                    severity: r.get(3)?,
                    family: r.get(4)?,
                    first_seen: r.get(5)?,
                    last_updated: r.get(6)?,
                    source: r.get(7)?,
                })
            })
            .optional()?;
        Ok(row)
    }

    pub fn get_recent_threats(conn: &Connection, limit: u32) -> Result<Vec<ThreatIntel>> {
        let mut stmt = conn.prepare("SELECT id, file_hash, threat_name, severity, family, first_seen, last_updated, source FROM threat_intel ORDER BY last_updated DESC LIMIT ?1")?;
        let rows = stmt
            .query_map([limit as i64], |r| {
                Ok(ThreatIntel {
                    id: r.get(0)?,
                    file_hash: r.get(1)?,
                    threat_name: r.get(2)?,
                    severity: r.get(3)?,
                    family: r.get(4)?,
                    first_seen: r.get(5)?,
                    last_updated: r.get(6)?,
                    source: r.get(7)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn get_all_threat_hashes(conn: &Connection) -> Result<Vec<String>> {
        let mut stmt = conn.prepare("SELECT file_hash FROM threat_intel")?;
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn get_threat_intel_count(conn: &Connection) -> Result<usize> {
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM threat_intel", [], |r| r.get(0))?;
        Ok(count as usize)
    }

    pub fn get_external_report(
        conn: &Connection,
        provider: &str,
        identifier: &str,
    ) -> Result<Option<ExternalReport>> {
        let mut stmt = conn.prepare("SELECT id, provider, identifier, data_json, fetched_at FROM external_reports WHERE provider = ?1 AND identifier = ?2 ORDER BY fetched_at DESC LIMIT 1")?;
        let row = stmt
            .query_row(params![provider, identifier], |r| {
                Ok(ExternalReport {
                    id: r.get(0)?,
                    provider: r.get(1)?,
                    identifier: r.get(2)?,
                    data_json: r.get(3)?,
                    fetched_at: r.get(4)?,
                })
            })
            .optional()?;
        Ok(row)
    }

    pub fn get_recent_external_reports(
        conn: &Connection,
        limit: u32,
    ) -> Result<Vec<ExternalReport>> {
        let mut stmt = conn.prepare("SELECT id, provider, identifier, data_json, fetched_at FROM external_reports ORDER BY fetched_at DESC LIMIT ?1")?;
        let rows = stmt
            .query_map([limit as i64], |r| {
                Ok(ExternalReport {
                    id: r.get(0)?,
                    provider: r.get(1)?,
                    identifier: r.get(2)?,
                    data_json: r.get(3)?,
                    fetched_at: r.get(4)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn insert_scan_history(conn: &Connection, history: &ScanHistory) -> Result<()> {
        conn.execute(
            "INSERT INTO scan_history 
            (scan_path, scan_type, total_files, clean_files, suspicious_files, malicious_files, scan_duration_seconds, started_at, completed_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                &history.scan_path,
                &history.scan_type,
                history.total_files,
                history.clean_files,
                history.suspicious_files,
                history.malicious_files,
                history.scan_duration_seconds,
                history.started_at,
                history.completed_at,
            ],
        )?;
        Ok(())
    }

    pub fn insert_exclusion(
        conn: &Connection,
        exclusion_type: &str,
        pattern: &str,
        reason: Option<&str>,
    ) -> Result<i64> {
        let now = chrono::Utc::now().timestamp();
        conn.execute(
            "INSERT INTO exclusions (exclusion_type, pattern, reason, enabled, created_at, updated_at)
             VALUES (?1, ?2, ?3, 1, ?4, ?5)",
            params![exclusion_type, pattern, reason, now, now],
        )?;
        invalidate_exclusion_cache();
        Ok(conn.last_insert_rowid())
    }

    /// Insert exclusion with tamper-evident signature
    pub fn insert_exclusion_signed(
        conn: &Connection,
        exclusion_type: &str,
        pattern: &str,
        reason: Option<&str>,
    ) -> Result<i64> {
        let now = chrono::Utc::now().timestamp();
        let signature = crate::core::tamper_protection::compute_exclusion_signature(
            exclusion_type,
            pattern,
            reason,
            now,
        );
        conn.execute(
            "INSERT INTO exclusions (exclusion_type, pattern, reason, enabled, created_at, updated_at, signature)
             VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6)",
            params![exclusion_type, pattern, reason, now, now, signature],
        )?;
        invalidate_exclusion_cache();
        Ok(conn.last_insert_rowid())
    }

    pub fn get_all_exclusions(conn: &Connection) -> Result<Vec<Exclusion>> {
        let mut stmt = conn.prepare(
            "SELECT id, exclusion_type, pattern, reason, enabled, created_at, updated_at, signature 
             FROM exclusions ORDER BY created_at DESC"
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(Exclusion {
                id: row.get(0)?,
                exclusion_type: row.get(1)?,
                pattern: row.get(2)?,
                reason: row.get(3)?,
                enabled: row.get::<_, i32>(4)? != 0,
                created_at: row.get(5)?,
                updated_at: row.get(6)?,
                signature: row.get(7).ok(),
            })
        })?;
        rows.collect()
    }

    pub fn get_enabled_exclusions(conn: &Connection) -> Result<Vec<Exclusion>> {
        let mut stmt = conn.prepare(
            "SELECT id, exclusion_type, pattern, reason, enabled, created_at, updated_at, signature 
             FROM exclusions WHERE enabled = 1 ORDER BY exclusion_type, pattern"
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(Exclusion {
                id: row.get(0)?,
                exclusion_type: row.get(1)?,
                pattern: row.get(2)?,
                reason: row.get(3)?,
                enabled: row.get::<_, i32>(4)? != 0,
                created_at: row.get(5)?,
                updated_at: row.get(6)?,
                signature: row.get(7).ok(),
            })
        })?;
        rows.collect()
    }

    pub fn update_exclusion(
        conn: &Connection,
        id: i64,
        exclusion_type: Option<&str>,
        pattern: Option<&str>,
        reason: Option<&str>,
        enabled: Option<bool>,
    ) -> Result<()> {
        let now = chrono::Utc::now().timestamp();

        conn.execute(
            "UPDATE exclusions SET exclusion_type = COALESCE(?2, exclusion_type), pattern = COALESCE(?3, pattern), reason = COALESCE(?4, reason), enabled = COALESCE(?5, enabled), updated_at = ?1 WHERE id = ?6",
            params![now, exclusion_type, pattern, reason, enabled.map(|b| if b { 1 } else { 0 }), id],
        )?;
        invalidate_exclusion_cache();
        Ok(())
    }

    pub fn toggle_exclusion(conn: &Connection, id: i64, enabled: bool) -> Result<()> {
        let now = chrono::Utc::now().timestamp();
        conn.execute(
            "UPDATE exclusions SET enabled = ?1, updated_at = ?2 WHERE id = ?3",
            params![if enabled { 1 } else { 0 }, now, id],
        )?;
        invalidate_exclusion_cache();
        Ok(())
    }

    pub fn delete_exclusion(conn: &Connection, id: i64) -> Result<()> {
        conn.execute("DELETE FROM exclusions WHERE id = ?1", params![id])?;
        invalidate_exclusion_cache();
        Ok(())
    }

    pub fn is_path_excluded(conn: &Connection, path: &str) -> Result<bool> {
        // Fast path: use cached exclusions if available
        let exclusions = {
            if let Ok(guard) = EXCLUSION_CACHE.read() {
                if let Some(ref cached) = *guard {
                    cached.clone()
                } else {
                    drop(guard);
                    let fresh = Self::get_enabled_exclusions(conn)?;
                    if let Ok(mut w) = EXCLUSION_CACHE.write() {
                        *w = Some(fresh.clone());
                    }
                    fresh
                }
            } else {
                Self::get_enabled_exclusions(conn)?
            }
        };
        let path_lower = path.to_lowercase();
        let path_normalized = path_lower.replace('\\', "/");

        for excl in exclusions {
            let pattern_lower = excl.pattern.to_lowercase();
            let pattern_normalized = pattern_lower.replace('\\', "/");

            match excl.exclusion_type.as_str() {
                "path" => {
                    if path_normalized == pattern_normalized {
                        return Ok(true);
                    }
                }
                "folder" => {
                    let folder_pattern = if pattern_normalized.ends_with('/') {
                        pattern_normalized.clone()
                    } else {
                        format!("{}/", pattern_normalized)
                    };
                    if path_normalized.starts_with(&folder_pattern)
                        || path_normalized == pattern_normalized.trim_end_matches('/')
                    {
                        return Ok(true);
                    }
                }
                "extension" => {
                    let ext = if pattern_lower.starts_with('.') {
                        pattern_lower.clone()
                    } else {
                        format!(".{}", pattern_lower)
                    };
                    if path_lower.ends_with(&ext) {
                        return Ok(true);
                    }
                }
                "pattern" => {
                    if pattern_lower.contains('*') {
                        let parts: Vec<&str> = pattern_normalized.split('*').collect();
                        if parts.len() == 2 {
                            let (prefix, suffix) = (parts[0], parts[1]);
                            if path_normalized.starts_with(prefix)
                                && path_normalized.ends_with(suffix)
                            {
                                return Ok(true);
                            }
                        } else if parts.len() == 1 {
                            if pattern_normalized.starts_with('*')
                                && path_normalized.ends_with(parts[0])
                            {
                                return Ok(true);
                            }
                            if pattern_normalized.ends_with('*')
                                && path_normalized.starts_with(parts[0])
                            {
                                return Ok(true);
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(false)
    }

    pub fn insert_network_event(conn: &Connection, event: &NetworkEvent) -> Result<()> {
        conn.execute(
            "INSERT INTO network_events (pid, process_name, process_path, remote_ip, remote_port, protocol, event_type, reason, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                event.pid,
                event.process_name,
                event.process_path,
                event.remote_ip,
                event.remote_port,
                event.protocol,
                event.event_type,
                event.reason,
                event.created_at,
            ],
        )?;
        Ok(())
    }

    pub fn get_network_events(conn: &Connection, limit: u32) -> Result<Vec<NetworkEvent>> {
        let mut stmt = conn.prepare(
            "SELECT id, pid, process_name, process_path, remote_ip, remote_port, protocol, event_type, reason, created_at
             FROM network_events ORDER BY created_at DESC LIMIT ?1"
        )?;
        let rows = stmt.query_map(params![limit], |row| {
            Ok(NetworkEvent {
                id: row.get(0)?,
                pid: row.get(1)?,
                process_name: row.get(2)?,
                process_path: row.get(3)?,
                remote_ip: row.get(4)?,
                remote_port: row.get(5)?,
                protocol: row.get(6)?,
                event_type: row.get(7)?,
                reason: row.get(8)?,
                created_at: row.get(9)?,
            })
        })?;
        rows.collect()
    }

    pub fn prune_network_events(conn: &Connection, keep: u32) -> Result<()> {
        conn.execute(
            "DELETE FROM network_events WHERE id NOT IN (
                SELECT id FROM network_events ORDER BY created_at DESC LIMIT ?1
            )",
            params![keep],
        )?;
        Ok(())
    }

    pub fn get_firewall_rules(conn: &Connection) -> Result<Vec<FirewallRule>> {
        let mut stmt = conn.prepare(
            "SELECT id, rule_name, executable_path, direction, action, reason, auto_created, enabled, created_at
             FROM firewall_rules ORDER BY created_at DESC"
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(FirewallRule {
                id: row.get(0)?,
                rule_name: row.get(1)?,
                executable_path: row.get(2)?,
                direction: row.get(3)?,
                action: row.get(4)?,
                reason: row.get(5)?,
                auto_created: row.get::<_, i64>(6)? != 0,
                enabled: row.get::<_, i64>(7)? != 0,
                created_at: row.get(8)?,
            })
        })?;
        rows.collect()
    }

    pub fn insert_firewall_rule(conn: &Connection, rule: &FirewallRule) -> Result<()> {
        conn.execute(
            "INSERT INTO firewall_rules (rule_name, executable_path, direction, action, reason, auto_created, enabled, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                rule.rule_name,
                rule.executable_path,
                rule.direction,
                rule.action,
                rule.reason,
                rule.auto_created as i64,
                rule.enabled as i64,
                rule.created_at,
            ],
        )?;
        Ok(())
    }

    pub fn remove_firewall_rule_by_id(conn: &Connection, id: i64) -> Result<String> {
        let rule_name: String = conn.query_row(
            "SELECT rule_name FROM firewall_rules WHERE id = ?1",
            params![id],
            |row| row.get(0),
        )?;
        conn.execute("DELETE FROM firewall_rules WHERE id = ?1", params![id])?;
        Ok(rule_name)
    }

    pub fn toggle_firewall_rule(conn: &Connection, id: i64) -> Result<(String, bool)> {
        conn.execute(
            "UPDATE firewall_rules SET enabled = CASE WHEN enabled = 1 THEN 0 ELSE 1 END WHERE id = ?1",
            params![id],
        )?;
        let row: (String, i64) = conn.query_row(
            "SELECT rule_name, enabled FROM firewall_rules WHERE id = ?1",
            params![id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        Ok((row.0, row.1 != 0))
    }

    pub fn get_malicious_ips_set(conn: &Connection) -> Result<HashSet<String>> {
        let mut stmt = conn.prepare("SELECT ip_address FROM malicious_ips")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut set = HashSet::new();
        for ip in rows {
            set.insert(ip?);
        }
        Ok(set)
    }

    pub fn insert_malicious_ip(
        conn: &Connection,
        ip: &str,
        threat_name: Option<&str>,
        source: &str,
    ) -> Result<()> {
        conn.execute(
            "INSERT OR IGNORE INTO malicious_ips (ip_address, threat_name, source, added_at) VALUES (?1, ?2, ?3, ?4)",
            params![ip, threat_name, source, chrono::Utc::now().timestamp()],
        )?;
        Ok(())
    }

    pub fn get_network_threats(conn: &Connection, limit: u32) -> Result<Vec<NetworkThreat>> {
        let mut stmt = conn.prepare(
            "SELECT id, pid, process_name, process_path, remote_ip, remote_port, threat_name, protocol, detected_at
             FROM network_threats ORDER BY detected_at DESC LIMIT ?1"
        )?;
        let rows = stmt.query_map(params![limit], |row| {
            Ok(NetworkThreat {
                id: row.get(0)?,
                pid: row.get(1)?,
                process_name: row.get(2)?,
                process_path: row.get(3)?,
                remote_ip: row.get(4)?,
                remote_port: row.get(5)?,
                threat_name: row.get(6)?,
                protocol: row.get(7)?,
                detected_at: row.get(8)?,
            })
        })?;
        rows.collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::schema::DatabaseSchema;
    use rusqlite::Connection;

    #[test]
    fn test_insert_and_query_feature_record() {
        let conn = Connection::open_in_memory().unwrap();
        DatabaseSchema::init(&conn).unwrap();

        let hash = "testhash123";
        let features = "[0.1,0.2,0.3]";
        let ts = 42;

        DatabaseQueries::insert_feature_record(&conn, hash, features, ts).unwrap();

        let read = DatabaseQueries::get_features_by_hash(&conn, hash).unwrap();
        assert!(read.is_some());
        assert_eq!(read.unwrap(), features.to_string());

        let recent = DatabaseQueries::get_recent_features(&conn, 10).unwrap();
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].0, hash.to_string());
    }
    #[test]
    fn test_get_or_create_file_creates_and_returns_same_id() {
        let conn = Connection::open_in_memory().unwrap();
        DatabaseSchema::init(&conn).unwrap();

        let id1 = DatabaseQueries::get_or_create_file(
            &conn,
            "filehash1",
            Some("/tmp/foo"),
            Some(42),
            Some("PE"),
        )
        .unwrap();
        let id2 = DatabaseQueries::get_or_create_file(
            &conn,
            "filehash1",
            Some("/tmp/foo"),
            Some(42),
            Some("PE"),
        )
        .unwrap();
        assert_eq!(id1, id2);

        let id3 =
            DatabaseQueries::get_or_create_file(&conn, "filehash2", None, None, None).unwrap();
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_backfill_files_migration() {
        let conn = Connection::open_in_memory().unwrap();
        DatabaseSchema::init(&conn).unwrap();

        conn.execute("INSERT INTO verdicts (file_hash, file_path, verdict, confidence, threat_level, scan_time_ms, scanned_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params!["hash-mig", "C:/tmp/x", "Malware", 0.9_f64, "HIGH", 100, 12345]).unwrap();

        let mut stmt = conn.prepare("SELECT count(*) FROM files").unwrap();
        let count: i64 = stmt.query_row([], |r| r.get(0)).unwrap();
        assert!(count >= 0);

        crate::database::schema::backfill_files_from_existing(&conn).unwrap();

        let mut stmt = conn
            .prepare("SELECT id FROM files WHERE file_hash = ?1")
            .unwrap();
        let id: i64 = stmt.query_row(["hash-mig"], |r| r.get(0)).unwrap();
        assert!(id > 0);

        let mut stmt = conn
            .prepare("SELECT file_id FROM verdicts WHERE file_hash = ?1")
            .unwrap();
        let fid: Option<i64> = stmt.query_row(["hash-mig"], |r| r.get(0)).unwrap();
        assert!(fid.is_some());
    }

    #[test]
    fn test_insert_and_get_external_report() {
        let conn = Connection::open_in_memory().unwrap();
        DatabaseSchema::init(&conn).unwrap();

        let provider = "mockapi";
        let identifier = "hash-123";
        let data_json = r#"{"status":"ok","count":1}"#;
        let ts = 12345;

        DatabaseQueries::insert_external_report(&conn, provider, identifier, data_json, ts)
            .unwrap();

        let read = DatabaseQueries::get_external_report(&conn, provider, identifier).unwrap();
        assert!(read.is_some());
        let r = read.unwrap();
        assert_eq!(r.provider, provider);
        assert_eq!(r.identifier, identifier);
        assert_eq!(r.data_json, data_json.to_string());

        let recent = DatabaseQueries::get_recent_external_reports(&conn, 10).unwrap();
        assert!(!recent.is_empty());
    }

    #[test]
    fn test_insert_and_get_threat_intel() {
        let conn = Connection::open_in_memory().unwrap();
        DatabaseSchema::init(&conn).unwrap();

        let hash = "threat-hash-1";
        let name = "Test Trojan";
        let severity = "CRITICAL";
        let family = Some("Trojan.Generic");
        let ts1 = 123456;
        let ts2 = 123457;

        let rec = crate::database::models::ThreatIntelRecord {
            file_hash: hash.to_string(),
            threat_name: name.to_string(),
            severity: severity.to_string(),
            family: family.map(|s| s.to_string()),
            first_seen: ts1,
            last_updated: ts2,
            source: "manual".to_string(),
        };
        DatabaseQueries::insert_threat_intel(&conn, &rec).unwrap();

        let got = DatabaseQueries::get_threat_by_hash(&conn, hash).unwrap();
        assert!(got.is_some());
        let t = got.unwrap();
        assert_eq!(t.file_hash, hash);
        assert_eq!(t.threat_name, name);
        assert_eq!(t.severity, severity);

        let recent = DatabaseQueries::get_recent_threats(&conn, 10).unwrap();
        assert!(!recent.is_empty());
    }

    #[test]
    fn test_quarantine_query_excludes_restored() {
        let conn = Connection::open_in_memory().unwrap();
        DatabaseSchema::init(&conn).unwrap();

        // Insert an active quarantine entry
        let active = QuarantineRecord {
            id: 0,
            file_hash: "active_hash".to_string(),
            original_path: "C:/test/active.exe".to_string(),
            quarantine_path: "vault/active.enc".to_string(),
            verdict: "malware".to_string(),
            threat_level: "HIGH".to_string(),
            reason: "test".to_string(),
            quarantined_at: 1000,
            restored_at: None,
            permanently_deleted: false,
            file_size: 1024,
            file_type: "exe".to_string(),
        };
        DatabaseQueries::insert_quarantine(&conn, &active).unwrap();

        // Insert a restored entry
        let mut restored = active.clone();
        restored.file_hash = "restored_hash".to_string();
        restored.original_path = "C:/test/restored.exe".to_string();
        restored.restored_at = Some(2000);
        DatabaseQueries::insert_quarantine(&conn, &restored).unwrap();

        // Insert a deleted entry
        let mut deleted = active.clone();
        deleted.file_hash = "deleted_hash".to_string();
        deleted.original_path = "C:/test/deleted.exe".to_string();
        deleted.permanently_deleted = true;
        DatabaseQueries::insert_quarantine(&conn, &deleted).unwrap();

        let results = DatabaseQueries::get_all_quarantined(&conn).unwrap();
        assert_eq!(
            results.len(),
            1,
            "Only active (non-restored, non-deleted) entries should appear"
        );
        assert_eq!(results[0].file_hash, "active_hash");
    }
}
