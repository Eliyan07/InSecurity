/// Database schema and migrations
use rusqlite::{params, Connection, Result};

pub struct DatabaseSchema;

impl DatabaseSchema {
    pub fn init(conn: &Connection) -> Result<()> {
        // Verdicts table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS verdicts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_hash TEXT NOT NULL,
                file_path TEXT NOT NULL,
                verdict TEXT NOT NULL,
                confidence REAL NOT NULL,
                threat_level TEXT NOT NULL,
                threat_name TEXT,
                scan_time_ms INTEGER NOT NULL,
                scanned_at INTEGER NOT NULL
            )",
            [],
        )?;

        // Reputation table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS reputation (
                id INTEGER PRIMARY KEY,
                file_hash TEXT NOT NULL UNIQUE,
                overall_score REAL NOT NULL,
                threat_count INTEGER NOT NULL,
                last_analysis_date INTEGER NOT NULL,
                sources TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            )",
            [],
        )?;

        // Scan history table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY,
                scan_path TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                total_files INTEGER NOT NULL,
                clean_files INTEGER NOT NULL,
                suspicious_files INTEGER NOT NULL,
                malicious_files INTEGER NOT NULL,
                scan_duration_seconds INTEGER NOT NULL,
                started_at INTEGER NOT NULL,
                completed_at INTEGER NOT NULL
            )",
            [],
        )?;

        // Quarantine table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS quarantine (
                id INTEGER PRIMARY KEY,
                file_hash TEXT NOT NULL,
                original_path TEXT NOT NULL,
                quarantine_path TEXT NOT NULL,
                verdict TEXT NOT NULL,
                threat_level TEXT NOT NULL,
                reason TEXT NOT NULL,
                quarantined_at INTEGER NOT NULL,
                restored_at INTEGER,
                permanently_deleted INTEGER DEFAULT 0,
                file_size INTEGER NOT NULL,
                file_type TEXT NOT NULL
            )",
            [],
        )?;

        // Cache table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS cache (
                id INTEGER PRIMARY KEY,
                file_hash TEXT NOT NULL UNIQUE,
                verdict TEXT NOT NULL,
                confidence REAL NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            )",
            [],
        )?;

        // Features table (store feature vectors as JSON strings so novelty detection
        // and model retraining can load example vectors)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS features (
                id INTEGER PRIMARY KEY,
                file_hash TEXT NOT NULL UNIQUE,
                features_json TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )",
            [],
        )?;

        // Canonical files table - central entity for all file-scoped data
        conn.execute(
            "CREATE TABLE IF NOT EXISTS files (
                    id INTEGER PRIMARY KEY,
                    file_hash TEXT NOT NULL UNIQUE,
                    canonical_path TEXT,
                    file_size INTEGER DEFAULT 0,
                    file_type TEXT,
                    first_seen INTEGER,
                    last_seen INTEGER
                )",
            [],
        )?;

        // External reports table - store raw JSON responses from online reputation providers
        conn.execute(
            "CREATE TABLE IF NOT EXISTS external_reports (
                id INTEGER PRIMARY KEY,
                provider TEXT NOT NULL,
                identifier TEXT NOT NULL,
                data_json TEXT NOT NULL,
                fetched_at INTEGER NOT NULL
            )",
            [],
        )?;

        // Threat intelligence table - known malicious hashes and meta
        conn.execute(
            "CREATE TABLE IF NOT EXISTS threat_intel (
                    id INTEGER PRIMARY KEY,
                    file_hash TEXT NOT NULL UNIQUE,
                    threat_name TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    family TEXT,
                    first_seen INTEGER NOT NULL,
                    last_updated INTEGER NOT NULL,
                    source TEXT NOT NULL
                )",
            [],
        )?;

        // Exclusions table - paths/patterns to exclude from scanning
        conn.execute(
            "CREATE TABLE IF NOT EXISTS exclusions (
                id INTEGER PRIMARY KEY,
                exclusion_type TEXT NOT NULL,
                pattern TEXT NOT NULL UNIQUE,
                reason TEXT,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )",
            [],
        )?;

        // App settings table - key/value store for various app settings
        conn.execute(
            "CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )",
            [],
        )?;

        // Link columns
        let _ = conn.execute("ALTER TABLE verdicts ADD COLUMN file_id INTEGER", []);
        let _ = conn.execute("ALTER TABLE features ADD COLUMN file_id INTEGER", []);
        let _ = conn.execute("ALTER TABLE quarantine ADD COLUMN file_id INTEGER", []);
        let _ = conn.execute(
            "ALTER TABLE external_reports ADD COLUMN file_id INTEGER",
            [],
        );
        let _ = conn.execute("ALTER TABLE threat_intel ADD COLUMN file_id INTEGER", []);
        let _ = conn.execute("ALTER TABLE reputation ADD COLUMN file_id INTEGER", []);
        // Verdict source tracking (realtime, manual, posture)
        let _ = conn.execute(
            "ALTER TABLE verdicts ADD COLUMN source TEXT NOT NULL DEFAULT 'realtime'",
            [],
        );

        // Create indexes for performance
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_verdicts_hash ON verdicts(file_hash)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_verdicts_scanned_at ON verdicts(scanned_at)",
            [],
        )?;

        conn.execute("CREATE INDEX IF NOT EXISTS idx_verdicts_scanned_desc ON verdicts(scanned_at DESC, file_hash, verdict)", [])?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_reputation_hash ON reputation(file_hash)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_quarantine_hash ON quarantine(file_hash)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_cache_expires_at ON cache(expires_at)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_features_hash ON features(file_hash)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_files_hash ON files(file_hash)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_verdicts_file_id ON verdicts(file_id)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_features_file_id ON features(file_id)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_external_reports_file_id ON external_reports(file_id)",
            [],
        )?;
        conn.execute("CREATE INDEX IF NOT EXISTS idx_external_reports_provider_id ON external_reports(provider, identifier)", [])?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scan_history_started_at ON scan_history(started_at)",
            [],
        )?;

        // Composite indexes for the "latest verdict per file" pattern used by
        // get_recent_verdicts, get_active_threats, and get_dashboard_stats.
        // Without these, the correlated sub-query `SELECT MAX(scanned_at) FROM verdicts WHERE file_path = ?`
        // performs a full table scan for every row.
        conn.execute("CREATE INDEX IF NOT EXISTS idx_verdicts_path_scanned ON verdicts(file_path, scanned_at DESC)", [])?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_verdicts_path_norm_scanned ON verdicts(LOWER(REPLACE(file_path, '/', '\\')), scanned_at DESC)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_verdicts_verdict ON verdicts(verdict)",
            [],
        )?;
        conn.execute("CREATE INDEX IF NOT EXISTS idx_quarantine_active ON quarantine(permanently_deleted, restored_at)", [])?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_quarantine_original_path_norm ON quarantine(LOWER(REPLACE(original_path, '/', '\\')), permanently_deleted, restored_at)",
            [],
        )?;

        Ok(())
    }
}

pub fn backfill_files_from_existing(conn: &Connection) -> Result<()> {
    let ts = chrono::Utc::now().timestamp();

    let tables = vec![
        "verdicts",
        "features",
        "reputation",
        "quarantine",
        "external_reports",
        "threat_intel",
    ];
    let allowed = [
        "verdicts",
        "features",
        "reputation",
        "quarantine",
        "external_reports",
        "threat_intel",
    ];
    for table in tables {
        if !allowed.contains(&table) {
            continue;
        }
        let sql = format!("SELECT DISTINCT file_hash FROM {}", table);
        if let Ok(mut stmt) = conn.prepare(&sql) {
            let mut rows = stmt.query([])?;
            while let Some(r) = rows.next()? {
                let hash: Option<String> = r.get(0).ok();
                if let Some(h) = hash {
                    if h.trim().is_empty() {
                        continue;
                    }
                    let _ = conn.execute("INSERT OR IGNORE INTO files (file_hash, first_seen, last_seen) VALUES (?1, ?2, ?2)", params![h, ts]);
                }
            }
        }
    }

    let _ = conn.execute("UPDATE verdicts SET file_id = (SELECT id FROM files WHERE files.file_hash = verdicts.file_hash) WHERE file_id IS NULL", []);
    let _ = conn.execute("UPDATE features SET file_id = (SELECT id FROM files WHERE files.file_hash = features.file_hash) WHERE file_id IS NULL", []);
    let _ = conn.execute("UPDATE reputation SET file_id = (SELECT id FROM files WHERE files.file_hash = reputation.file_hash) WHERE file_id IS NULL", []);
    let _ = conn.execute("UPDATE quarantine SET file_id = (SELECT id FROM files WHERE files.file_hash = quarantine.file_hash) WHERE file_id IS NULL", []);
    let _ = conn.execute("UPDATE external_reports SET file_id = (SELECT id FROM files WHERE files.file_hash = external_reports.identifier) WHERE file_id IS NULL", []);
    let _ = conn.execute("UPDATE threat_intel SET file_id = (SELECT id FROM files WHERE files.file_hash = threat_intel.file_hash) WHERE file_id IS NULL", []);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn in_memory_db() -> Connection {
        Connection::open_in_memory().unwrap()
    }

    // =========================================================================
    // Schema init tests
    // =========================================================================

    #[test]
    fn test_schema_init_creates_all_tables() {
        let conn = in_memory_db();
        DatabaseSchema::init(&conn).unwrap();

        let expected_tables = [
            "verdicts",
            "reputation",
            "scan_history",
            "quarantine",
            "cache",
            "features",
            "files",
            "external_reports",
            "threat_intel",
            "exclusions",
            "app_settings",
        ];

        for table in &expected_tables {
            let exists: bool = conn
                .query_row(
                    "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name=?1",
                    [table],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(exists, "Table '{}' should exist after init", table);
        }
    }

    #[test]
    fn test_schema_init_creates_indexes() {
        let conn = in_memory_db();
        DatabaseSchema::init(&conn).unwrap();

        let expected_indexes = [
            "idx_verdicts_hash",
            "idx_verdicts_scanned_at",
            "idx_reputation_hash",
            "idx_quarantine_hash",
            "idx_cache_expires_at",
            "idx_features_hash",
            "idx_files_hash",
            "idx_verdicts_file_id",
            "idx_features_file_id",
            "idx_external_reports_file_id",
            "idx_external_reports_provider_id",
            "idx_scan_history_started_at",
            "idx_verdicts_path_scanned",
            "idx_verdicts_path_norm_scanned",
            "idx_verdicts_verdict",
            "idx_quarantine_active",
            "idx_quarantine_original_path_norm",
        ];

        for idx in &expected_indexes {
            let exists: bool = conn
                .query_row(
                    "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='index' AND name=?1",
                    [idx],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(exists, "Index '{}' should exist after init", idx);
        }
    }

    #[test]
    fn test_schema_init_idempotent() {
        let conn = in_memory_db();
        // Call init twice - should not error
        DatabaseSchema::init(&conn).unwrap();
        DatabaseSchema::init(&conn).unwrap();
    }

    #[test]
    fn test_verdicts_table_has_source_column() {
        let conn = in_memory_db();
        DatabaseSchema::init(&conn).unwrap();

        // Insert a verdict with source column
        conn.execute(
            "INSERT INTO verdicts (file_hash, file_path, verdict, confidence, threat_level, scan_time_ms, scanned_at, source) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params!["abc", "/test", "Clean", 0.9, "LOW", 100, 1700000000i64, "manual"],
        ).unwrap();

        let source: String = conn
            .query_row(
                "SELECT source FROM verdicts WHERE file_hash = 'abc'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(source, "manual");
    }

    #[test]
    fn test_verdicts_source_default_value() {
        let conn = in_memory_db();
        DatabaseSchema::init(&conn).unwrap();

        // Insert without explicitly setting source - should use default 'realtime'
        conn.execute(
            "INSERT INTO verdicts (file_hash, file_path, verdict, confidence, threat_level, scan_time_ms, scanned_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params!["def", "/test2", "Malware", 0.99, "HIGH", 50, 1700000000i64],
        ).unwrap();

        let source: String = conn
            .query_row(
                "SELECT source FROM verdicts WHERE file_hash = 'def'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(source, "realtime");
    }

    #[test]
    fn test_verdicts_allow_same_hash_in_multiple_paths() {
        let conn = in_memory_db();
        DatabaseSchema::init(&conn).unwrap();

        conn.execute(
            "INSERT INTO verdicts (file_hash, file_path, verdict, confidence, threat_level, scan_time_ms, scanned_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params!["samehash", "C:\\one\\sample.exe", "Suspicious", 0.6, "MEDIUM", 10, 100i64],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO verdicts (file_hash, file_path, verdict, confidence, threat_level, scan_time_ms, scanned_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params!["samehash", "C:\\two\\sample.exe", "Suspicious", 0.7, "MEDIUM", 10, 101i64],
        )
        .unwrap();

        let count: u32 = conn
            .query_row(
                "SELECT COUNT(*) FROM verdicts WHERE file_hash = 'samehash'",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(count, 2);
    }

    #[test]
    fn test_files_table_structure() {
        let conn = in_memory_db();
        DatabaseSchema::init(&conn).unwrap();

        conn.execute(
            "INSERT INTO files (file_hash, canonical_path, file_size, file_type, first_seen, last_seen) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params!["hash1", "C:\\test.exe", 1024i64, "exe", 100i64, 200i64],
        ).unwrap();

        let (hash, path, size): (String, String, i64) = conn
            .query_row(
                "SELECT file_hash, canonical_path, file_size FROM files WHERE file_hash = 'hash1'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(hash, "hash1");
        assert_eq!(path, "C:\\test.exe");
        assert_eq!(size, 1024);
    }

    #[test]
    fn test_exclusions_unique_pattern() {
        let conn = in_memory_db();
        DatabaseSchema::init(&conn).unwrap();

        conn.execute(
            "INSERT INTO exclusions (exclusion_type, pattern, enabled, created_at, updated_at) VALUES ('path', 'C:\\test', 1, 0, 0)",
            [],
        ).unwrap();

        // Duplicate pattern should fail
        let result = conn.execute(
            "INSERT INTO exclusions (exclusion_type, pattern, enabled, created_at, updated_at) VALUES ('folder', 'C:\\test', 1, 0, 0)",
            [],
        );
        assert!(result.is_err());
    }

    // =========================================================================
    // Backfill tests
    // =========================================================================

    #[test]
    fn test_backfill_files_from_verdicts() {
        let conn = in_memory_db();
        DatabaseSchema::init(&conn).unwrap();

        // Insert some verdicts
        conn.execute(
            "INSERT INTO verdicts (file_hash, file_path, verdict, confidence, threat_level, scan_time_ms, scanned_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params!["hash_a", "/file_a", "Clean", 0.9, "LOW", 10, 100i64],
        ).unwrap();
        conn.execute(
            "INSERT INTO verdicts (file_hash, file_path, verdict, confidence, threat_level, scan_time_ms, scanned_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params!["hash_b", "/file_b", "Malware", 0.99, "HIGH", 20, 200i64],
        ).unwrap();

        backfill_files_from_existing(&conn).unwrap();

        // Check files table was populated
        let count: u32 = conn
            .query_row("SELECT COUNT(*) FROM files", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 2);

        // Check file_id was linked back to verdicts
        let linked: u32 = conn
            .query_row(
                "SELECT COUNT(*) FROM verdicts WHERE file_id IS NOT NULL",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(linked, 2);
    }

    #[test]
    fn test_backfill_skips_empty_hashes() {
        let conn = in_memory_db();
        DatabaseSchema::init(&conn).unwrap();

        // Insert a verdict with empty hash
        conn.execute(
            "INSERT INTO verdicts (file_hash, file_path, verdict, confidence, threat_level, scan_time_ms, scanned_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params!["", "/empty", "Clean", 0.5, "LOW", 5, 50i64],
        ).unwrap();
        conn.execute(
            "INSERT INTO verdicts (file_hash, file_path, verdict, confidence, threat_level, scan_time_ms, scanned_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params!["valid_hash", "/valid", "Clean", 0.9, "LOW", 10, 100i64],
        ).unwrap();

        backfill_files_from_existing(&conn).unwrap();

        let count: u32 = conn
            .query_row("SELECT COUNT(*) FROM files", [], |row| row.get(0))
            .unwrap();
        // Only the valid hash should be inserted
        assert_eq!(count, 1);
    }

    #[test]
    fn test_backfill_idempotent() {
        let conn = in_memory_db();
        DatabaseSchema::init(&conn).unwrap();

        conn.execute(
            "INSERT INTO verdicts (file_hash, file_path, verdict, confidence, threat_level, scan_time_ms, scanned_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params!["hash_x", "/x", "Clean", 0.8, "LOW", 10, 100i64],
        ).unwrap();

        // Run backfill twice
        backfill_files_from_existing(&conn).unwrap();
        backfill_files_from_existing(&conn).unwrap();

        let count: u32 = conn
            .query_row("SELECT COUNT(*) FROM files", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1); // INSERT OR IGNORE prevents duplicates
    }

    #[test]
    fn test_backfill_multiple_tables() {
        let conn = in_memory_db();
        DatabaseSchema::init(&conn).unwrap();

        conn.execute(
            "INSERT INTO verdicts (file_hash, file_path, verdict, confidence, threat_level, scan_time_ms, scanned_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params!["shared_hash", "/v", "Clean", 0.9, "LOW", 10, 100i64],
        ).unwrap();
        conn.execute(
            "INSERT INTO features (file_hash, features_json, created_at) VALUES (?1, ?2, ?3)",
            params!["shared_hash", "[]", 100i64],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO threat_intel (file_hash, threat_name, severity, first_seen, last_updated, source) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params!["unique_to_intel", "Test", "HIGH", 50i64, 100i64, "src"],
        ).unwrap();

        backfill_files_from_existing(&conn).unwrap();

        let count: u32 = conn
            .query_row("SELECT COUNT(*) FROM files", [], |row| row.get(0))
            .unwrap();
        // shared_hash (deduped across verdicts+features) + unique_to_intel = 2
        assert_eq!(count, 2);
    }
}
