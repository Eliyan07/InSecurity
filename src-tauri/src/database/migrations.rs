use chrono::Utc;
/// Database Migrations Framework
use rusqlite::{params, Connection, Result};

pub trait Migration: Sync {
    /// Migration version number (must be unique and sequential)
    fn version(&self) -> u32;

    fn name(&self) -> &'static str;

    /// Apply the migration (schema changes, data transformations)
    fn up(&self, conn: &Connection) -> Result<()>;

    /// Rollback the migration (must reverse up() exactly)
    fn down(&self, conn: &Connection) -> Result<()>;
}

/// Migrator manages database schema versioning
pub struct Migrator<'a> {
    conn: &'a Connection,
}

impl<'a> Migrator<'a> {
    pub fn new(conn: &'a Connection) -> Self {
        Migrator { conn }
    }

    pub fn init(&self) -> Result<()> {
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS _migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at INTEGER NOT NULL
            )",
            [],
        )?;
        Ok(())
    }

    pub fn current_version(&self) -> Result<u32> {
        self.init()?;

        let version: Result<u32> = self.conn.query_row(
            "SELECT COALESCE(MAX(version), 0) FROM _migrations",
            [],
            |row| row.get(0),
        );

        version.or(Ok(0))
    }

    pub fn applied_migrations(&self) -> Result<Vec<(u32, String, i64)>> {
        self.init()?;

        let mut stmt = self
            .conn
            .prepare("SELECT version, name, applied_at FROM _migrations ORDER BY version")?;

        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;

        rows.collect()
    }

    pub fn migrate_to_latest(&self) -> Result<u32> {
        let current = self.current_version()?;
        let migrations = get_all_migrations();
        let mut applied = 0;

        for migration in migrations {
            if migration.version() > current {
                log::info!(
                    "Applying migration {}: {}",
                    migration.version(),
                    migration.name()
                );

                let tx = self.conn.unchecked_transaction()?;
                migration.up(self.conn)?;

                self.conn.execute(
                    "INSERT INTO _migrations (version, name, applied_at) VALUES (?1, ?2, ?3)",
                    params![
                        migration.version(),
                        migration.name(),
                        Utc::now().timestamp()
                    ],
                )?;

                tx.commit()?;
                applied += 1;

                log::info!("Migration {} applied successfully", migration.version());
            }
        }

        if applied == 0 {
            log::info!("Database is up to date (version {})", current);
        } else {
            log::info!("Applied {} migration(s)", applied);
        }

        Ok(applied)
    }

    pub fn migrate_to(&self, target_version: u32) -> Result<()> {
        let current = self.current_version()?;

        if target_version == current {
            log::info!("Already at version {}", current);
            return Ok(());
        }

        let migrations = get_all_migrations();

        if target_version > current {
            for migration in migrations {
                if migration.version() > current && migration.version() <= target_version {
                    log::info!(
                        "Applying migration {}: {}",
                        migration.version(),
                        migration.name()
                    );

                    let tx = self.conn.unchecked_transaction()?;
                    migration.up(self.conn)?;

                    self.conn.execute(
                        "INSERT INTO _migrations (version, name, applied_at) VALUES (?1, ?2, ?3)",
                        params![
                            migration.version(),
                            migration.name(),
                            Utc::now().timestamp()
                        ],
                    )?;

                    tx.commit()?;
                }
            }
        } else {
            let mut to_rollback: Vec<&dyn Migration> = migrations
                .iter()
                .filter(|m| m.version() > target_version && m.version() <= current)
                .copied()
                .collect();

            to_rollback.sort_by_key(|b| std::cmp::Reverse(b.version()));

            for migration in to_rollback {
                log::info!(
                    "Rolling back migration {}: {}",
                    migration.version(),
                    migration.name()
                );

                let tx = self.conn.unchecked_transaction()?;
                migration.down(self.conn)?;

                self.conn.execute(
                    "DELETE FROM _migrations WHERE version = ?1",
                    params![migration.version()],
                )?;

                tx.commit()?;
            }
        }

        Ok(())
    }

    pub fn rollback(&self) -> Result<bool> {
        let current = self.current_version()?;

        if current == 0 {
            log::info!("No migrations to rollback");
            return Ok(false);
        }

        let migrations = get_all_migrations();

        if let Some(migration) = migrations.iter().find(|m| m.version() == current) {
            log::info!(
                "Rolling back migration {}: {}",
                migration.version(),
                migration.name()
            );

            let tx = self.conn.unchecked_transaction()?;
            migration.down(self.conn)?;

            self.conn.execute(
                "DELETE FROM _migrations WHERE version = ?1",
                params![migration.version()],
            )?;

            tx.commit()?;

            log::info!("Rollback complete");
            return Ok(true);
        }

        Ok(false)
    }

    pub fn reset(&self) -> Result<()> {
        self.migrate_to(0)
    }
}
/// Migration 1: Initial schema with core tables
struct Migration001InitialSchema;

impl Migration for Migration001InitialSchema {
    fn version(&self) -> u32 {
        1
    }
    fn name(&self) -> &'static str {
        "initial_schema"
    }

    fn up(&self, conn: &Connection) -> Result<()> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS verdicts (
                id INTEGER PRIMARY KEY,
                file_hash TEXT NOT NULL UNIQUE,
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

        conn.execute(
            "CREATE TABLE IF NOT EXISTS features (
                id INTEGER PRIMARY KEY,
                file_hash TEXT NOT NULL UNIQUE,
                features_json TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_verdicts_hash ON verdicts(file_hash)",
            [],
        )?;
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

        Ok(())
    }

    fn down(&self, conn: &Connection) -> Result<()> {
        conn.execute("DROP TABLE IF EXISTS verdicts", [])?;
        conn.execute("DROP TABLE IF EXISTS reputation", [])?;
        conn.execute("DROP TABLE IF EXISTS scan_history", [])?;
        conn.execute("DROP TABLE IF EXISTS quarantine", [])?;
        conn.execute("DROP TABLE IF EXISTS cache", [])?;
        conn.execute("DROP TABLE IF EXISTS features", [])?;
        Ok(())
    }
}

/// Migration 2: Add files table and foreign key relationships
struct Migration002AddFilesTable;

impl Migration for Migration002AddFilesTable {
    fn version(&self) -> u32 {
        2
    }
    fn name(&self) -> &'static str {
        "add_files_table"
    }

    fn up(&self, conn: &Connection) -> Result<()> {
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

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_files_hash ON files(file_hash)",
            [],
        )?;

        let _ = conn.execute("ALTER TABLE verdicts ADD COLUMN file_id INTEGER", []);
        let _ = conn.execute("ALTER TABLE features ADD COLUMN file_id INTEGER", []);
        let _ = conn.execute("ALTER TABLE quarantine ADD COLUMN file_id INTEGER", []);
        let _ = conn.execute("ALTER TABLE reputation ADD COLUMN file_id INTEGER", []);

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_verdicts_file_id ON verdicts(file_id)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_features_file_id ON features(file_id)",
            [],
        )?;

        Ok(())
    }

    fn down(&self, conn: &Connection) -> Result<()> {
        conn.execute("DROP TABLE IF EXISTS files", [])?;
        Ok(())
    }
}

/// Migration 3: Add threat intelligence and external reports
struct Migration003AddThreatIntel;

impl Migration for Migration003AddThreatIntel {
    fn version(&self) -> u32 {
        3
    }
    fn name(&self) -> &'static str {
        "add_threat_intel"
    }

    fn up(&self, conn: &Connection) -> Result<()> {
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

        let _ = conn.execute("ALTER TABLE threat_intel ADD COLUMN file_id INTEGER", []);
        let _ = conn.execute(
            "ALTER TABLE external_reports ADD COLUMN file_id INTEGER",
            [],
        );

        conn.execute("CREATE INDEX IF NOT EXISTS idx_external_reports_provider_id ON external_reports(provider, identifier)", [])?;

        Ok(())
    }

    fn down(&self, conn: &Connection) -> Result<()> {
        conn.execute("DROP TABLE IF EXISTS threat_intel", [])?;
        conn.execute("DROP TABLE IF EXISTS external_reports", [])?;
        Ok(())
    }
}

/// Migration 4: Add scheduled scans
struct Migration004AddScheduling;

impl Migration for Migration004AddScheduling {
    fn version(&self) -> u32 {
        4
    }
    fn name(&self) -> &'static str {
        "add_scheduling"
    }

    fn up(&self, conn: &Connection) -> Result<()> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS scheduled_scans (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                scan_type TEXT NOT NULL,
                frequency TEXT NOT NULL,
                hour INTEGER NOT NULL DEFAULT 2,
                minute INTEGER NOT NULL DEFAULT 0,
                day_of_week INTEGER,
                day_of_month INTEGER,
                paths TEXT,
                last_run INTEGER,
                next_run INTEGER,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )",
            [],
        )?;

        Ok(())
    }

    fn down(&self, conn: &Connection) -> Result<()> {
        conn.execute("DROP TABLE IF EXISTS scheduled_scans", [])?;
        Ok(())
    }
}

/// Migration 5: Add exclusions and app settings
struct Migration005AddExclusionsAndSettings;

impl Migration for Migration005AddExclusionsAndSettings {
    fn version(&self) -> u32 {
        5
    }
    fn name(&self) -> &'static str {
        "add_exclusions_and_settings"
    }

    fn up(&self, conn: &Connection) -> Result<()> {
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

        conn.execute(
            "CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )",
            [],
        )?;

        Ok(())
    }

    fn down(&self, conn: &Connection) -> Result<()> {
        conn.execute("DROP TABLE IF EXISTS exclusions", [])?;
        conn.execute("DROP TABLE IF EXISTS app_settings", [])?;
        Ok(())
    }
}

/// Migration 6: Add performance indexes
struct Migration006AddPerformanceIndexes;

impl Migration for Migration006AddPerformanceIndexes {
    fn version(&self) -> u32 {
        6
    }
    fn name(&self) -> &'static str {
        "add_performance_indexes"
    }

    fn up(&self, conn: &Connection) -> Result<()> {
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_verdicts_scanned_at ON verdicts(scanned_at)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_verdicts_scanned_desc ON verdicts(scanned_at DESC, file_hash, verdict)", 
            []
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_features_hash ON features(file_hash)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scan_history_started_at ON scan_history(started_at)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_external_reports_file_id ON external_reports(file_id)",
            [],
        )?;

        Ok(())
    }

    fn down(&self, conn: &Connection) -> Result<()> {
        conn.execute("DROP INDEX IF EXISTS idx_verdicts_scanned_at", [])?;
        conn.execute("DROP INDEX IF EXISTS idx_verdicts_scanned_desc", [])?;
        conn.execute("DROP INDEX IF EXISTS idx_features_hash", [])?;
        conn.execute("DROP INDEX IF EXISTS idx_scan_history_started_at", [])?;
        conn.execute("DROP INDEX IF EXISTS idx_external_reports_file_id", [])?;
        Ok(())
    }
}

/// Migration 7: Update scheduled_scans table with additional columns and fix schema
struct Migration007UpdateScheduledScans;

impl Migration for Migration007UpdateScheduledScans {
    fn version(&self) -> u32 {
        7
    }
    fn name(&self) -> &'static str {
        "update_scheduled_scans"
    }

    fn up(&self, conn: &Connection) -> Result<()> {
        // The original scheduled_scans table had TEXT id and hour/minute columns
        // We need to recreate it with proper INTEGER id and time_of_day column

        // First, check if we need to migrate (does old table exist with TEXT id?)
        let has_old_schema: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM pragma_table_info('scheduled_scans') WHERE name = 'hour'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(false);

        if has_old_schema {
            // Backup existing data
            let _ = conn.execute(
                "ALTER TABLE scheduled_scans RENAME TO scheduled_scans_old",
                [],
            );

            // Create new table with correct schema
            conn.execute(
                "CREATE TABLE scheduled_scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    scan_type TEXT NOT NULL,
                    custom_path TEXT,
                    frequency TEXT NOT NULL,
                    time_of_day TEXT NOT NULL DEFAULT '09:00',
                    day_of_week INTEGER,
                    day_of_month INTEGER,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    last_run INTEGER,
                    next_run INTEGER NOT NULL,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                )",
                [],
            )?;

            // Migrate data from old table
            let _ = conn.execute(
                "INSERT INTO scheduled_scans (name, scan_type, custom_path, frequency, time_of_day, day_of_week, day_of_month, enabled, last_run, next_run, created_at, updated_at)
                 SELECT name, scan_type, paths, frequency, printf('%02d:%02d', hour, minute), day_of_week, day_of_month, enabled, last_run, COALESCE(next_run, 0), created_at, updated_at
                 FROM scheduled_scans_old",
                []
            );

            // Drop old table
            let _ = conn.execute("DROP TABLE IF EXISTS scheduled_scans_old", []);
        } else {
            // Just add the missing columns if they don't exist
            let _ = conn.execute(
                "ALTER TABLE scheduled_scans ADD COLUMN custom_path TEXT",
                [],
            );
            let _ = conn.execute(
                "ALTER TABLE scheduled_scans ADD COLUMN time_of_day TEXT DEFAULT '09:00'",
                [],
            );
        }

        Ok(())
    }

    fn down(&self, _conn: &Connection) -> Result<()> {
        // Can't easily rollback schema changes in SQLite
        Ok(())
    }
}

/// Migration 8: Add tamper protection columns
/// Adds signature column to exclusions for tamper evidence
struct Migration008AddTamperProtection;

impl Migration for Migration008AddTamperProtection {
    fn version(&self) -> u32 {
        8
    }
    fn name(&self) -> &'static str {
        "add_tamper_protection"
    }

    fn up(&self, conn: &Connection) -> Result<()> {
        // Add signature column to exclusions table for tamper protection
        // Signature is computed as HMAC-SHA256 of (exclusion_type|pattern|reason|created_at)
        let _ = conn.execute("ALTER TABLE exclusions ADD COLUMN signature TEXT", []);

        // Create audit_events table for fast queries (journal is append-only file)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                details TEXT,
                file_path TEXT,
                file_hash TEXT,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
            )",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp DESC)",
            [],
        )?;

        Ok(())
    }

    fn down(&self, conn: &Connection) -> Result<()> {
        // Can't easily drop columns in SQLite, just drop the audit table
        conn.execute("DROP TABLE IF EXISTS audit_events", [])?;
        Ok(())
    }
}

/// Migration 9: Add targeted performance indexes for Insights & Quarantine queries
///
/// The existing idx_verdicts_scanned_desc covers (scanned_at DESC, file_hash, verdict)
/// but the hot path in get_recent_verdicts uses a correlated GROUP BY on file_path
/// which requires a covering index on (file_path, scanned_at DESC).
/// Similarly, quarantine listing filters on (permanently_deleted, restored_at) and
/// dashboard stats filter on verdict - both benefit from dedicated indexes.
struct Migration009AddQueryOptimizationIndexes;

impl Migration for Migration009AddQueryOptimizationIndexes {
    fn version(&self) -> u32 {
        9
    }
    fn name(&self) -> &'static str {
        "add_query_optimization_indexes"
    }

    fn up(&self, conn: &Connection) -> Result<()> {
        // Covers the correlated subquery in get_recent_verdicts:
        //   SELECT file_path, MAX(scanned_at) FROM verdicts GROUP BY file_path
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_verdicts_path_scanned ON verdicts(file_path, scanned_at DESC)",
            [],
        )?;
        // Dashboard stats filter by verdict value (e.g. WHERE verdict = 'malware')
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_verdicts_verdict ON verdicts(verdict)",
            [],
        )?;
        // Quarantine listing: WHERE permanently_deleted = 0 AND restored_at IS NULL
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_quarantine_active ON quarantine(permanently_deleted, restored_at)",
            [],
        )?;
        Ok(())
    }

    fn down(&self, conn: &Connection) -> Result<()> {
        conn.execute("DROP INDEX IF EXISTS idx_verdicts_path_scanned", [])?;
        conn.execute("DROP INDEX IF EXISTS idx_verdicts_verdict", [])?;
        conn.execute("DROP INDEX IF EXISTS idx_quarantine_active", [])?;
        Ok(())
    }
}

/// Migration 10: Add `source` column to verdicts table.
/// Tracks where each verdict originated: "realtime", "manual", or "posture".
/// Defaults to "realtime" so all existing rows are correctly attributed.
/// Dashboard queries filter on this column to exclude manual scan results.
struct Migration010AddVerdictSource;

impl Migration for Migration010AddVerdictSource {
    fn version(&self) -> u32 {
        10
    }
    fn name(&self) -> &'static str {
        "add_verdict_source"
    }

    fn up(&self, conn: &Connection) -> Result<()> {
        conn.execute(
            "ALTER TABLE verdicts ADD COLUMN source TEXT NOT NULL DEFAULT 'realtime'",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_verdicts_source ON verdicts(source)",
            [],
        )?;
        Ok(())
    }

    fn down(&self, conn: &Connection) -> Result<()> {
        conn.execute("DROP INDEX IF EXISTS idx_verdicts_source", [])?;
        // SQLite doesn't support DROP COLUMN before 3.35.0; the column
        // is harmless if left in place after rollback.
        Ok(())
    }
}

/// Migration 11: Add user_whitelist table for tracking user-ignored files
/// When users click "Ignore" on a detected threat, the hash is stored here
/// so they can review and undo their whitelist decisions from Settings.
struct Migration011UserWhitelist;

impl Migration for Migration011UserWhitelist {
    fn version(&self) -> u32 {
        11
    }
    fn name(&self) -> &'static str {
        "add_user_whitelist"
    }

    fn up(&self, conn: &Connection) -> Result<()> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS user_whitelist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_hash TEXT NOT NULL UNIQUE,
                file_path TEXT,
                original_verdict TEXT,
                created_at INTEGER NOT NULL
            )",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_user_whitelist_hash ON user_whitelist(file_hash)",
            [],
        )?;
        Ok(())
    }

    fn down(&self, conn: &Connection) -> Result<()> {
        conn.execute("DROP TABLE IF EXISTS user_whitelist", [])?;
        Ok(())
    }
}

// =========================================================================
// Migration 012 – Network Security tables
// =========================================================================

struct Migration012NetworkSecurity;

impl Migration for Migration012NetworkSecurity {
    fn version(&self) -> u32 {
        12
    }
    fn name(&self) -> &'static str {
        "add_network_security"
    }

    fn up(&self, conn: &Connection) -> Result<()> {
        conn.execute_batch("

            CREATE TABLE IF NOT EXISTS network_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pid INTEGER NOT NULL,
                process_name TEXT NOT NULL,
                process_path TEXT,
                remote_ip TEXT NOT NULL,
                remote_port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                event_type TEXT NOT NULL,
                reason TEXT,
                created_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_network_events_created ON network_events(created_at DESC);

            CREATE TABLE IF NOT EXISTS firewall_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_name TEXT NOT NULL UNIQUE,
                executable_path TEXT NOT NULL,
                direction TEXT NOT NULL DEFAULT 'out',
                action TEXT NOT NULL DEFAULT 'block',
                reason TEXT,
                auto_created INTEGER NOT NULL DEFAULT 0,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS malicious_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL UNIQUE,
                threat_name TEXT,
                source TEXT NOT NULL DEFAULT 'default',
                added_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_malicious_ips_addr ON malicious_ips(ip_address);

            CREATE TABLE IF NOT EXISTS network_threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pid INTEGER NOT NULL,
                process_name TEXT NOT NULL,
                process_path TEXT,
                remote_ip TEXT NOT NULL,
                remote_port INTEGER NOT NULL,
                threat_name TEXT NOT NULL,
                protocol TEXT NOT NULL DEFAULT 'TCP',
                detected_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_network_threats_detected ON network_threats(detected_at DESC);
        ")?;
        Ok(())
    }

    fn down(&self, conn: &Connection) -> Result<()> {
        conn.execute_batch(
            "
            
            DROP TABLE IF EXISTS network_events;
            DROP TABLE IF EXISTS firewall_rules;
            DROP TABLE IF EXISTS malicious_ips;
            DROP TABLE IF EXISTS network_threats;
        ",
        )?;
        Ok(())
    }
}

fn get_all_migrations() -> Vec<&'static dyn Migration> {
    vec![
        &Migration001InitialSchema,
        &Migration002AddFilesTable,
        &Migration003AddThreatIntel,
        &Migration004AddScheduling,
        &Migration005AddExclusionsAndSettings,
        &Migration006AddPerformanceIndexes,
        &Migration007UpdateScheduledScans,
        &Migration008AddTamperProtection,
        &Migration009AddQueryOptimizationIndexes,
        &Migration010AddVerdictSource,
        &Migration011UserWhitelist,
        &Migration012NetworkSecurity,
    ]
}

pub fn latest_version() -> u32 {
    get_all_migrations()
        .last()
        .map(|m| m.version())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_db() -> Connection {
        Connection::open_in_memory().unwrap()
    }

    #[test]
    fn test_migrator_init() {
        let conn = create_test_db();
        let migrator = Migrator::new(&conn);

        migrator.init().unwrap();

        // Check migrations table exists
        let count: i32 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='_migrations'",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(count, 1);
    }

    #[test]
    fn test_current_version_empty() {
        let conn = create_test_db();
        let migrator = Migrator::new(&conn);

        let version = migrator.current_version().unwrap();
        assert_eq!(version, 0);
    }

    #[test]
    fn test_migrate_to_latest() {
        let conn = create_test_db();
        let migrator = Migrator::new(&conn);

        let applied = migrator.migrate_to_latest().unwrap();
        assert!(applied > 0);

        let version = migrator.current_version().unwrap();
        assert_eq!(version, latest_version());
    }

    #[test]
    fn test_migrate_idempotent() {
        let conn = create_test_db();
        let migrator = Migrator::new(&conn);

        // Run twice
        migrator.migrate_to_latest().unwrap();
        let applied_second = migrator.migrate_to_latest().unwrap();

        // Second run should apply 0 migrations
        assert_eq!(applied_second, 0);
    }

    #[test]
    fn test_rollback() {
        let conn = create_test_db();
        let migrator = Migrator::new(&conn);

        migrator.migrate_to_latest().unwrap();
        let version_before = migrator.current_version().unwrap();

        let rolled_back = migrator.rollback().unwrap();
        assert!(rolled_back);

        let version_after = migrator.current_version().unwrap();
        assert_eq!(version_after, version_before - 1);
    }

    #[test]
    fn test_migrate_to_specific_version() {
        let conn = create_test_db();
        let migrator = Migrator::new(&conn);

        // Migrate to version 3
        migrator.migrate_to(3).unwrap();
        assert_eq!(migrator.current_version().unwrap(), 3);

        // Migrate up to version 5
        migrator.migrate_to(5).unwrap();
        assert_eq!(migrator.current_version().unwrap(), 5);

        // Migrate down to version 2
        migrator.migrate_to(2).unwrap();
        assert_eq!(migrator.current_version().unwrap(), 2);
    }

    #[test]
    fn test_applied_migrations() {
        let conn = create_test_db();
        let migrator = Migrator::new(&conn);

        migrator.migrate_to(3).unwrap();

        let applied = migrator.applied_migrations().unwrap();
        assert_eq!(applied.len(), 3);
        assert_eq!(applied[0].0, 1); // version
        assert_eq!(applied[1].0, 2);
        assert_eq!(applied[2].0, 3);
    }

    #[test]
    fn test_reset() {
        let conn = create_test_db();
        let migrator = Migrator::new(&conn);

        migrator.migrate_to_latest().unwrap();
        migrator.reset().unwrap();

        assert_eq!(migrator.current_version().unwrap(), 0);
    }

    #[test]
    fn test_migration_creates_tables() {
        let conn = create_test_db();
        let migrator = Migrator::new(&conn);

        migrator.migrate_to_latest().unwrap();

        // Check that expected tables exist
        let tables = vec![
            "verdicts",
            "reputation",
            "scan_history",
            "quarantine",
            "cache",
            "features",
            "files",
            "threat_intel",
            "external_reports",
            "scheduled_scans",
            "exclusions",
            "app_settings",
            "user_whitelist",
            "network_events",
            "firewall_rules",
            "malicious_ips",
        ];

        for table in tables {
            let exists: i32 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                    params![table],
                    |row| row.get(0),
                )
                .unwrap();

            assert_eq!(exists, 1, "Table {} should exist", table);
        }
    }

    #[test]
    fn test_latest_version() {
        assert!(latest_version() >= 6);
    }
}
