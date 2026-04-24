use chrono::Utc;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

const FEEDBACK_TABLE_SCHEMA: &str = r#"
    CREATE TABLE IF NOT EXISTS feedback (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_hash TEXT NOT NULL,
        feedback_type TEXT NOT NULL,
        original_verdict TEXT,
        original_confidence REAL,
        user_correction TEXT,
        features_json TEXT,
        source TEXT NOT NULL,
        timestamp INTEGER NOT NULL,
        metadata_json TEXT,
        processed INTEGER DEFAULT 0,
        UNIQUE(file_hash, feedback_type, source)
    );
    CREATE INDEX IF NOT EXISTS idx_feedback_type
    ON feedback(feedback_type);
    CREATE INDEX IF NOT EXISTS idx_feedback_processed
    ON feedback(processed);
"#;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FeedbackStats {
    pub by_type: HashMap<String, i64>,
    pub by_source: HashMap<String, i64>,
    pub last_7_days: HashMap<String, i64>,
    pub unprocessed: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ThresholdRecommendation {
    pub adjustment: f64,
    pub reason: String,
    pub fp_count: Option<i64>,
    pub fn_count: Option<i64>,
    pub fp_ratio: Option<f64>,
}

pub struct FeedbackStore {
    db_path: PathBuf,
}

impl FeedbackStore {
    pub fn new() -> Result<Self, String> {
        Self::with_db_path(Self::default_db_path()?)
    }

    pub fn with_db_path(db_path: PathBuf) -> Result<Self, String> {
        let store = Self { db_path };
        store.initialize()?;
        Ok(store)
    }

    pub fn report_false_positive(
        &self,
        file_hash: &str,
        original_verdict: &str,
        confidence: f64,
        features_json: Option<&str>,
    ) -> Result<bool, String> {
        self.insert_feedback(
            file_hash,
            "false_positive",
            original_verdict,
            confidence,
            Some("clean"),
            features_json,
            "user",
            Utc::now().timestamp(),
            None,
        )
    }

    pub fn report_false_negative(
        &self,
        file_hash: &str,
        original_verdict: &str,
        confidence: f64,
        actual_threat: &str,
        features_json: Option<&str>,
    ) -> Result<bool, String> {
        let metadata_json = serde_json::json!({ "actual_threat": actual_threat }).to_string();
        self.insert_feedback(
            file_hash,
            "false_negative",
            original_verdict,
            confidence,
            Some(actual_threat),
            features_json,
            "user",
            Utc::now().timestamp(),
            Some(metadata_json),
        )
    }

    pub fn get_feedback_stats(&self) -> Result<FeedbackStats, String> {
        let conn = self.open_connection()?;
        let by_type = Self::load_count_map(
            &conn,
            "SELECT feedback_type, COUNT(*) FROM feedback GROUP BY feedback_type",
            params![],
        )?;
        let by_source = Self::load_count_map(
            &conn,
            "SELECT source, COUNT(*) FROM feedback GROUP BY source",
            params![],
        )?;
        let week_ago = Utc::now().timestamp() - (7 * 24 * 3600);
        let last_7_days = Self::load_count_map(
            &conn,
            "SELECT feedback_type, COUNT(*) FROM feedback WHERE timestamp > ? GROUP BY feedback_type",
            params![week_ago],
        )?;
        let unprocessed = conn
            .query_row(
                "SELECT COUNT(*) FROM feedback WHERE processed = 0",
                params![],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|e| format!("Failed to query unprocessed feedback count: {e}"))?;

        Ok(FeedbackStats {
            by_type,
            by_source,
            last_7_days,
            unprocessed,
        })
    }

    pub fn should_retrain(&self) -> Result<bool, String> {
        Ok(self.get_feedback_stats()?.unprocessed >= 100)
    }

    pub fn get_threshold_recommendation(&self) -> Result<ThresholdRecommendation, String> {
        let stats = self.get_feedback_stats()?;
        let fp_count = *stats.last_7_days.get("false_positive").unwrap_or(&0);
        let fn_count = *stats.last_7_days.get("false_negative").unwrap_or(&0);
        let total = fp_count + fn_count;

        if total < 10 {
            return Ok(ThresholdRecommendation {
                adjustment: 0.0,
                reason: "insufficient_data".to_string(),
                fp_count: None,
                fn_count: None,
                fp_ratio: None,
            });
        }

        let fp_ratio = fp_count as f64 / total as f64;
        let fn_ratio = fn_count as f64 / total as f64;
        let (adjustment, reason) = if fp_ratio > 0.7 {
            (
                (fp_ratio - 0.5).min(0.1),
                "high_false_positive_rate".to_string(),
            )
        } else if fn_ratio > 0.7 {
            (
                -((fn_ratio - 0.5).min(0.1)),
                "high_false_negative_rate".to_string(),
            )
        } else {
            (0.0, "balanced".to_string())
        };

        Ok(ThresholdRecommendation {
            adjustment,
            reason,
            fp_count: Some(fp_count),
            fn_count: Some(fn_count),
            fp_ratio: Some(fp_ratio),
        })
    }

    fn default_db_path() -> Result<PathBuf, String> {
        let home_dir = dirs::home_dir().ok_or("Failed to locate the user's home directory")?;
        Ok(home_dir
            .join(".insecurity")
            .join("ml_feedback")
            .join("feedback.db"))
    }

    fn initialize(&self) -> Result<(), String> {
        let _ = self.open_connection()?;
        Ok(())
    }

    fn open_connection(&self) -> Result<Connection, String> {
        self.ensure_parent_dir()?;
        let conn = Connection::open(&self.db_path).map_err(|e| {
            format!(
                "Failed to open feedback database at {}: {e}",
                self.db_path.display()
            )
        })?;
        conn.execute_batch(FEEDBACK_TABLE_SCHEMA)
            .map_err(|e| format!("Failed to initialize feedback schema: {e}"))?;
        Ok(conn)
    }

    fn ensure_parent_dir(&self) -> Result<(), String> {
        let Some(parent) = self.db_path.parent() else {
            return Err(format!(
                "Feedback database path has no parent directory: {}",
                self.db_path.display()
            ));
        };
        fs::create_dir_all(parent).map_err(|e| {
            format!(
                "Failed to create feedback database directory {}: {e}",
                parent.display()
            )
        })
    }

    fn insert_feedback(
        &self,
        file_hash: &str,
        feedback_type: &str,
        original_verdict: &str,
        confidence: f64,
        user_correction: Option<&str>,
        features_json: Option<&str>,
        source: &str,
        timestamp: i64,
        metadata_json: Option<String>,
    ) -> Result<bool, String> {
        let conn = self.open_connection()?;
        conn.execute(
            r#"
                INSERT OR REPLACE INTO feedback
                    (file_hash, feedback_type, original_verdict, original_confidence,
                     user_correction, features_json, source, timestamp, metadata_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
            params![
                file_hash,
                feedback_type,
                original_verdict,
                confidence,
                user_correction,
                features_json,
                source,
                timestamp,
                metadata_json
            ],
        )
        .map_err(|e| format!("Failed to persist feedback: {e}"))?;

        Ok(true)
    }

    fn load_count_map<P>(
        conn: &Connection,
        sql: &str,
        params: P,
    ) -> Result<HashMap<String, i64>, String>
    where
        P: rusqlite::Params,
    {
        let mut stmt = conn
            .prepare(sql)
            .map_err(|e| format!("Failed to prepare feedback stats query: {e}"))?;
        let rows = stmt
            .query_map(params, |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })
            .map_err(|e| format!("Failed to execute feedback stats query: {e}"))?;

        let mut map = HashMap::new();
        for row in rows {
            let (key, value) =
                row.map_err(|e| format!("Failed to read feedback stats row: {e}"))?;
            map.insert(key, value);
        }

        Ok(map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use tempfile::tempdir;

    fn test_store() -> (tempfile::TempDir, FeedbackStore) {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("feedback.db");
        let store = FeedbackStore::with_db_path(db_path).unwrap();
        (dir, store)
    }

    fn count_rows(db_path: &Path) -> i64 {
        let conn = Connection::open(db_path).unwrap();
        conn.query_row("SELECT COUNT(*) FROM feedback", params![], |row| row.get(0))
            .unwrap()
    }

    #[test]
    fn initializes_database_schema() {
        let (dir, store) = test_store();
        let conn = store.open_connection().unwrap();
        let exists: String = conn
            .query_row(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'feedback'",
                params![],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(exists, "feedback");
        assert!(dir.path().join("feedback.db").exists());
    }

    #[test]
    fn records_false_positive_feedback() {
        let (_dir, store) = test_store();
        let added = store
            .report_false_positive("a".repeat(64).as_str(), "malware", 0.91, Some("[1,2,3]"))
            .unwrap();
        let stats = store.get_feedback_stats().unwrap();

        assert!(added);
        assert_eq!(stats.by_type.get("false_positive"), Some(&1));
        assert_eq!(stats.by_source.get("user"), Some(&1));
        assert_eq!(stats.last_7_days.get("false_positive"), Some(&1));
        assert_eq!(stats.unprocessed, 1);
    }

    #[test]
    fn records_false_negative_feedback() {
        let (_dir, store) = test_store();
        let added = store
            .report_false_negative("b".repeat(64).as_str(), "clean", 0.22, "trojan", None)
            .unwrap();
        let stats = store.get_feedback_stats().unwrap();

        assert!(added);
        assert_eq!(stats.by_type.get("false_negative"), Some(&1));
        assert_eq!(stats.by_source.get("user"), Some(&1));
        assert_eq!(stats.last_7_days.get("false_negative"), Some(&1));
        assert_eq!(stats.unprocessed, 1);
    }

    #[test]
    fn replaces_duplicate_feedback_entries() {
        let (dir, store) = test_store();
        let file_hash = "c".repeat(64);

        store
            .report_false_positive(&file_hash, "malware", 0.95, None)
            .unwrap();
        store
            .report_false_positive(&file_hash, "suspicious", 0.70, Some("[9,9,9]"))
            .unwrap();

        assert_eq!(count_rows(&dir.path().join("feedback.db")), 1);
        assert_eq!(
            store
                .get_feedback_stats()
                .unwrap()
                .by_type
                .get("false_positive"),
            Some(&1)
        );
    }

    #[test]
    fn aggregates_stats_by_type_source_and_recency() {
        let (_dir, store) = test_store();
        let now = Utc::now().timestamp();
        let old = now - (8 * 24 * 3600);

        store
            .insert_feedback(
                "d".repeat(64).as_str(),
                "false_positive",
                "malware",
                0.98,
                Some("clean"),
                None,
                "user",
                now,
                None,
            )
            .unwrap();
        store
            .insert_feedback(
                "e".repeat(64).as_str(),
                "false_negative",
                "clean",
                0.10,
                Some("worm"),
                None,
                "virustotal",
                now,
                Some(r#"{"actual_threat":"worm"}"#.to_string()),
            )
            .unwrap();
        store
            .insert_feedback(
                "f".repeat(64).as_str(),
                "false_positive",
                "malware",
                0.90,
                Some("clean"),
                None,
                "user",
                old,
                None,
            )
            .unwrap();

        let stats = store.get_feedback_stats().unwrap();

        assert_eq!(stats.by_type.get("false_positive"), Some(&2));
        assert_eq!(stats.by_type.get("false_negative"), Some(&1));
        assert_eq!(stats.by_source.get("user"), Some(&2));
        assert_eq!(stats.by_source.get("virustotal"), Some(&1));
        assert_eq!(stats.last_7_days.get("false_positive"), Some(&1));
        assert_eq!(stats.last_7_days.get("false_negative"), Some(&1));
        assert_eq!(stats.unprocessed, 3);
    }

    #[test]
    fn threshold_recommendation_reports_insufficient_data() {
        let (_dir, store) = test_store();
        for idx in 0..9 {
            store
                .report_false_positive(format!("{idx:064x}").as_str(), "malware", 0.95, None)
                .unwrap();
        }

        let recommendation = store.get_threshold_recommendation().unwrap();

        assert_eq!(
            recommendation,
            ThresholdRecommendation {
                adjustment: 0.0,
                reason: "insufficient_data".to_string(),
                fp_count: None,
                fn_count: None,
                fp_ratio: None,
            }
        );
    }

    #[test]
    fn threshold_recommendation_handles_false_positive_heavy_feedback() {
        let (_dir, store) = test_store();
        for idx in 0..8 {
            store
                .report_false_positive(format!("fp-{idx:062}").as_str(), "malware", 0.95, None)
                .unwrap();
        }
        for idx in 0..2 {
            store
                .report_false_negative(
                    format!("fn-{idx:062}").as_str(),
                    "clean",
                    0.15,
                    "trojan",
                    None,
                )
                .unwrap();
        }

        let recommendation = store.get_threshold_recommendation().unwrap();

        assert_eq!(recommendation.reason, "high_false_positive_rate");
        assert_eq!(recommendation.adjustment, 0.1);
        assert_eq!(recommendation.fp_count, Some(8));
        assert_eq!(recommendation.fn_count, Some(2));
        assert_eq!(recommendation.fp_ratio, Some(0.8));
    }

    #[test]
    fn threshold_recommendation_handles_false_negative_heavy_feedback() {
        let (_dir, store) = test_store();
        for idx in 0..2 {
            store
                .report_false_positive(format!("fp-{idx:062}").as_str(), "malware", 0.95, None)
                .unwrap();
        }
        for idx in 0..8 {
            store
                .report_false_negative(
                    format!("fn-{idx:062}").as_str(),
                    "clean",
                    0.15,
                    "trojan",
                    None,
                )
                .unwrap();
        }

        let recommendation = store.get_threshold_recommendation().unwrap();

        assert_eq!(recommendation.reason, "high_false_negative_rate");
        assert_eq!(recommendation.adjustment, -0.1);
        assert_eq!(recommendation.fp_count, Some(2));
        assert_eq!(recommendation.fn_count, Some(8));
        assert_eq!(recommendation.fp_ratio, Some(0.2));
    }

    #[test]
    fn threshold_recommendation_handles_balanced_feedback() {
        let (_dir, store) = test_store();
        for idx in 0..6 {
            store
                .report_false_positive(format!("fp-{idx:062}").as_str(), "malware", 0.95, None)
                .unwrap();
        }
        for idx in 0..4 {
            store
                .report_false_negative(
                    format!("fn-{idx:062}").as_str(),
                    "clean",
                    0.15,
                    "trojan",
                    None,
                )
                .unwrap();
        }

        let recommendation = store.get_threshold_recommendation().unwrap();

        assert_eq!(recommendation.reason, "balanced");
        assert_eq!(recommendation.adjustment, 0.0);
        assert_eq!(recommendation.fp_count, Some(6));
        assert_eq!(recommendation.fn_count, Some(4));
        assert_eq!(recommendation.fp_ratio, Some(0.6));
    }

    #[test]
    fn retrain_status_respects_threshold_boundary() {
        let (_dir, store) = test_store();
        for idx in 0..99 {
            store
                .report_false_positive(format!("{idx:064x}").as_str(), "malware", 0.90, None)
                .unwrap();
        }
        assert!(!store.should_retrain().unwrap());

        store
            .report_false_positive(format!("{:064x}", 100).as_str(), "malware", 0.90, None)
            .unwrap();
        assert!(store.should_retrain().unwrap());
    }
}
