//! Structured error types for the antivirus application
//! Provides typed errors that can be serialized to the frontend

use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "domain", content = "error")]
pub enum AppError {
    Scan(ScanError),
    Quarantine(QuarantineError),
    Database(DatabaseError),
    Config(ConfigError),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::Scan(e) => write!(f, "Scan: {}", e),
            AppError::Quarantine(e) => write!(f, "Quarantine: {}", e),
            AppError::Database(e) => write!(f, "Database: {}", e),
            AppError::Config(e) => write!(f, "Config: {}", e),
        }
    }
}

impl std::error::Error for AppError {}

impl From<ScanError> for AppError {
    fn from(e: ScanError) -> Self {
        AppError::Scan(e)
    }
}

impl From<QuarantineError> for AppError {
    fn from(e: QuarantineError) -> Self {
        AppError::Quarantine(e)
    }
}

impl From<DatabaseError> for AppError {
    fn from(e: DatabaseError) -> Self {
        AppError::Database(e)
    }
}

impl From<ConfigError> for AppError {
    fn from(e: ConfigError) -> Self {
        AppError::Config(e)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "details")]
pub enum ConfigError {
    InvalidValue { key: String, message: String },
    Missing { key: String },
    ParseError { message: String },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::InvalidValue { key, message } => {
                write!(f, "Invalid config '{}': {}", key, message)
            }
            ConfigError::Missing { key } => write!(f, "Missing config: {}", key),
            ConfigError::ParseError { message } => write!(f, "Config parse error: {}", message),
        }
    }
}

impl std::error::Error for ConfigError {}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "details")]
pub enum ScanError {
    FileNotFound {
        path: String,
    },
    PermissionDenied {
        path: String,
    },
    FileTooLarge {
        path: String,
        size_bytes: u64,
        max_bytes: u64,
    },
    Timeout {
        duration_ms: u64,
    },
    DatabaseError {
        message: String,
    },
    MlError {
        message: String,
    },
    IoError {
        message: String,
    },
    Internal {
        message: String,
    },
    InvalidHash {
        hash: String,
        expected_format: String,
    },
    PathTraversal {
        path: String,
    },
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanError::FileNotFound { path } => write!(f, "File not found: {}", path),
            ScanError::PermissionDenied { path } => write!(f, "Permission denied: {}", path),
            ScanError::FileTooLarge {
                path,
                size_bytes,
                max_bytes,
            } => {
                write!(
                    f,
                    "File too large: {} ({} bytes, max {} bytes)",
                    path, size_bytes, max_bytes
                )
            }
            ScanError::Timeout { duration_ms } => {
                write!(f, "Scan timed out after {}ms", duration_ms)
            }
            ScanError::DatabaseError { message } => write!(f, "Database error: {}", message),
            ScanError::MlError { message } => write!(f, "ML error: {}", message),
            ScanError::IoError { message } => write!(f, "IO error: {}", message),
            ScanError::Internal { message } => write!(f, "Internal error: {}", message),
            ScanError::InvalidHash {
                hash,
                expected_format,
            } => {
                write!(f, "Invalid hash '{}': expected {}", hash, expected_format)
            }
            ScanError::PathTraversal { path } => {
                write!(f, "Path traversal attempt blocked: {}", path)
            }
        }
    }
}

impl std::error::Error for ScanError {}

impl From<std::io::Error> for ScanError {
    fn from(e: std::io::Error) -> Self {
        match e.kind() {
            std::io::ErrorKind::NotFound => ScanError::FileNotFound {
                path: "unknown".to_string(),
            },
            std::io::ErrorKind::PermissionDenied => ScanError::PermissionDenied {
                path: "unknown".to_string(),
            },
            _ => ScanError::IoError {
                message: e.to_string(),
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "details")]
pub enum QuarantineError {
    FileNotFound { path: String },
    KeyUnavailable { reason: String },
    CryptoError { message: String },
    EntryNotFound { id: i64 },
    DatabaseError { message: String },
    IoError { message: String },
}

impl fmt::Display for QuarantineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QuarantineError::FileNotFound { path } => write!(f, "File not found: {}", path),
            QuarantineError::KeyUnavailable { reason } => {
                write!(f, "Encryption key unavailable: {}", reason)
            }
            QuarantineError::CryptoError { message } => write!(f, "Encryption error: {}", message),
            QuarantineError::EntryNotFound { id } => {
                write!(f, "Quarantine entry not found: {}", id)
            }
            QuarantineError::DatabaseError { message } => write!(f, "Database error: {}", message),
            QuarantineError::IoError { message } => write!(f, "IO error: {}", message),
        }
    }
}

impl std::error::Error for QuarantineError {}

impl From<std::io::Error> for QuarantineError {
    fn from(e: std::io::Error) -> Self {
        match e.kind() {
            std::io::ErrorKind::NotFound => QuarantineError::FileNotFound {
                path: "unknown".to_string(),
            },
            _ => QuarantineError::IoError {
                message: e.to_string(),
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "details")]
pub enum DatabaseError {
    ConnectionFailed { message: String },
    QueryFailed { message: String },
    NotFound { table: String, id: String },
    ConstraintViolation { message: String },
    LockError { message: String },
}

impl fmt::Display for DatabaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DatabaseError::ConnectionFailed { message } => {
                write!(f, "Connection failed: {}", message)
            }
            DatabaseError::QueryFailed { message } => write!(f, "Query failed: {}", message),
            DatabaseError::NotFound { table, id } => write!(f, "Not found in {}: {}", table, id),
            DatabaseError::ConstraintViolation { message } => {
                write!(f, "Constraint violation: {}", message)
            }
            DatabaseError::LockError { message } => write!(f, "Lock error: {}", message),
        }
    }
}

impl std::error::Error for DatabaseError {}

impl From<rusqlite::Error> for DatabaseError {
    fn from(e: rusqlite::Error) -> Self {
        match e {
            rusqlite::Error::QueryReturnedNoRows => DatabaseError::NotFound {
                table: "unknown".to_string(),
                id: "unknown".to_string(),
            },
            _ => DatabaseError::QueryFailed {
                message: e.to_string(),
            },
        }
    }
}

impl From<String> for ScanError {
    fn from(s: String) -> Self {
        ScanError::Internal { message: s }
    }
}

impl From<String> for QuarantineError {
    fn from(s: String) -> Self {
        QuarantineError::IoError { message: s }
    }
}

impl From<String> for DatabaseError {
    fn from(s: String) -> Self {
        DatabaseError::QueryFailed { message: s }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Display impl tests
    // =========================================================================

    #[test]
    fn test_scan_error_display_file_not_found() {
        let err = ScanError::FileNotFound {
            path: "/tmp/missing.exe".to_string(),
        };
        assert_eq!(err.to_string(), "File not found: /tmp/missing.exe");
    }

    #[test]
    fn test_scan_error_display_permission_denied() {
        let err = ScanError::PermissionDenied {
            path: "/root/secret".to_string(),
        };
        assert_eq!(err.to_string(), "Permission denied: /root/secret");
    }

    #[test]
    fn test_scan_error_display_file_too_large() {
        let err = ScanError::FileTooLarge {
            path: "/tmp/big.iso".to_string(),
            size_bytes: 5_000_000_000,
            max_bytes: 1_000_000_000,
        };
        let msg = err.to_string();
        assert!(msg.contains("big.iso"));
        assert!(msg.contains("5000000000"));
        assert!(msg.contains("1000000000"));
    }

    #[test]
    fn test_scan_error_display_timeout() {
        let err = ScanError::Timeout { duration_ms: 30000 };
        assert_eq!(err.to_string(), "Scan timed out after 30000ms");
    }

    #[test]
    fn test_scan_error_display_path_traversal() {
        let err = ScanError::PathTraversal {
            path: "../../etc/passwd".to_string(),
        };
        assert!(err.to_string().contains("traversal"));
    }

    #[test]
    fn test_quarantine_error_display() {
        let err = QuarantineError::EntryNotFound { id: 42 };
        assert_eq!(err.to_string(), "Quarantine entry not found: 42");

        let err = QuarantineError::KeyUnavailable {
            reason: "TPM locked".to_string(),
        };
        assert!(err.to_string().contains("TPM locked"));
    }

    #[test]
    fn test_database_error_display() {
        let err = DatabaseError::NotFound {
            table: "verdicts".to_string(),
            id: "abc123".to_string(),
        };
        assert_eq!(err.to_string(), "Not found in verdicts: abc123");
    }

    #[test]
    fn test_config_error_display() {
        let err = ConfigError::Missing {
            key: "api_key".to_string(),
        };
        assert_eq!(err.to_string(), "Missing config: api_key");

        let err = ConfigError::InvalidValue {
            key: "threshold".to_string(),
            message: "must be between 0 and 1".to_string(),
        };
        assert!(err.to_string().contains("threshold"));
    }

    #[test]
    fn test_app_error_display_delegates() {
        let err = AppError::Scan(ScanError::Timeout { duration_ms: 5000 });
        assert!(err.to_string().starts_with("Scan:"));

        let err = AppError::Database(DatabaseError::LockError {
            message: "busy".to_string(),
        });
        assert!(err.to_string().starts_with("Database:"));
    }

    // =========================================================================
    // From conversions
    // =========================================================================

    #[test]
    fn test_scan_error_from_io_not_found() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "gone");
        let scan_err: ScanError = io_err.into();
        assert!(matches!(scan_err, ScanError::FileNotFound { .. }));
    }

    #[test]
    fn test_scan_error_from_io_permission_denied() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "nope");
        let scan_err: ScanError = io_err.into();
        assert!(matches!(scan_err, ScanError::PermissionDenied { .. }));
    }

    #[test]
    fn test_scan_error_from_io_other() {
        let io_err = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "broken");
        let scan_err: ScanError = io_err.into();
        assert!(matches!(scan_err, ScanError::IoError { .. }));
    }

    #[test]
    fn test_quarantine_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "vanished");
        let qerr: QuarantineError = io_err.into();
        assert!(matches!(qerr, QuarantineError::FileNotFound { .. }));
    }

    #[test]
    fn test_scan_error_from_string() {
        let err: ScanError = "something went wrong".to_string().into();
        assert!(matches!(err, ScanError::Internal { .. }));
        assert!(err.to_string().contains("something went wrong"));
    }

    #[test]
    fn test_quarantine_error_from_string() {
        let err: QuarantineError = "disk full".to_string().into();
        assert!(matches!(err, QuarantineError::IoError { .. }));
    }

    #[test]
    fn test_database_error_from_string() {
        let err: DatabaseError = "table locked".to_string().into();
        assert!(matches!(err, DatabaseError::QueryFailed { .. }));
    }

    #[test]
    fn test_app_error_from_scan_error() {
        let scan_err = ScanError::Timeout { duration_ms: 1000 };
        let app_err: AppError = scan_err.into();
        assert!(matches!(app_err, AppError::Scan(ScanError::Timeout { .. })));
    }

    #[test]
    fn test_app_error_from_quarantine_error() {
        let qerr = QuarantineError::EntryNotFound { id: 1 };
        let app_err: AppError = qerr.into();
        assert!(matches!(
            app_err,
            AppError::Quarantine(QuarantineError::EntryNotFound { .. })
        ));
    }

    #[test]
    fn test_app_error_from_config_error() {
        let cerr = ConfigError::Missing {
            key: "x".to_string(),
        };
        let app_err: AppError = cerr.into();
        assert!(matches!(
            app_err,
            AppError::Config(ConfigError::Missing { .. })
        ));
    }

    // =========================================================================
    // Serialization - tagged enums
    // =========================================================================

    #[test]
    fn test_app_error_serialization_tagged() {
        let err = AppError::Scan(ScanError::FileNotFound {
            path: "/test".to_string(),
        });
        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains("\"domain\":\"Scan\""));
        assert!(json.contains("\"type\":\"FileNotFound\""));
    }

    #[test]
    fn test_app_error_serialization_roundtrip() {
        let original = AppError::Quarantine(QuarantineError::CryptoError {
            message: "AES key derivation failed".to_string(),
        });
        let json = serde_json::to_string(&original).unwrap();
        let deser: AppError = serde_json::from_str(&json).unwrap();
        assert_eq!(original.to_string(), deser.to_string());
    }

    #[test]
    fn test_database_error_serialization() {
        let err = DatabaseError::ConstraintViolation {
            message: "unique".to_string(),
        };
        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains("ConstraintViolation"));
        let deser: DatabaseError = serde_json::from_str(&json).unwrap();
        assert!(matches!(deser, DatabaseError::ConstraintViolation { .. }));
    }
}
