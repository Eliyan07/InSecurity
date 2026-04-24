use crate::database::models::Verdict;
use crate::database::queries::DatabaseQueries;
use once_cell::sync::Lazy;
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const DEFAULT_BATCH_SIZE: usize = 50;
const DEFAULT_BATCH_TIMEOUT_MS: u64 = 500;
const DEFAULT_MAX_QUEUE_SIZE: usize = 1000;

static SENDER: Lazy<Mutex<Option<SyncSender<Verdict>>>> = Lazy::new(|| Mutex::new(None));

static INITIALIZED: Lazy<Mutex<bool>> = Lazy::new(|| Mutex::new(false));

pub fn init() {
    let mut guard = SENDER.lock().unwrap_or_else(|e| e.into_inner());
    if guard.is_some() {
        return;
    }

    let max_queue: usize = std::env::var("DB_MAX_QUEUE_SIZE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_MAX_QUEUE_SIZE);
    let (tx, rx): (SyncSender<Verdict>, Receiver<Verdict>) = mpsc::sync_channel(max_queue);
    *guard = Some(tx.clone());

    if let Ok(mut init) = INITIALIZED.lock() {
        *init = true;
    }

    std::thread::spawn(move || {
        let batch_size: usize = std::env::var("DB_BATCH_SIZE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_BATCH_SIZE);
        let batch_timeout = Duration::from_millis(
            std::env::var("DB_BATCH_TIMEOUT_MS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(DEFAULT_BATCH_TIMEOUT_MS),
        );

        log::info!(
            "Database batcher thread started (batch_size={}, timeout={}ms)",
            batch_size,
            batch_timeout.as_millis()
        );

        while let Ok(first) = rx.recv() {
            let mut vec = Vec::with_capacity(batch_size);
            vec.push(first);

            let start = Instant::now();

            while vec.len() < batch_size {
                let remaining = batch_timeout
                    .checked_sub(start.elapsed())
                    .unwrap_or(Duration::from_millis(0));
                match rx.recv_timeout(remaining) {
                    Ok(v) => vec.push(v),
                    Err(mpsc::RecvTimeoutError::Timeout) => break,
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        log::info!(
                            "Batcher channel closed, flushing {} remaining verdicts",
                            vec.len()
                        );
                        break;
                    }
                }
            }

            if let Ok(db_lock) = crate::DB.lock() {
                if let Some(conn) = db_lock.as_ref() {
                    match conn.execute_batch("BEGIN TRANSACTION;") {
                        Ok(_) => {
                            for rec in &vec {
                                if let Err(e) = DatabaseQueries::insert_verdict(conn, rec) {
                                    log::warn!("Batch insert verdict failed: {}", e);
                                }
                            }
                            let _ = conn.execute_batch("COMMIT;");
                        }
                        Err(e) => {
                            log::warn!("Failed to begin DB transaction for batch insert: {}", e);
                        }
                    }
                }
            }
        }

        log::info!("Database batcher thread shutting down");
    });
}

pub fn shutdown() {
    if let Ok(mut guard) = SENDER.lock() {
        if guard.take().is_some() {
            log::info!("Batcher shutdown initiated - channel closed");
        }
    }
    if let Ok(mut init) = INITIALIZED.lock() {
        *init = false;
    }
}

pub fn is_running() -> bool {
    INITIALIZED.lock().map(|g| *g).unwrap_or(false)
}

pub fn enqueue_verdict(v: Verdict) {
    if let Ok(guard) = SENDER.lock() {
        if let Some(tx) = guard.as_ref() {
            if let Err(e) = tx.try_send(v) {
                match e {
                    std::sync::mpsc::TrySendError::Full(_) => {
                        log::warn!("Verdict queue full - verdict dropped. Consider increasing DB_MAX_QUEUE_SIZE");
                    }
                    std::sync::mpsc::TrySendError::Disconnected(_) => {
                        log::error!("Batcher channel disconnected - verdict lost");
                    }
                }
            }
        } else {
            log::debug!("Batcher not initialized - verdict not queued");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_verdict() -> Verdict {
        Verdict {
            id: 0,
            file_hash: "abc123".to_string(),
            file_path: "C:\\test\\file.exe".to_string(),
            verdict: "Clean".to_string(),
            confidence: 0.9,
            threat_level: "LOW".to_string(),
            threat_name: None,
            scan_time_ms: 50,
            scanned_at: chrono::Utc::now().timestamp(),
            source: "manual".to_string(),
        }
    }

    #[test]
    fn test_is_running_before_init() {
        // Before init, batcher should report not running
        // (unless a previous test initialized it - use a fresh check)
        // This test verifies the function doesn't panic
        let _ = is_running();
    }

    #[test]
    fn test_shutdown_when_not_initialized() {
        // Calling shutdown when not initialized should not panic
        shutdown();
    }

    #[test]
    fn test_enqueue_verdict_when_not_initialized() {
        // Enqueuing when batcher not initialized should not panic
        let v = make_test_verdict();
        enqueue_verdict(v);
    }

    #[test]
    fn test_constants() {
        assert_eq!(DEFAULT_BATCH_SIZE, 50);
        assert_eq!(DEFAULT_BATCH_TIMEOUT_MS, 500);
        assert_eq!(DEFAULT_MAX_QUEUE_SIZE, 1000);
    }
}
