use crate::core::{
    threat_feed::ThreatEntry,
    update_manager::{MalwareBazaarEntry, UpdateResult, UpdateStats, UPDATE_MANAGER},
};
/// Update Manager Commands
/// Tauri commands for threat intelligence updates
use tauri::command;
use tauri::Emitter;

#[command]
pub fn get_update_stats() -> Result<UpdateStats, String> {
    UPDATE_MANAGER
        .lock()
        .map_err(|e| format!("Failed to lock update manager: {}", e))?
        .get_stats()
        .pipe(Ok)
}

trait Pipe: Sized {
    fn pipe<F, R>(self, f: F) -> R
    where
        F: FnOnce(Self) -> R,
    {
        f(self)
    }
}
impl<T> Pipe for T {}

/// Trigger a full update from all sources
#[command]
pub async fn run_threat_update(app_handle: tauri::AppHandle) -> Result<Vec<UpdateResult>, String> {
    let _ = app_handle.emit(
        "update_started",
        serde_json::json!({
            "message": "Starting threat intelligence update..."
        }),
    );

    // We cannot hold the Mutex guard across an async await point, so we release it
    // immediately after confirming the global is available, then run the update on a
    // fresh instance (which re-reads the API key from disk just like the global would).
    {
        let _check = UPDATE_MANAGER
            .lock()
            .map_err(|e| format!("Failed to lock update manager: {}", e))?;
        // guard dropped here
    }

    let manager = crate::core::update_manager::UpdateManager::new();
    let results = manager.run_full_update().await;

    let total_added: usize = results.iter().map(|r| r.entries_added).sum();
    let success_count = results.iter().filter(|r| r.success).count();

    // Write the completion timestamp back into the global so get_update_stats() reflects it.
    if let Ok(mut global) = UPDATE_MANAGER.lock() {
        global.mark_all_sources_updated();
    }

    let _ = app_handle.emit(
        "update_completed",
        serde_json::json!({
            "success": success_count == results.len(),
            "total_added": total_added,
            "results": results,
        }),
    );

    Ok(results)
}

#[command]
pub async fn preview_malwarebazaar_recent(limit: u32) -> Result<Vec<MalwareBazaarEntry>, String> {
    let manager = crate::core::update_manager::UpdateManager::new();

    manager
        .fetch_malwarebazaar_recent(limit.min(100))
        .await
        .map_err(|e| e.to_string())
}

#[command]
pub fn preview_threat_feed_json(body: String) -> Result<Vec<ThreatEntry>, String> {
    crate::core::threat_feed::parse_feed_json(&body)
        .map_err(|e| format!("Failed to parse threat feed JSON: {}", e))
}

#[command]
pub async fn fetch_malware_by_signature(
    signature: String,
    limit: u32,
) -> Result<Vec<MalwareBazaarEntry>, String> {
    let manager = crate::core::update_manager::UpdateManager::new();

    manager
        .fetch_malwarebazaar_by_signature(&signature, limit.min(100))
        .await
        .map_err(|e| e.to_string())
}

#[command]
pub async fn fetch_malware_by_tag(
    tag: String,
    limit: u32,
) -> Result<Vec<MalwareBazaarEntry>, String> {
    let manager = crate::core::update_manager::UpdateManager::new();

    manager
        .fetch_malwarebazaar_by_tag(&tag, limit.min(100))
        .await
        .map_err(|e| e.to_string())
}

#[command]
pub async fn import_threat_feed_json(
    body: String,
    source: Option<String>,
) -> Result<UpdateResult, String> {
    let manager = crate::core::update_manager::UpdateManager::new();
    let source_name = source
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "CustomThreatFeed".to_string());

    let added = manager
        .ingest_threat_feed_json(&source_name, &body)
        .await
        .map_err(|e| e.to_string())?;

    use crate::core::static_scanner::refresh_blacklist;
    tokio::task::spawn_blocking(|| {
        if let Err(e) = refresh_blacklist() {
            log::error!("Failed to refresh in-memory blacklist: {}", e);
        }
    })
    .await
    .map_err(|e| format!("Task join error: {}", e))?;

    Ok(UpdateResult {
        source: source_name,
        success: true,
        entries_added: added,
        entries_updated: 0,
        error: None,
        timestamp: chrono::Utc::now().timestamp(),
    })
}

#[command]
pub async fn add_to_blacklist(entries: Vec<MalwareBazaarEntry>) -> Result<UpdateResult, String> {
    let manager = crate::core::update_manager::UpdateManager::new();

    let added = manager
        .update_threat_intel(&entries)
        .await
        .map_err(|e| e.to_string())?;

    use crate::core::static_scanner::refresh_blacklist;
    tokio::task::spawn_blocking(|| {
        if let Err(e) = refresh_blacklist() {
            log::error!("Failed to refresh in-memory blacklist: {}", e);
        }
    })
    .await
    .map_err(|e| format!("Task join error: {}", e))?;

    Ok(UpdateResult {
        source: "ManualAdd".to_string(),
        success: true,
        entries_added: added,
        entries_updated: 0,
        error: None,
        timestamp: chrono::Utc::now().timestamp(),
    })
}

/// Check if a hash exists in known malware databases
/// Requires MALWAREBAZAAR_API_KEY environment variable to be set
#[command]
pub async fn check_hash_malwarebazaar(hash: String) -> Result<Option<MalwareBazaarEntry>, String> {
    let api_key = crate::config::settings::get_api_key("malwarebazaar_api_key")
        .or_else(|| std::env::var("MALWAREBAZAAR_API_KEY").ok())
        .ok_or_else(|| "MalwareBazaar API key not configured. Add it in Settings > Protection. Get a free key at https://auth.abuse.ch/".to_string())?;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .user_agent("InSecurity-AV/1.0")
        .build()
        .map_err(|e| e.to_string())?;

    let response = client
        .post("https://mb-api.abuse.ch/api/v1/")
        .header("Auth-Key", &api_key)
        .form(&[("query", "get_info"), ("hash", &hash)])
        .send()
        .await
        .map_err(|e| e.to_string())?;

    let body = response.text().await.map_err(|e| e.to_string())?;

    #[derive(serde::Deserialize)]
    struct Response {
        #[serde(default)]
        query_status: String,
        #[serde(default)]
        data: Vec<MalwareBazaarEntry>,
    }

    let parsed: Response = serde_json::from_str(&body).map_err(|e| {
        format!(
            "Failed to parse MalwareBazaar response: {} - Body: {}",
            e,
            &body[..body.len().min(200)]
        )
    })?;

    if parsed.query_status == "ok" && !parsed.data.is_empty() {
        Ok(parsed.data.into_iter().next())
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pipe_trait_with_ok() {
        let value: i32 = 42;
        let result: Result<i32, String> = value.pipe(Ok);
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn test_pipe_trait_with_transform() {
        let value = 10;
        let doubled = value.pipe(|v| v * 2);
        assert_eq!(doubled, 20);
    }

    #[test]
    fn test_pipe_trait_with_string() {
        let s = "hello".to_string();
        let len = s.pipe(|s| s.len());
        assert_eq!(len, 5);
    }
}
