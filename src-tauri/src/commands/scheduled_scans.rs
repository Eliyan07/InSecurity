use chrono::{Datelike, NaiveTime, Utc};
/// Scheduled Scans commands
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ScheduleFrequency {
    Daily,
    Weekly,
    Monthly,
}

impl std::fmt::Display for ScheduleFrequency {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScheduleFrequency::Daily => write!(f, "daily"),
            ScheduleFrequency::Weekly => write!(f, "weekly"),
            ScheduleFrequency::Monthly => write!(f, "monthly"),
        }
    }
}

impl From<&str> for ScheduleFrequency {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "daily" => ScheduleFrequency::Daily,
            "weekly" => ScheduleFrequency::Weekly,
            "monthly" => ScheduleFrequency::Monthly,
            _ => ScheduleFrequency::Daily,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScheduledScan {
    pub id: i64,
    pub name: String,
    pub scan_type: String, // "quick", "full", "custom"
    pub custom_path: Option<String>,
    pub frequency: String,         // "daily", "weekly", "monthly"
    pub time_of_day: String,       // "HH:MM" format (24h)
    pub day_of_week: Option<i32>,  // 0-6 (Sunday-Saturday) for weekly
    pub day_of_month: Option<i32>, // 1-31 for monthly
    pub enabled: bool,
    pub last_run: Option<i64>,
    pub next_run: i64,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateScheduledScan {
    pub name: String,
    pub scan_type: String,
    pub custom_path: Option<String>,
    pub frequency: String,
    pub time_of_day: String,
    pub day_of_week: Option<i32>,
    pub day_of_month: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateScheduledScan {
    pub id: i64,
    pub name: Option<String>,
    pub scan_type: Option<String>,
    pub custom_path: Option<String>,
    pub frequency: Option<String>,
    pub time_of_day: Option<String>,
    pub day_of_week: Option<i32>,
    pub day_of_month: Option<i32>,
    pub enabled: Option<bool>,
}

/// Calculate the next run time based on schedule parameters
fn calculate_next_run(
    frequency: &str,
    time_of_day: &str,
    day_of_week: Option<i32>,
    day_of_month: Option<i32>,
) -> i64 {
    let now = Utc::now();

    // Parse time_of_day (HH:MM)
    let parts: Vec<&str> = time_of_day.split(':').collect();
    let (hour, minute) = if parts.len() == 2 {
        (
            parts[0].parse::<u32>().unwrap_or(9),
            parts[1].parse::<u32>().unwrap_or(0),
        )
    } else {
        (9, 0)
    };

    let target_time = NaiveTime::from_hms_opt(hour, minute, 0)
        .unwrap_or(NaiveTime::from_hms_opt(9, 0, 0).expect("09:00:00 is always a valid time"));

    let today_at_target = now.date_naive().and_time(target_time);
    let today_at_target_utc =
        chrono::DateTime::<Utc>::from_naive_utc_and_offset(today_at_target, Utc);

    match frequency.to_lowercase().as_str() {
        "daily" => {
            if now.time() < target_time {
                today_at_target_utc.timestamp()
            } else {
                (today_at_target_utc + chrono::Duration::days(1)).timestamp()
            }
        }
        "weekly" => {
            let target_weekday = day_of_week.unwrap_or(0).clamp(0, 6); // Default to Sunday, clamp to valid range
            let current_weekday = now.weekday().num_days_from_sunday() as i32;
            let mut days_until = target_weekday - current_weekday;

            if days_until < 0 || (days_until == 0 && now.time() >= target_time) {
                days_until += 7;
            }

            (today_at_target_utc + chrono::Duration::days(days_until as i64)).timestamp()
        }
        "monthly" => {
            let target_day = day_of_month.unwrap_or(1).clamp(1, 28) as u32; // Clamp to 1-28 for safety
            let current_day = now.day();

            let next_run = if current_day < target_day
                || (current_day == target_day && now.time() < target_time)
            {
                // This month
                now.date_naive()
                    .with_day(target_day)
                    .unwrap_or(now.date_naive())
                    .and_time(target_time)
            } else {
                // Next month
                let next_month = if now.month() == 12 {
                    now.with_year(now.year() + 1)
                        .and_then(|d| d.with_month(1))
                        .unwrap_or(now)
                } else {
                    now.with_month(now.month() + 1).unwrap_or(now)
                };
                next_month
                    .date_naive()
                    .with_day(target_day)
                    .unwrap_or(next_month.date_naive())
                    .and_time(target_time)
            };

            chrono::DateTime::<Utc>::from_naive_utc_and_offset(next_run, Utc).timestamp()
        }
        _ => today_at_target_utc.timestamp(),
    }
}

/// Get all scheduled scans
#[tauri::command]
pub async fn get_scheduled_scans() -> Result<Vec<ScheduledScan>, String> {
    crate::with_db_async(|conn| {
        let mut stmt = conn
            .prepare(
                "SELECT id, name, scan_type, custom_path, frequency, time_of_day,
                    day_of_week, day_of_month, enabled, last_run, next_run,
                    created_at, updated_at
             FROM scheduled_scans
             ORDER BY next_run ASC",
            )
            .map_err(|e| format!("Query prepare error: {}", e))?;

        let scans = stmt
            .query_map([], |row| {
                Ok(ScheduledScan {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    scan_type: row.get(2)?,
                    custom_path: row.get(3)?,
                    frequency: row.get(4)?,
                    time_of_day: row.get(5)?,
                    day_of_week: row.get(6)?,
                    day_of_month: row.get(7)?,
                    enabled: row.get::<_, i32>(8)? != 0,
                    last_run: row.get(9)?,
                    next_run: row.get(10)?,
                    created_at: row.get(11)?,
                    updated_at: row.get(12)?,
                })
            })
            .map_err(|e| format!("Query execution error: {}", e))?;

        let result: Vec<ScheduledScan> = scans.filter_map(|r| r.ok()).collect();

        Ok(result)
    })
    .await
}

/// Create a new scheduled scan
#[tauri::command]
pub async fn create_scheduled_scan(scan: CreateScheduledScan) -> Result<ScheduledScan, String> {
    // Validate inputs before touching DB
    if !["quick", "full", "custom"].contains(&scan.scan_type.to_lowercase().as_str()) {
        return Err("Invalid scan type. Must be 'quick', 'full', or 'custom'".to_string());
    }

    if scan.scan_type.to_lowercase() == "custom" && scan.custom_path.is_none() {
        return Err("Custom scan requires a custom_path".to_string());
    }

    if !["daily", "weekly", "monthly"].contains(&scan.frequency.to_lowercase().as_str()) {
        return Err("Invalid frequency. Must be 'daily', 'weekly', or 'monthly'".to_string());
    }

    let time_parts: Vec<&str> = scan.time_of_day.split(':').collect();
    if time_parts.len() != 2 {
        return Err("Invalid time format. Use HH:MM (24-hour)".to_string());
    }
    let hour: u32 = time_parts[0]
        .parse()
        .map_err(|_| "Invalid hour".to_string())?;
    let minute: u32 = time_parts[1]
        .parse()
        .map_err(|_| "Invalid minute".to_string())?;
    if hour > 23 || minute > 59 {
        return Err("Invalid time. Hour must be 0-23, minute must be 0-59".to_string());
    }

    let now = Utc::now().timestamp();
    let next_run = calculate_next_run(
        &scan.frequency,
        &scan.time_of_day,
        scan.day_of_week,
        scan.day_of_month,
    );

    let scan_name = scan.name.clone();
    let scan_type = scan.scan_type.to_lowercase();
    let custom_path = scan.custom_path.clone();
    let frequency = scan.frequency.to_lowercase();
    let time_of_day = scan.time_of_day.clone();
    let day_of_week = scan.day_of_week;
    let day_of_month = scan.day_of_month;

    let id = crate::with_db_async(move |conn| {
        conn.execute(
            "INSERT INTO scheduled_scans
             (name, scan_type, custom_path, frequency, time_of_day, day_of_week,
              day_of_month, enabled, last_run, next_run, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, NULL, ?8, ?9, ?9)",
            rusqlite::params![
                scan_name,
                scan_type,
                custom_path,
                frequency,
                time_of_day,
                day_of_week,
                day_of_month,
                next_run,
                now,
            ],
        )
        .map_err(|e| format!("Insert error: {}", e))?;

        Ok(conn.last_insert_rowid())
    })
    .await?;

    log::info!("Created scheduled scan '{}' (ID: {})", scan.name, id);

    Ok(ScheduledScan {
        id,
        name: scan.name,
        scan_type: scan.scan_type.to_lowercase(),
        custom_path: scan.custom_path,
        frequency: scan.frequency.to_lowercase(),
        time_of_day: scan.time_of_day,
        day_of_week: scan.day_of_week,
        day_of_month: scan.day_of_month,
        enabled: true,
        last_run: None,
        next_run,
        created_at: now,
        updated_at: now,
    })
}

/// Update an existing scheduled scan
#[tauri::command]
pub async fn update_scheduled_scan(update: UpdateScheduledScan) -> Result<ScheduledScan, String> {
    crate::with_db_async(move |conn| {
        // Fetch the existing scan
        let mut stmt = conn
            .prepare(
                "SELECT id, name, scan_type, custom_path, frequency, time_of_day,
                    day_of_week, day_of_month, enabled, last_run, next_run,
                    created_at, updated_at
             FROM scheduled_scans WHERE id = ?1",
            )
            .map_err(|e| format!("Query prepare error: {}", e))?;

        let existing = stmt
            .query_row([update.id], |row| {
                Ok(ScheduledScan {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    scan_type: row.get(2)?,
                    custom_path: row.get(3)?,
                    frequency: row.get(4)?,
                    time_of_day: row.get(5)?,
                    day_of_week: row.get(6)?,
                    day_of_month: row.get(7)?,
                    enabled: row.get::<_, i32>(8)? != 0,
                    last_run: row.get(9)?,
                    next_run: row.get(10)?,
                    created_at: row.get(11)?,
                    updated_at: row.get(12)?,
                })
            })
            .map_err(|_| format!("Scheduled scan with ID {} not found", update.id))?;

        let name = update.name.unwrap_or(existing.name);
        let scan_type = update
            .scan_type
            .map(|s| s.to_lowercase())
            .unwrap_or(existing.scan_type);
        let custom_path = update.custom_path.or(existing.custom_path);
        let frequency = update
            .frequency
            .map(|s| s.to_lowercase())
            .unwrap_or(existing.frequency);
        let time_of_day = update.time_of_day.unwrap_or(existing.time_of_day);
        let day_of_week = update.day_of_week.or(existing.day_of_week);
        let day_of_month = update.day_of_month.or(existing.day_of_month);
        let enabled = update.enabled.unwrap_or(existing.enabled);

        let next_run = calculate_next_run(&frequency, &time_of_day, day_of_week, day_of_month);
        let now = Utc::now().timestamp();

        conn.execute(
            "UPDATE scheduled_scans SET
             name = ?1, scan_type = ?2, custom_path = ?3, frequency = ?4,
             time_of_day = ?5, day_of_week = ?6, day_of_month = ?7,
             enabled = ?8, next_run = ?9, updated_at = ?10
             WHERE id = ?11",
            rusqlite::params![
                name,
                scan_type,
                custom_path,
                frequency,
                time_of_day,
                day_of_week,
                day_of_month,
                enabled as i32,
                next_run,
                now,
                update.id,
            ],
        )
        .map_err(|e| format!("Update error: {}", e))?;

        log::info!("Updated scheduled scan ID {}", update.id);

        Ok(ScheduledScan {
            id: update.id,
            name,
            scan_type,
            custom_path,
            frequency,
            time_of_day,
            day_of_week,
            day_of_month,
            enabled,
            last_run: existing.last_run,
            next_run,
            created_at: existing.created_at,
            updated_at: now,
        })
    })
    .await
}

/// Toggle a scheduled scan's enabled state
#[tauri::command]
pub async fn toggle_scheduled_scan(id: i64) -> Result<bool, String> {
    crate::with_db_async(move |conn| {
        let current_enabled: i32 = conn
            .query_row(
                "SELECT enabled FROM scheduled_scans WHERE id = ?1",
                [id],
                |row| row.get(0),
            )
            .map_err(|_| format!("Scheduled scan with ID {} not found", id))?;

        let new_enabled = if current_enabled != 0 { 0 } else { 1 };
        let now = Utc::now().timestamp();

        conn.execute(
            "UPDATE scheduled_scans SET enabled = ?1, updated_at = ?2 WHERE id = ?3",
            rusqlite::params![new_enabled, now, id],
        )
        .map_err(|e| format!("Update error: {}", e))?;

        log::info!(
            "Toggled scheduled scan ID {} to enabled={}",
            id,
            new_enabled != 0
        );

        Ok(new_enabled != 0)
    })
    .await
}

/// Delete a scheduled scan
#[tauri::command]
pub async fn delete_scheduled_scan(id: i64) -> Result<(), String> {
    crate::with_db_async(move |conn| {
        let rows = conn
            .execute("DELETE FROM scheduled_scans WHERE id = ?1", [id])
            .map_err(|e| format!("Delete error: {}", e))?;

        if rows == 0 {
            return Err(format!("Scheduled scan with ID {} not found", id));
        }

        log::info!("Deleted scheduled scan ID {}", id);

        Ok(())
    })
    .await
}

/// Run a scheduled scan immediately (triggered by "Run Now" in the UI).
/// Fetches the scan config by ID and starts the scan via the normal scan machinery.
#[tauri::command]
pub async fn run_scheduled_scan_now(app: tauri::AppHandle, id: i64) -> Result<(), String> {
    let scan = crate::with_db_async(move |conn| {
        let mut stmt = conn
            .prepare(
                "SELECT id, name, scan_type, custom_path, frequency, time_of_day,
                    day_of_week, day_of_month, enabled, last_run, next_run,
                    created_at, updated_at
             FROM scheduled_scans WHERE id = ?1",
            )
            .map_err(|e| format!("Query prepare error: {}", e))?;

        stmt.query_row([id], |row| {
            Ok(ScheduledScan {
                id: row.get(0)?,
                name: row.get(1)?,
                scan_type: row.get(2)?,
                custom_path: row.get(3)?,
                frequency: row.get(4)?,
                time_of_day: row.get(5)?,
                day_of_week: row.get(6)?,
                day_of_month: row.get(7)?,
                enabled: row.get::<_, i32>(8)? != 0,
                last_run: row.get(9)?,
                next_run: row.get(10)?,
                created_at: row.get(11)?,
                updated_at: row.get(12)?,
            })
        })
        .map_err(|_| format!("Scheduled scan with ID {} not found", id))
    })
    .await?;

    log::info!(
        "Running scheduled scan '{}' (ID: {}) on demand",
        scan.name,
        scan.id
    );

    crate::commands::scan::start_scan(app, scan.scan_type, scan.custom_path).await
}

/// Get the next scheduled scan that is due
#[tauri::command]
pub fn get_next_due_scan() -> Result<Option<ScheduledScan>, String> {
    // NOTE: This is intentionally sync - it's called from background task, not frontend
    let now = Utc::now().timestamp();

    let guard = crate::DB
        .lock()
        .map_err(|e| format!("DB lock error: {}", e))?;
    let conn = guard.as_ref().ok_or("Database not available")?;

    let mut stmt = conn
        .prepare(
            "SELECT id, name, scan_type, custom_path, frequency, time_of_day,
                day_of_week, day_of_month, enabled, last_run, next_run,
                created_at, updated_at
         FROM scheduled_scans
         WHERE enabled = 1 AND next_run <= ?1
         ORDER BY next_run ASC
         LIMIT 1",
        )
        .map_err(|e| format!("Query prepare error: {}", e))?;

    let scan = stmt
        .query_row([now], |row| {
            Ok(ScheduledScan {
                id: row.get(0)?,
                name: row.get(1)?,
                scan_type: row.get(2)?,
                custom_path: row.get(3)?,
                frequency: row.get(4)?,
                time_of_day: row.get(5)?,
                day_of_week: row.get(6)?,
                day_of_month: row.get(7)?,
                enabled: row.get::<_, i32>(8)? != 0,
                last_run: row.get(9)?,
                next_run: row.get(10)?,
                created_at: row.get(11)?,
                updated_at: row.get(12)?,
            })
        })
        .ok();

    Ok(scan)
}

/// Mark a scheduled scan as completed and update next_run
pub fn mark_scan_completed(id: i64) -> Result<(), String> {
    // NOTE: This is intentionally sync - called from background task
    let now = Utc::now().timestamp();

    let guard = crate::DB
        .lock()
        .map_err(|e| format!("DB lock error: {}", e))?;
    let conn = guard.as_ref().ok_or("Database not available")?;

    let (frequency, time_of_day, day_of_week, day_of_month): (String, String, Option<i32>, Option<i32>) =
        conn.query_row(
            "SELECT frequency, time_of_day, day_of_week, day_of_month FROM scheduled_scans WHERE id = ?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        ).map_err(|_| format!("Scheduled scan with ID {} not found", id))?;

    let next_run = calculate_next_run(&frequency, &time_of_day, day_of_week, day_of_month);

    conn.execute(
        "UPDATE scheduled_scans SET last_run = ?1, next_run = ?2, updated_at = ?1 WHERE id = ?3",
        rusqlite::params![now, next_run, id],
    )
    .map_err(|e| format!("Update error: {}", e))?;

    log::info!(
        "Marked scheduled scan ID {} as completed, next run at {}",
        id,
        next_run
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_calculate_next_run_always_in_future() {
        let now = Utc::now().timestamp();
        let result = calculate_next_run("daily", "00:00", None, None);
        assert!(result >= now, "next_run should be in the future");
    }

    #[test]
    fn test_calculate_next_run_daily_returns_reasonable_timestamp() {
        let now = Utc::now().timestamp();
        let result = calculate_next_run("daily", "12:00", None, None);
        // Should be within 24 hours from now
        assert!(result > now - 1);
        assert!(result <= now + 86400);
    }

    #[test]
    fn test_calculate_next_run_weekly_returns_within_7_days() {
        let now = Utc::now().timestamp();
        let result = calculate_next_run("weekly", "12:00", Some(3), None); // Wednesday
        assert!(result > now - 1);
        assert!(result <= now + 7 * 86400 + 1);
    }

    #[test]
    fn test_calculate_next_run_weekly_default_sunday() {
        let now = Utc::now().timestamp();
        let result = calculate_next_run("weekly", "12:00", None, None);
        // Should be within 7 days and target Sunday
        assert!(result > now - 1);
        assert!(result <= now + 7 * 86400 + 1);
    }

    #[test]
    fn test_calculate_next_run_weekly_invalid_day_clamped() {
        // day_of_week=7 is now clamped to 6 (Saturday)
        let now = Utc::now().timestamp();
        let result = calculate_next_run("weekly", "12:00", Some(7), None);
        // Should not panic and should produce a valid future timestamp
        assert!(result > now - 1);
        assert!(result <= now + 7 * 86400 + 1);
    }

    #[test]
    fn test_calculate_next_run_weekly_large_day_clamped() {
        // day_of_week=100 is clamped to 6
        let now = Utc::now().timestamp();
        let result = calculate_next_run("weekly", "12:00", Some(100), None);
        assert!(result > now - 1);
        assert!(result <= now + 7 * 86400 + 1);
    }

    #[test]
    fn test_calculate_next_run_weekly_negative_day_clamped() {
        let now = Utc::now().timestamp();
        let result = calculate_next_run("weekly", "12:00", Some(-5), None);
        assert!(result > now - 1);
        assert!(result <= now + 7 * 86400 + 1);
    }

    #[test]
    fn test_calculate_next_run_monthly_clamp_31() {
        let now = Utc::now().timestamp();
        let result = calculate_next_run("monthly", "09:00", None, Some(31));
        // day_of_month=31 is clamped to 28
        assert!(result > now - 1);
        // Should be within ~31 days
        assert!(result <= now + 32 * 86400);
    }

    #[test]
    fn test_calculate_next_run_monthly_clamp_0_to_1() {
        let now = Utc::now().timestamp();
        let result = calculate_next_run("monthly", "09:00", None, Some(0));
        // day_of_month=0 is clamped to 1
        assert!(result > now - 1);
    }

    #[test]
    fn test_calculate_next_run_monthly_default_day_1() {
        let now = Utc::now().timestamp();
        let result = calculate_next_run("monthly", "09:00", None, None);
        // day_of_month defaults to 1
        assert!(result > now - 1);
    }

    #[test]
    fn test_calculate_next_run_invalid_time_defaults_to_0900() {
        let now = Utc::now().timestamp();
        let result = calculate_next_run("daily", "invalid", None, None);
        // Should not panic, defaults to 09:00
        assert!(result > now - 1);
        assert!(result <= now + 86400);
    }

    #[test]
    fn test_calculate_next_run_out_of_range_time_defaults() {
        // hour=25 -> from_hms_opt returns None -> falls back to 09:00
        let now = Utc::now().timestamp();
        let result = calculate_next_run("daily", "25:00", None, None);
        assert!(result > now - 1);
    }

    #[test]
    fn test_calculate_next_run_unknown_frequency() {
        let now = Utc::now().timestamp();
        let result = calculate_next_run("hourly", "12:00", None, None);
        // Falls through to default case: returns today at target time (may be in past)
        // Just verify it doesn't panic and returns a reasonable timestamp
        assert!(result > 0, "Should return a valid timestamp");
        assert!((result - now).abs() < 86400, "Should be within 24h of now");
    }

    #[test]
    fn test_schedule_frequency_from_str() {
        assert_eq!(ScheduleFrequency::from("daily"), ScheduleFrequency::Daily);
        assert_eq!(ScheduleFrequency::from("weekly"), ScheduleFrequency::Weekly);
        assert_eq!(
            ScheduleFrequency::from("monthly"),
            ScheduleFrequency::Monthly
        );
        assert_eq!(ScheduleFrequency::from("DAILY"), ScheduleFrequency::Daily);
        assert_eq!(ScheduleFrequency::from("Weekly"), ScheduleFrequency::Weekly);
        // Unknown defaults to Daily
        assert_eq!(ScheduleFrequency::from("unknown"), ScheduleFrequency::Daily);
    }

    #[test]
    fn test_schedule_frequency_display() {
        assert_eq!(ScheduleFrequency::Daily.to_string(), "daily");
        assert_eq!(ScheduleFrequency::Weekly.to_string(), "weekly");
        assert_eq!(ScheduleFrequency::Monthly.to_string(), "monthly");
    }

    #[test]
    fn test_calculate_next_run_all_weekdays() {
        let now = Utc::now().timestamp();
        for day in 0..=6 {
            let result = calculate_next_run("weekly", "12:00", Some(day), None);
            assert!(
                result > now - 1,
                "day {} should produce future timestamp",
                day
            );
            assert!(
                result <= now + 7 * 86400 + 1,
                "day {} should be within 7 days",
                day
            );
        }
    }
}
