use chrono::Utc;
use reqwest::Client;
use serde::{Deserialize, Serialize};

const APP_RELEASE_API_URL: &str =
    "https://api.github.com/repos/Eliyan07/InSecurity/releases/latest";
const APP_RELEASES_URL: &str = "https://github.com/Eliyan07/InSecurity/releases/latest";
const APP_UPDATE_CHECK_INTERVAL_SECS: i64 = 24 * 60 * 60;
const APP_USER_AGENT: &str = concat!("InSecurity-AV/", env!("CARGO_PKG_VERSION"));

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppUpdateInfo {
    pub current_version: String,
    pub latest_version: String,
    pub download_url: String,
    pub release_page_url: String,
    pub published_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppUpdateCheckResult {
    pub update: Option<AppUpdateInfo>,
    pub should_notify: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct GitHubReleaseAsset {
    #[serde(default)]
    name: String,
    #[serde(default)]
    browser_download_url: String,
}

#[derive(Debug, Clone, Deserialize)]
struct GitHubRelease {
    #[serde(default)]
    tag_name: String,
    #[serde(default)]
    html_url: String,
    #[serde(default)]
    published_at: Option<String>,
    #[serde(default)]
    assets: Vec<GitHubReleaseAsset>,
}

async fn load_settings() -> Result<crate::config::Settings, String> {
    tokio::task::spawn_blocking(crate::config::Settings::load)
        .await
        .map_err(|e| format!("Task join error: {}", e))
}

async fn save_settings(settings: crate::config::Settings) -> Result<(), String> {
    tokio::task::spawn_blocking(move || {
        settings.save();
        Ok::<(), String>(())
    })
    .await
    .map_err(|e| format!("Task join error: {}", e))?
}

fn normalize_release_version(version: &str) -> String {
    version
        .trim()
        .trim_start_matches(|c: char| c == 'v' || c == 'V')
        .trim()
        .to_string()
}

fn version_segments(version: &str) -> Vec<u64> {
    let normalized = normalize_release_version(version);
    let numeric_prefix = normalized
        .split(|c: char| !(c.is_ascii_digit() || c == '.'))
        .next()
        .unwrap_or_default();

    numeric_prefix
        .split('.')
        .filter(|segment| !segment.is_empty())
        .map(|segment| segment.parse::<u64>().unwrap_or(0))
        .collect()
}

fn is_newer_version(latest: &str, current: &str) -> bool {
    let latest_segments = version_segments(latest);
    let current_segments = version_segments(current);
    let max_len = latest_segments.len().max(current_segments.len());

    for index in 0..max_len {
        let latest_value = *latest_segments.get(index).unwrap_or(&0);
        let current_value = *current_segments.get(index).unwrap_or(&0);
        match latest_value.cmp(&current_value) {
            std::cmp::Ordering::Greater => return true,
            std::cmp::Ordering::Less => return false,
            std::cmp::Ordering::Equal => {}
        }
    }

    false
}

fn pick_download_url(release: &GitHubRelease) -> String {
    release
        .assets
        .iter()
        .find(|asset| {
            let name = asset.name.to_ascii_lowercase();
            name.ends_with(".exe") || name.ends_with(".msi")
        })
        .or_else(|| {
            release.assets.iter().find(|asset| {
                let name = asset.name.to_ascii_lowercase();
                name.contains("installer") || name.contains("setup")
            })
        })
        .map(|asset| asset.browser_download_url.clone())
        .filter(|url| !url.trim().is_empty())
        .unwrap_or_else(|| {
            if release.html_url.trim().is_empty() {
                APP_RELEASES_URL.to_string()
            } else {
                release.html_url.clone()
            }
        })
}

async fn fetch_latest_release() -> Result<GitHubRelease, String> {
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .user_agent(APP_USER_AGENT)
        .build()
        .map_err(|e| format!("Failed to create update client: {}", e))?;

    let response = client
        .get(APP_RELEASE_API_URL)
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .map_err(|e| format!("Could not reach GitHub Releases right now ({})", e))?;

    if !response.status().is_success() {
        return Err(format!(
            "GitHub Releases returned {} while checking for updates.",
            response.status()
        ));
    }

    response
        .json::<GitHubRelease>()
        .await
        .map_err(|e| format!("GitHub Releases returned an unexpected response ({})", e))
}

#[tauri::command]
pub async fn check_app_update(force: Option<bool>) -> Result<AppUpdateCheckResult, String> {
    let force = force.unwrap_or(false);
    let now = Utc::now().timestamp();
    let current_version = normalize_release_version(env!("CARGO_PKG_VERSION"));
    let mut settings = load_settings().await?;

    if !force {
        let recently_checked = settings
            .last_app_update_check
            .map(|last_check| now - last_check < APP_UPDATE_CHECK_INTERVAL_SECS)
            .unwrap_or(false);

        if recently_checked {
            return Ok(AppUpdateCheckResult {
                update: None,
                should_notify: false,
                error: None,
            });
        }
    }

    settings.last_app_update_check = Some(now);
    save_settings(settings.clone()).await?;

    let release = match fetch_latest_release().await {
        Ok(release) => release,
        Err(error) => {
            return Ok(AppUpdateCheckResult {
                update: None,
                should_notify: false,
                error: Some(error),
            });
        }
    };

    let latest_version = normalize_release_version(&release.tag_name);
    if latest_version.is_empty() {
        return Ok(AppUpdateCheckResult {
            update: None,
            should_notify: false,
            error: Some("GitHub Releases did not include a usable version tag.".to_string()),
        });
    }

    if !is_newer_version(&latest_version, &current_version) {
        return Ok(AppUpdateCheckResult {
            update: None,
            should_notify: false,
            error: None,
        });
    }

    if !force && settings.dismissed_app_update_version.as_deref() == Some(latest_version.as_str()) {
        return Ok(AppUpdateCheckResult {
            update: None,
            should_notify: false,
            error: None,
        });
    }

    let should_notify = !force
        && settings.last_notified_app_update_version.as_deref() != Some(latest_version.as_str());

    if should_notify {
        settings.last_notified_app_update_version = Some(latest_version.clone());
        save_settings(settings.clone()).await?;
    }

    Ok(AppUpdateCheckResult {
        update: Some(AppUpdateInfo {
            current_version,
            latest_version,
            download_url: pick_download_url(&release),
            release_page_url: if release.html_url.trim().is_empty() {
                APP_RELEASES_URL.to_string()
            } else {
                release.html_url
            },
            published_at: release.published_at,
        }),
        should_notify,
        error: None,
    })
}

#[tauri::command]
pub async fn dismiss_app_update(version: String) -> Result<(), String> {
    let normalized_version = normalize_release_version(&version);
    if normalized_version.is_empty() {
        return Err("Missing installer version to dismiss.".to_string());
    }

    let mut settings = load_settings().await?;
    settings.dismissed_app_update_version = Some(normalized_version);
    save_settings(settings).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_release_version_strips_v_prefix() {
        assert_eq!(normalize_release_version("v1.2.3"), "1.2.3");
        assert_eq!(normalize_release_version(" V2.0.0 "), "2.0.0");
    }

    #[test]
    fn newer_version_comparison_handles_multi_digit_segments() {
        assert!(is_newer_version("1.0.10", "1.0.2"));
        assert!(is_newer_version("2.0.0", "1.9.9"));
        assert!(!is_newer_version("1.0.1", "1.0.1"));
        assert!(!is_newer_version("0.9.9", "1.0.0"));
    }

    #[test]
    fn pick_download_url_prefers_windows_installer_assets() {
        let release = GitHubRelease {
            tag_name: "v1.2.0".to_string(),
            html_url: "https://github.com/example/release".to_string(),
            published_at: None,
            assets: vec![
                GitHubReleaseAsset {
                    name: "notes.txt".to_string(),
                    browser_download_url: "https://example.com/notes.txt".to_string(),
                },
                GitHubReleaseAsset {
                    name: "InSecurity_1.2.0_x64-setup.exe".to_string(),
                    browser_download_url: "https://example.com/InSecurity_1.2.0.exe".to_string(),
                },
            ],
        };

        assert_eq!(
            pick_download_url(&release),
            "https://example.com/InSecurity_1.2.0.exe"
        );
    }

    #[test]
    fn pick_download_url_falls_back_to_release_page() {
        let release = GitHubRelease {
            tag_name: "v1.2.0".to_string(),
            html_url: "https://github.com/example/release".to_string(),
            published_at: None,
            assets: vec![],
        };

        assert_eq!(
            pick_download_url(&release),
            "https://github.com/example/release"
        );
    }
}
