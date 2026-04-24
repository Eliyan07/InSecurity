use super::update_manager::MalwareBazaarEntry;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatEntry {
    pub hash: String,
    pub name: String,
    pub severity: String,
    pub family: Option<String>,
    pub first_seen: Option<i64>,
}

impl ThreatEntry {
    pub fn normalize_first_seen(&self) -> i64 {
        self.first_seen
            .unwrap_or_else(|| chrono::Utc::now().timestamp())
    }

    pub fn from_malware_bazaar(entry: &MalwareBazaarEntry) -> Self {
        let severity = if entry
            .tags
            .as_ref()
            .map(|tags| {
                tags.iter().any(|tag| {
                    let tag = tag.to_lowercase();
                    tag.contains("ransomware") || tag.contains("rat")
                })
            })
            .unwrap_or(false)
        {
            "critical"
        } else {
            "high"
        };

        let family = entry.signature.clone();

        Self {
            hash: entry.sha256_hash.to_lowercase(),
            name: family.clone().unwrap_or_else(|| "Unknown".to_string()),
            severity: severity.to_string(),
            family,
            first_seen: None,
        }
    }
}

impl From<&MalwareBazaarEntry> for ThreatEntry {
    fn from(entry: &MalwareBazaarEntry) -> Self {
        Self::from_malware_bazaar(entry)
    }
}

pub fn parse_feed_json(body: &str) -> Result<Vec<ThreatEntry>, serde_json::Error> {
    serde_json::from_str(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threat_entry_normalize_first_seen_with_value() {
        let entry = ThreatEntry {
            hash: "abc123".to_string(),
            name: "TestMalware".to_string(),
            severity: "high".to_string(),
            family: Some("Trojan".to_string()),
            first_seen: Some(1000000),
        };
        assert_eq!(entry.normalize_first_seen(), 1000000);
    }

    #[test]
    fn test_threat_entry_normalize_first_seen_none() {
        let entry = ThreatEntry {
            hash: "abc123".to_string(),
            name: "TestMalware".to_string(),
            severity: "high".to_string(),
            family: None,
            first_seen: None,
        };
        let ts = entry.normalize_first_seen();
        let now = chrono::Utc::now().timestamp();
        assert!((now - ts).abs() < 5);
    }

    #[test]
    fn test_from_malware_bazaar_maps_fields() {
        let entry = MalwareBazaarEntry {
            sha256_hash: "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
                .to_string(),
            sha1_hash: None,
            md5_hash: None,
            file_type: Some("exe".to_string()),
            file_type_mime: None,
            signature: Some("AsyncRAT".to_string()),
            tags: Some(vec!["rat".to_string()]),
            intelligence: None,
        };

        let threat = ThreatEntry::from(&entry);

        assert_eq!(
            threat.hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(threat.name, "AsyncRAT");
        assert_eq!(threat.family, Some("AsyncRAT".to_string()));
        assert_eq!(threat.severity, "critical");
    }

    #[test]
    fn test_parse_feed_json_valid() {
        let json = r#"[
            {"hash": "aabb", "name": "Mal1", "severity": "high", "family": "Trojan", "first_seen": 1000},
            {"hash": "ccdd", "name": "Mal2", "severity": "low", "family": null, "first_seen": null}
        ]"#;
        let entries = parse_feed_json(json).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].hash, "aabb");
        assert_eq!(entries[0].name, "Mal1");
        assert_eq!(entries[0].family, Some("Trojan".to_string()));
        assert_eq!(entries[1].family, None);
        assert_eq!(entries[1].first_seen, None);
    }

    #[test]
    fn test_parse_feed_json_empty_array() {
        let entries = parse_feed_json("[]").unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_parse_feed_json_invalid() {
        let result = parse_feed_json("not valid json");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_feed_json_missing_required_field() {
        let json = r#"[{"hash": "aabb", "severity": "high"}]"#;
        let result = parse_feed_json(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_threat_entry_serialization_roundtrip() {
        let entry = ThreatEntry {
            hash: "deadbeef".to_string(),
            name: "Test".to_string(),
            severity: "critical".to_string(),
            family: Some("RAT".to_string()),
            first_seen: Some(999),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: ThreatEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.hash, "deadbeef");
        assert_eq!(deserialized.family, Some("RAT".to_string()));
    }
}
