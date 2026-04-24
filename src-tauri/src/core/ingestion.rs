//! Stage 0: File Ingestion and Metadata Extraction
//! Handles hash extraction, file metadata collection, and initial file analysis
use crate::core::utils::{calculate_file_sha256, calculate_md5, calculate_sha256};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Quickly compute file hash without full metadata extraction
/// Uses streaming to handle large files efficiently
/// Used for cache lookups before running expensive pipeline stages
#[must_use = "hash result should be used for cache lookups"]
pub fn compute_file_hash(file_path: &str) -> Result<String, Box<dyn std::error::Error>> {
    calculate_file_sha256(file_path).map_err(|e| e.into())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    pub file_path: String,
    pub file_name: String,
    pub sha256_hash: String,
    pub md5_hash: String,
    pub file_size: u64,
    pub file_type: String,
    pub packer_flags: Vec<String>,
    pub embedded_objects: Vec<String>,
    pub created_at: i64,
    pub modified_at: i64,
}

/// Result of file ingestion containing both metadata and content
/// This avoids reading the file twice in the pipeline
#[must_use = "ingestion result contains file content and should not be discarded"]
pub struct IngestionResult {
    pub metadata: FileMetadata,
    pub content: Vec<u8>,
}

/// Extract file hash, metadata, and content in a single read
/// Returns both so the pipeline doesn't need to re-read the file
///
/// If `precomputed_sha256` is provided, the SHA256 hash is reused instead of
/// being recomputed from the file content. This avoids a redundant full-file
/// hash when the pipeline already computed it in an earlier stage.
pub fn ingest_file(file_path: &str) -> Result<IngestionResult, Box<dyn std::error::Error>> {
    ingest_file_with_hash(file_path, None)
}

pub fn ingest_file_with_hash(
    file_path: &str,
    precomputed_sha256: Option<&str>,
) -> Result<IngestionResult, Box<dyn std::error::Error>> {
    let path = Path::new(file_path);

    let file_content = fs::read(path)?;

    let sha256_hash = match precomputed_sha256 {
        Some(hash) if !hash.is_empty() => hash.to_string(),
        _ => calculate_sha256(&file_content),
    };
    let md5_hash = calculate_md5(&file_content);

    let fs_metadata = fs::metadata(path)?;
    let file_size = fs_metadata.len();

    let file_type = determine_file_type(&file_content, path);

    let created_at = fs_metadata
        .created()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let modified_at = fs_metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let mut packer_flags = Vec::new();
    if file_content.windows(4).any(|w| w == b"UPX!") {
        packer_flags.push("UPX".to_string());
    }
    if file_content.windows(8).any(|w| w == b"VMProtect") {
        packer_flags.push("VMProtect".to_string());
    }
    if file_content.windows(5).any(|w| w == b"ASPack") {
        packer_flags.push("ASPack".to_string());
    }

    let mut embedded_objects = Vec::new();
    if file_content.windows(4).any(|w| w == b"%PDF") {
        embedded_objects.push("PDF".to_string());
    }
    if file_content.len() >= 8 && &file_content[0..8] == b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1" {
        embedded_objects.push("OLE".to_string());
    }
    if file_content.starts_with(b"#!") {
        embedded_objects.push("script_shebang".to_string());
    }

    let metadata = FileMetadata {
        file_path: file_path.to_string(),
        file_name: path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string(),
        sha256_hash,
        md5_hash,
        file_size,
        file_type,
        packer_flags,
        embedded_objects,
        created_at,
        modified_at,
    };

    Ok(IngestionResult {
        metadata,
        content: file_content,
    })
}

fn determine_file_type(content: &[u8], path: &Path) -> String {
    if content.len() >= 2 {
        match &content[0..2] {
            b"MZ" => return "PE".to_string(),
            b"PK" => return "ZIP".to_string(),
            b"\x7fE" => return "ELF".to_string(),
            _ => {}
        }
    }

    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|s| s.to_uppercase())
        .unwrap_or_else(|| "UNKNOWN".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_calculation() {
        let data = b"test";
        let hash = calculate_sha256(data);
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_determine_file_type_pe() {
        let content = b"MZ\x90\x00\x03\x00\x00\x00";
        let path = Path::new("test.exe");
        assert_eq!(determine_file_type(content, path), "PE");
    }

    #[test]
    fn test_determine_file_type_zip() {
        let content = b"PK\x03\x04\x14\x00";
        let path = Path::new("test.zip");
        assert_eq!(determine_file_type(content, path), "ZIP");
    }

    #[test]
    fn test_determine_file_type_elf() {
        let content = b"\x7fELF\x02\x01\x01";
        let path = Path::new("test.bin");
        assert_eq!(determine_file_type(content, path), "ELF");
    }

    #[test]
    fn test_determine_file_type_by_extension() {
        let content = b"random content without magic bytes";
        let path = Path::new("test.xyz");
        assert_eq!(determine_file_type(content, path), "XYZ");
    }

    #[test]
    fn test_determine_file_type_no_extension() {
        let content = b"random content";
        let path = Path::new("noext");
        assert_eq!(determine_file_type(content, path), "UNKNOWN");
    }

    #[test]
    fn test_determine_file_type_empty_content() {
        let content: &[u8] = b"";
        let path = Path::new("empty.dll");
        assert_eq!(determine_file_type(content, path), "DLL");
    }

    #[test]
    fn test_determine_file_type_single_byte() {
        let content = b"M"; // Only one byte, not enough for MZ
        let path = Path::new("test.exe");
        assert_eq!(determine_file_type(content, path), "EXE");
    }

    #[test]
    fn test_compute_file_hash_real_file() {
        let dir = std::env::temp_dir().join("insecurity_test_ingestion");
        let _ = std::fs::create_dir_all(&dir);
        let file = dir.join("test_hash.bin");
        std::fs::write(&file, b"hello").unwrap();

        let hash = compute_file_hash(file.to_str().unwrap()).unwrap();
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_compute_file_hash_nonexistent() {
        assert!(compute_file_hash("nonexistent_file_xyz.exe").is_err());
    }
}
