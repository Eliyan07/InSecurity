//! EMBER Feature Extractor for LightGBM Malware Classifier
//!
//! Extracts 2,381 features matching the EMBER schema.
//!
//! Feature Groups:
//! - ByteHistogram (256): Byte value distribution
//! - ByteEntropyHistogram (256): Entropy per byte value
//! - StringExtractor (104): String statistics
//! - GeneralFileInfo (10): File size, virtual size, etc.
//! - HeaderFileInfo (62): PE header fields
//! - SectionInfo (255): Section statistics (5 sections × 51 features)
//! - ImportsInfo (1280): Import statistics (256 libraries × 5 features)
//! - ExportsInfo (128): Export statistics
//! - DataDirectories (30): Data directory entries

use crate::core::utils::calculate_entropy;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

pub const EMBER_FEATURE_COUNT: usize = 2381;

pub const EMBER_SCHEMA_VERSION: &str = "2018";

pub struct EmberExtractor {
    features: Vec<f64>,
}

impl Default for EmberExtractor {
    fn default() -> Self {
        Self::new()
    }
}

impl EmberExtractor {
    pub fn new() -> Self {
        Self {
            features: vec![0.0; EMBER_FEATURE_COUNT],
        }
    }

    /// Extract all 2,381 EMBER features from a file path
    /// Note: If you already have the file content, use `extract_from_bytes` instead
    /// to avoid redundant file I/O.
    pub fn extract(&mut self, file_path: &str) -> Result<Vec<f64>, Box<dyn std::error::Error>> {
        let path = Path::new(file_path);
        let content = fs::read(path)?;
        Ok(self.extract_from_bytes(&content))
    }

    /// Extract all 2,381 EMBER features from file content bytes
    /// This is more efficient when you already have the file content in memory,
    /// as it avoids redundant file I/O.
    pub fn extract_from_bytes(&mut self, content: &[u8]) -> Vec<f64> {
        self.features = vec![0.0; EMBER_FEATURE_COUNT];

        let mut offset = 0;

        // 1. ByteHistogram (256 features) - indices 0-255
        offset = self.extract_byte_histogram(content, offset);

        // 2. ByteEntropyHistogram (256 features) - indices 256-511
        offset = self.extract_byte_entropy_histogram(content, offset);

        // 3. StringExtractor (104 features) - indices 512-615
        offset = self.extract_string_features(content, offset);

        // 4. GeneralFileInfo (10 features) - indices 616-625
        offset = self.extract_general_info(content, offset);

        // 5. HeaderFileInfo (62 features) - indices 626-687
        offset = self.extract_header_info(content, offset);

        // 6. SectionInfo (255 features) - indices 688-942
        offset = self.extract_section_info(content, offset);

        // 7. ImportsInfo (1280 features) - indices 943-2222
        offset = self.extract_imports_info(content, offset);

        // 8. ExportsInfo (128 features) - indices 2223-2350
        offset = self.extract_exports_info(content, offset);

        // 9. DataDirectories (30 features) - indices 2351-2380
        let _ = self.extract_data_directories(content, offset);

        self.features.clone()
    }

    /// ByteHistogram: 256 features representing byte value distribution
    fn extract_byte_histogram(&mut self, content: &[u8], offset: usize) -> usize {
        let mut histogram = [0u64; 256];

        for &byte in content {
            histogram[byte as usize] += 1;
        }

        let total = content.len() as f64;
        if total > 0.0 {
            for (i, &count) in histogram.iter().enumerate() {
                self.features[offset + i] = count as f64 / total;
            }
        }

        offset + 256
    }

    /// ByteEntropyHistogram: 256 features - entropy contribution per byte value
    fn extract_byte_entropy_histogram(&mut self, content: &[u8], offset: usize) -> usize {
        let mut histogram = [0u64; 256];

        for &byte in content {
            histogram[byte as usize] += 1;
        }

        let total = content.len() as f64;
        if total > 0.0 {
            for (i, &count) in histogram.iter().enumerate() {
                if count > 0 {
                    let p = count as f64 / total;
                    // Entropy contribution: -p * log2(p)
                    self.features[offset + i] = -p * p.log2();
                }
            }
        }

        offset + 256
    }

    /// StringExtractor: 104 features for string analysis
    fn extract_string_features(&mut self, content: &[u8], offset: usize) -> usize {
        let mut printable_count = 0u64;
        let mut string_lengths: Vec<usize> = Vec::new();
        let mut current_string_len = 0;

        for &byte in content {
            if (0x20..0x7F).contains(&byte) {
                printable_count += 1;
                current_string_len += 1;
            } else {
                if current_string_len >= 4 {
                    string_lengths.push(current_string_len);
                }
                current_string_len = 0;
            }
        }
        if current_string_len >= 4 {
            string_lengths.push(current_string_len);
        }

        // Feature 0: Number of strings
        self.features[offset] = string_lengths.len() as f64;

        // Feature 1: Average string length
        if !string_lengths.is_empty() {
            let avg_len: f64 =
                string_lengths.iter().sum::<usize>() as f64 / string_lengths.len() as f64;
            self.features[offset + 1] = avg_len;
        }

        // Feature 2: Printable ratio
        if !content.is_empty() {
            self.features[offset + 2] = printable_count as f64 / content.len() as f64;
        }

        // Features 3-102: String length histogram (binned)
        // Bin string lengths: 4-5, 6-7, 8-9, ..., 202-203 (100 bins)
        for len in &string_lengths {
            let bin = (*len - 4) / 2;
            if bin < 100 {
                self.features[offset + 3 + bin] += 1.0;
            }
        }

        // Feature 103: Entropy of strings
        self.features[offset + 103] = calculate_entropy(content);

        offset + 104
    }

    /// GeneralFileInfo: 10 basic file features
    fn extract_general_info(&mut self, content: &[u8], offset: usize) -> usize {
        let file_size = content.len() as f64;

        // Feature 0: File size (log-scaled)
        self.features[offset] = (file_size + 1.0).ln();

        // Feature 1: Virtual size (from PE if available)
        self.features[offset + 1] = 0.0; // Will be set in PE parsing

        // Feature 2: Has debug info
        self.features[offset + 2] = 0.0;

        // Feature 3: Export count
        self.features[offset + 3] = 0.0;

        // Feature 4: Import count
        self.features[offset + 4] = 0.0;

        // Feature 5: Has resources
        self.features[offset + 5] = 0.0;

        // Feature 6: Has signature
        self.features[offset + 6] = 0.0;

        // Feature 7: Has TLS
        self.features[offset + 7] = 0.0;

        // Feature 8: Has relocations
        self.features[offset + 8] = 0.0;

        // Feature 9: Symbol count
        self.features[offset + 9] = 0.0;

        if content.len() >= 64 && &content[0..2] == b"MZ" {
            self.parse_pe_general_info(content, offset);
        }

        offset + 10
    }

    fn parse_pe_general_info(&mut self, content: &[u8], offset: usize) {
        if content.len() < 64 {
            return;
        }

        let pe_offset =
            u32::from_le_bytes([content[60], content[61], content[62], content[63]]) as usize;

        if pe_offset + 248 > content.len() {
            return;
        }

        if &content[pe_offset..pe_offset + 4] != b"PE\0\0" {
            return;
        }

        let opt_header_offset = pe_offset + 24;
        if opt_header_offset + 96 > content.len() {
            return;
        }

        // Virtual size (SizeOfImage)
        if opt_header_offset + 60 <= content.len() {
            let size_of_image = u32::from_le_bytes([
                content[opt_header_offset + 56],
                content[opt_header_offset + 57],
                content[opt_header_offset + 58],
                content[opt_header_offset + 59],
            ]);
            self.features[offset + 1] = (size_of_image as f64 + 1.0).ln();
        }
    }

    /// HeaderFileInfo: 62 PE header features
    fn extract_header_info(&mut self, content: &[u8], offset: usize) -> usize {
        if content.len() < 64 || &content[0..2] != b"MZ" {
            return offset + 62;
        }

        let pe_offset =
            u32::from_le_bytes([content[60], content[61], content[62], content[63]]) as usize;

        if pe_offset + 24 > content.len() {
            return offset + 62;
        }

        if &content[pe_offset..pe_offset + 4] != b"PE\0\0" {
            return offset + 62;
        }

        let coff_offset = pe_offset + 4;

        if coff_offset + 2 <= content.len() {
            let machine = u16::from_le_bytes([content[coff_offset], content[coff_offset + 1]]);
            self.features[offset] = machine as f64;
            // Is 64-bit
            self.features[offset + 1] = if machine == 0x8664 { 1.0 } else { 0.0 };
        }

        if coff_offset + 4 <= content.len() {
            let num_sections =
                u16::from_le_bytes([content[coff_offset + 2], content[coff_offset + 3]]);
            self.features[offset + 2] = num_sections as f64;
        }

        if coff_offset + 8 <= content.len() {
            let timestamp = u32::from_le_bytes([
                content[coff_offset + 4],
                content[coff_offset + 5],
                content[coff_offset + 6],
                content[coff_offset + 7],
            ]);
            self.features[offset + 3] = timestamp as f64;
        }

        if coff_offset + 22 <= content.len() {
            let characteristics =
                u16::from_le_bytes([content[coff_offset + 18], content[coff_offset + 19]]);
            // Extract individual characteristic flags
            self.features[offset + 4] = if characteristics & 0x0002 != 0 {
                1.0
            } else {
                0.0
            }; // Executable
            self.features[offset + 5] = if characteristics & 0x0020 != 0 {
                1.0
            } else {
                0.0
            }; // Large address
            self.features[offset + 6] = if characteristics & 0x0100 != 0 {
                1.0
            } else {
                0.0
            }; // 32-bit
            self.features[offset + 7] = if characteristics & 0x2000 != 0 {
                1.0
            } else {
                0.0
            }; // DLL
        }

        let opt_offset = coff_offset + 20;
        if opt_offset + 96 <= content.len() {
            let magic = u16::from_le_bytes([content[opt_offset], content[opt_offset + 1]]);
            self.features[offset + 8] = magic as f64;

            self.features[offset + 9] = content[opt_offset + 2] as f64;
            self.features[offset + 10] = content[opt_offset + 3] as f64;

            let size_of_code = u32::from_le_bytes([
                content[opt_offset + 4],
                content[opt_offset + 5],
                content[opt_offset + 6],
                content[opt_offset + 7],
            ]);
            self.features[offset + 11] = (size_of_code as f64 + 1.0).ln();

            let size_init_data = u32::from_le_bytes([
                content[opt_offset + 8],
                content[opt_offset + 9],
                content[opt_offset + 10],
                content[opt_offset + 11],
            ]);
            self.features[offset + 12] = (size_init_data as f64 + 1.0).ln();

            let size_uninit_data = u32::from_le_bytes([
                content[opt_offset + 12],
                content[opt_offset + 13],
                content[opt_offset + 14],
                content[opt_offset + 15],
            ]);
            self.features[offset + 13] = (size_uninit_data as f64 + 1.0).ln();

            let entry_point = u32::from_le_bytes([
                content[opt_offset + 16],
                content[opt_offset + 17],
                content[opt_offset + 18],
                content[opt_offset + 19],
            ]);
            self.features[offset + 14] = entry_point as f64;

            self.features[offset + 15] =
                u16::from_le_bytes([content[opt_offset + 68], content[opt_offset + 69]]) as f64;

            let dll_characteristics =
                u16::from_le_bytes([content[opt_offset + 70], content[opt_offset + 71]]);
            self.features[offset + 16] = if dll_characteristics & 0x0040 != 0 {
                1.0
            } else {
                0.0
            }; // DYNAMIC_BASE
            self.features[offset + 17] = if dll_characteristics & 0x0100 != 0 {
                1.0
            } else {
                0.0
            }; // NX_COMPAT
            self.features[offset + 18] = if dll_characteristics & 0x0400 != 0 {
                1.0
            } else {
                0.0
            }; // NO_SEH
            self.features[offset + 19] = if dll_characteristics & 0x8000 != 0 {
                1.0
            } else {
                0.0
            }; // TERMINAL_SERVER
        }

        offset + 62
    }

    /// SectionInfo: 255 features for section analysis (5 sections × 51 features each)
    fn extract_section_info(&mut self, content: &[u8], offset: usize) -> usize {
        if content.len() < 64 || &content[0..2] != b"MZ" {
            return offset + 255;
        }

        let pe_offset =
            u32::from_le_bytes([content[60], content[61], content[62], content[63]]) as usize;

        if pe_offset + 24 > content.len() {
            return offset + 255;
        }

        let num_sections =
            u16::from_le_bytes([content[pe_offset + 6], content[pe_offset + 7]]) as usize;

        let opt_header_size =
            u16::from_le_bytes([content[pe_offset + 20], content[pe_offset + 21]]) as usize;

        let section_table_offset = pe_offset + 24 + opt_header_size;

        for i in 0..std::cmp::min(num_sections, 5) {
            let section_offset = section_table_offset + i * 40;
            if section_offset + 40 > content.len() {
                break;
            }

            let feature_base = offset + i * 51;

            // Section name (8 bytes) - hash to single feature
            let name_bytes = &content[section_offset..section_offset + 8];
            self.features[feature_base] = Self::simple_hash(name_bytes) as f64;

            // Virtual size
            let virtual_size = u32::from_le_bytes([
                content[section_offset + 8],
                content[section_offset + 9],
                content[section_offset + 10],
                content[section_offset + 11],
            ]);
            self.features[feature_base + 1] = (virtual_size as f64 + 1.0).ln();

            // Virtual address
            let virtual_addr = u32::from_le_bytes([
                content[section_offset + 12],
                content[section_offset + 13],
                content[section_offset + 14],
                content[section_offset + 15],
            ]);
            self.features[feature_base + 2] = virtual_addr as f64;

            // Raw size
            let raw_size = u32::from_le_bytes([
                content[section_offset + 16],
                content[section_offset + 17],
                content[section_offset + 18],
                content[section_offset + 19],
            ]);
            self.features[feature_base + 3] = (raw_size as f64 + 1.0).ln();

            // Raw pointer
            let raw_ptr = u32::from_le_bytes([
                content[section_offset + 20],
                content[section_offset + 21],
                content[section_offset + 22],
                content[section_offset + 23],
            ]);
            self.features[feature_base + 4] = raw_ptr as f64;

            // Characteristics
            let characteristics = u32::from_le_bytes([
                content[section_offset + 36],
                content[section_offset + 37],
                content[section_offset + 38],
                content[section_offset + 39],
            ]);

            // Parse section characteristics
            self.features[feature_base + 5] = if characteristics & 0x00000020 != 0 {
                1.0
            } else {
                0.0
            }; // Code
            self.features[feature_base + 6] = if characteristics & 0x00000040 != 0 {
                1.0
            } else {
                0.0
            }; // Initialized data
            self.features[feature_base + 7] = if characteristics & 0x00000080 != 0 {
                1.0
            } else {
                0.0
            }; // Uninitialized data
            self.features[feature_base + 8] = if characteristics & 0x20000000 != 0 {
                1.0
            } else {
                0.0
            }; // Execute
            self.features[feature_base + 9] = if characteristics & 0x40000000 != 0 {
                1.0
            } else {
                0.0
            }; // Read
            self.features[feature_base + 10] = if characteristics & 0x80000000 != 0 {
                1.0
            } else {
                0.0
            }; // Write

            // Section entropy
            if raw_ptr > 0 && raw_size > 0 {
                let start = raw_ptr as usize;
                let end = std::cmp::min(start + raw_size as usize, content.len());
                if start < content.len() && start < end {
                    let section_data = &content[start..end];
                    self.features[feature_base + 11] = calculate_entropy(section_data);
                }
            }

            // Size ratio (virtual/raw)
            if raw_size > 0 {
                self.features[feature_base + 12] = virtual_size as f64 / raw_size as f64;
            }

            // Suspicious section name detection
            let name_str = String::from_utf8_lossy(name_bytes).to_lowercase();
            self.features[feature_base + 13] = if Self::is_suspicious_section(&name_str) {
                1.0
            } else {
                0.0
            };

            // Fill remaining per-section features with zeros or derived values
            // Features 14-50 are reserved for additional section analysis
        }

        offset + 255
    }

    /// ImportsInfo: 1280 features for import analysis
    fn extract_imports_info(&mut self, content: &[u8], offset: usize) -> usize {
        // For EMBER compatibility, we use hashed import features
        // 256 library bins × 5 features each = 1280 features

        if content.len() < 64 || &content[0..2] != b"MZ" {
            return offset + 1280;
        }

        let imports = self.parse_imports(content);

        for (dll_name, functions) in imports.iter() {
            let bin = Self::simple_hash(dll_name.as_bytes()) as usize % 256;
            let feature_base = offset + bin * 5;

            // Feature 0: DLL present
            self.features[feature_base] = 1.0;

            // Feature 1: Function count
            self.features[feature_base + 1] += functions.len() as f64;

            // Feature 2: Has suspicious functions
            let suspicious_count = functions
                .iter()
                .filter(|f| Self::is_suspicious_import(f))
                .count();
            self.features[feature_base + 2] += suspicious_count as f64;

            // Feature 3: Average function name length
            if !functions.is_empty() {
                let avg_len: f64 =
                    functions.iter().map(|f| f.len() as f64).sum::<f64>() / functions.len() as f64;
                self.features[feature_base + 3] = avg_len;
            }

            // Feature 4: Ordinal import ratio
            let ordinal_count = functions.iter().filter(|f| f.starts_with('#')).count();
            if !functions.is_empty() {
                self.features[feature_base + 4] = ordinal_count as f64 / functions.len() as f64;
            }
        }

        offset + 1280
    }

    fn parse_imports(&self, content: &[u8]) -> HashMap<String, Vec<String>> {
        let mut imports: HashMap<String, Vec<String>> = HashMap::new();

        if content.len() < 64 {
            return imports;
        }

        let pe_offset =
            u32::from_le_bytes([content[60], content[61], content[62], content[63]]) as usize;

        if pe_offset + 120 > content.len() {
            return imports;
        }

        // Check PE32 vs PE32+
        let opt_offset = pe_offset + 24;
        if opt_offset + 2 > content.len() {
            return imports;
        }
        let magic = u16::from_le_bytes([content[opt_offset], content[opt_offset + 1]]);
        let is_pe32_plus = magic == 0x20b;

        // Import directory RVA location depends on PE32/PE32+
        let import_dir_offset = if is_pe32_plus {
            opt_offset + 120 // PE32+
        } else {
            opt_offset + 104 // PE32
        };

        if import_dir_offset + 8 > content.len() {
            return imports;
        }

        let import_rva = u32::from_le_bytes([
            content[import_dir_offset],
            content[import_dir_offset + 1],
            content[import_dir_offset + 2],
            content[import_dir_offset + 3],
        ]) as usize;

        if import_rva == 0 {
            return imports;
        }

        let import_offset = self.rva_to_offset(content, import_rva);
        if import_offset == 0 || import_offset + 20 > content.len() {
            return imports;
        }

        let mut desc_offset = import_offset;
        for _ in 0..256 {
            if desc_offset + 20 > content.len() {
                break;
            }

            let name_rva = u32::from_le_bytes([
                content[desc_offset + 12],
                content[desc_offset + 13],
                content[desc_offset + 14],
                content[desc_offset + 15],
            ]) as usize;

            if name_rva == 0 {
                break;
            }

            // Get DLL name
            let name_offset = self.rva_to_offset(content, name_rva);
            if name_offset > 0 && name_offset < content.len() {
                let mut dll_name = String::new();
                for i in 0..256 {
                    if name_offset + i >= content.len() {
                        break;
                    }
                    let c = content[name_offset + i];
                    if c == 0 {
                        break;
                    }
                    dll_name.push(c as char);
                }

                if !dll_name.is_empty() {
                    imports.entry(dll_name.to_lowercase()).or_default();
                }
            }

            desc_offset += 20;
        }

        imports
    }

    fn rva_to_offset(&self, content: &[u8], rva: usize) -> usize {
        if content.len() < 64 {
            return 0;
        }

        let pe_offset =
            u32::from_le_bytes([content[60], content[61], content[62], content[63]]) as usize;

        if pe_offset + 24 > content.len() {
            return 0;
        }

        let num_sections =
            u16::from_le_bytes([content[pe_offset + 6], content[pe_offset + 7]]) as usize;

        let opt_header_size =
            u16::from_le_bytes([content[pe_offset + 20], content[pe_offset + 21]]) as usize;

        let section_table = pe_offset + 24 + opt_header_size;

        for i in 0..num_sections {
            let section_offset = section_table + i * 40;
            if section_offset + 40 > content.len() {
                break;
            }

            let virtual_addr = u32::from_le_bytes([
                content[section_offset + 12],
                content[section_offset + 13],
                content[section_offset + 14],
                content[section_offset + 15],
            ]) as usize;

            let virtual_size = u32::from_le_bytes([
                content[section_offset + 8],
                content[section_offset + 9],
                content[section_offset + 10],
                content[section_offset + 11],
            ]) as usize;

            let raw_ptr = u32::from_le_bytes([
                content[section_offset + 20],
                content[section_offset + 21],
                content[section_offset + 22],
                content[section_offset + 23],
            ]) as usize;

            if rva >= virtual_addr && rva < virtual_addr + virtual_size {
                return raw_ptr + (rva - virtual_addr);
            }
        }

        rva
    }

    /// ExportsInfo: 128 features for export analysis
    fn extract_exports_info(&mut self, content: &[u8], offset: usize) -> usize {
        if content.len() < 64 || &content[0..2] != b"MZ" {
            return offset + 128;
        }

        // Feature 0: Has exports
        // Feature 1: Export count
        // Features 2-127: Hashed export names

        // Simplified: just detect if file has exports
        let pe_offset =
            u32::from_le_bytes([content[60], content[61], content[62], content[63]]) as usize;

        if pe_offset + 120 > content.len() {
            return offset + 128;
        }

        let opt_offset = pe_offset + 24;
        let magic = u16::from_le_bytes([content[opt_offset], content[opt_offset + 1]]);
        let is_pe32_plus = magic == 0x20b;

        let export_dir_offset = if is_pe32_plus {
            opt_offset + 112
        } else {
            opt_offset + 96
        };

        if export_dir_offset + 4 <= content.len() {
            let export_rva = u32::from_le_bytes([
                content[export_dir_offset],
                content[export_dir_offset + 1],
                content[export_dir_offset + 2],
                content[export_dir_offset + 3],
            ]);

            if export_rva > 0 {
                self.features[offset] = 1.0;
            }
        }

        offset + 128
    }

    /// DataDirectories: 30 features for data directory analysis
    fn extract_data_directories(&mut self, content: &[u8], offset: usize) -> usize {
        if content.len() < 64 || &content[0..2] != b"MZ" {
            return offset + 30;
        }

        let pe_offset =
            u32::from_le_bytes([content[60], content[61], content[62], content[63]]) as usize;

        if pe_offset + 24 > content.len() {
            return offset + 30;
        }

        let opt_offset = pe_offset + 24;
        let magic = u16::from_le_bytes([content[opt_offset], content[opt_offset + 1]]);
        let is_pe32_plus = magic == 0x20b;

        let dd_offset = if is_pe32_plus {
            opt_offset + 112
        } else {
            opt_offset + 96
        };

        for i in 0..15 {
            let entry_offset = dd_offset + i * 8;
            if entry_offset + 8 > content.len() {
                break;
            }

            let rva = u32::from_le_bytes([
                content[entry_offset],
                content[entry_offset + 1],
                content[entry_offset + 2],
                content[entry_offset + 3],
            ]);

            let size = u32::from_le_bytes([
                content[entry_offset + 4],
                content[entry_offset + 5],
                content[entry_offset + 6],
                content[entry_offset + 7],
            ]);

            self.features[offset + i * 2] = if rva > 0 { 1.0 } else { 0.0 };
            self.features[offset + i * 2 + 1] = (size as f64 + 1.0).ln();
        }

        offset + 30
    }

    fn simple_hash(data: &[u8]) -> u32 {
        let mut hash: u32 = 5381;
        for &byte in data {
            hash = hash.wrapping_mul(33).wrapping_add(byte as u32);
        }
        hash
    }

    fn is_suspicious_section(name: &str) -> bool {
        const SUSPICIOUS: &[&str] = &[
            "upx", ".upx", "upx0", "upx1", "upx2", "aspack", ".aspack", "adata", "mpress",
            ".mpress", "petite", ".petite", "enigma", ".enigma", "themida", ".themida", "vmp",
            ".vmp", "vmprote", "packed", ".packed", "crypted", ".crypted", "nsp", ".nsp", "pec",
            ".pec",
        ];

        let lower = name.trim_end_matches('\0').to_lowercase();
        SUSPICIOUS.iter().any(|s| lower.contains(s))
    }

    fn is_suspicious_import(name: &str) -> bool {
        const SUSPICIOUS: &[&str] = &[
            "virtualalloc",
            "virtualallocex",
            "virtualprotect",
            "writeprocessmemory",
            "readprocessmemory",
            "createremotethread",
            "ntcreatethreadex",
            "setwindowshookex",
            "getasynckeystate",
            "createprocess",
            "shellexecute",
            "winexec",
            "regsetvalue",
            "regcreatekey",
            "internetopen",
            "urldownloadtofile",
            "cryptencrypt",
            "cryptdecrypt",
            "isdebuggerpresent",
            "ntqueryinformationprocess",
            "loadlibrary",
            "getprocaddress",
            "adjusttokenprivileges",
        ];

        let lower = name.to_lowercase();
        SUSPICIOUS.iter().any(|s| lower.contains(s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ember_feature_count() {
        let extractor = EmberExtractor::new();
        assert_eq!(extractor.features.len(), EMBER_FEATURE_COUNT);
    }

    #[test]
    fn test_entropy_calculation() {
        // All same bytes = 0 entropy
        let uniform = vec![0u8; 1000];
        let entropy = calculate_entropy(&uniform);
        assert!((entropy - 0.0).abs() < 0.001);

        // Random-like data = high entropy
        let random: Vec<u8> = (0..=255).collect();
        let entropy = calculate_entropy(&random);
        assert!(entropy > 7.9);
    }

    #[test]
    fn test_extract_from_bytes_empty() {
        let mut extractor = EmberExtractor::new();
        let features = extractor.extract_from_bytes(&[]);
        assert_eq!(features.len(), EMBER_FEATURE_COUNT);
        // All features should be 0 for empty input
        assert!(features.iter().all(|&f| f == 0.0));
    }

    #[test]
    fn test_extract_from_bytes_single_byte() {
        let mut extractor = EmberExtractor::new();
        let features = extractor.extract_from_bytes(&[0x41]);
        assert_eq!(features.len(), EMBER_FEATURE_COUNT);
        // Byte 0x41 (index 65) should be 1.0 in histogram
        assert!((features[65] - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_extract_from_bytes_pe_header() {
        let mut extractor = EmberExtractor::new();
        // Minimal PE-like content starting with MZ
        let mut content = vec![0x4D, 0x5A]; // MZ
        content.extend(vec![0u8; 200]); // Padding
        let features = extractor.extract_from_bytes(&content);
        assert_eq!(features.len(), EMBER_FEATURE_COUNT);
    }

    #[test]
    fn test_extract_resets_features() {
        let mut extractor = EmberExtractor::new();
        // First extraction
        let _f1 = extractor.extract_from_bytes(&[0xFF; 100]);
        // Second extraction with different data
        let f2 = extractor.extract_from_bytes(&[0x00; 100]);
        // The byte 0xFF histogram entry (index 255) should be 0 in f2
        assert!((f2[255] - 0.0).abs() < 0.001);
        // The byte 0x00 histogram entry (index 0) should be 1.0 in f2
        assert!((f2[0] - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_default_extractor() {
        let extractor = EmberExtractor::default();
        assert_eq!(extractor.features.len(), EMBER_FEATURE_COUNT);
    }

    #[test]
    fn test_extract_nonexistent_file() {
        let mut extractor = EmberExtractor::new();
        let result = extractor.extract("/nonexistent/path/file.exe");
        assert!(result.is_err());
    }
}
