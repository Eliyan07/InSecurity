//! Novelty Feature Extractor for Isolation Forest Anomaly Detection
//!
//! Extracts 42 behavioral PE features matching `resources/models/novelty/features.json`.
//! The model is an IsolationForest (300 estimators) trained on 26,033 benign PE samples.
//!
//! Feature layout (indices):
//!   [ 0.. 7]  Section entropy statistics (8)
//!   [ 8..15]  Import analysis (8)
//!   [16..18]  Export statistics (3)
//!   [19..28]  PE header anomalies (10)
//!   [29..32]  String analysis (4)
//!   [33..37]  Packer indicators (5)
//!   [38..41]  Size statistics (4)
//!
//! Non-PE files and parse failures return all-zeros (same as EmberExtractor).

use crate::core::utils::calculate_entropy;

pub const NOVELTY_FEATURE_COUNT: usize = 42;

// --- API category sets (lowercase, matching features.py) ---

static NETWORKING_APIS: &[&str] = &[
    "wsastartup",
    "socket",
    "connect",
    "send",
    "recv",
    "bind",
    "listen",
    "accept",
    "gethostbyname",
    "inet_addr",
    "httpsendrequesta",
    "internetopena",
    "internetopenurla",
    "urldownloadtofile",
    "winexec",
    "ftpputfile",
];

static CRYPTO_APIS: &[&str] = &[
    "cryptencrypt",
    "cryptdecrypt",
    "crypthashdata",
    "cryptacquirecontext",
    "cryptgenkey",
    "cryptimportkey",
    "bcryptencrypt",
    "bcryptdecrypt",
];

static PROCESS_APIS: &[&str] = &[
    "createprocess",
    "openprocess",
    "virtualalloc",
    "virtualallocex",
    "writeprocessmemory",
    "readprocessmemory",
    "createremotethread",
    "ntcreatethreadex",
    "rtlcreateuserthread",
    "terminateprocess",
];

static REGISTRY_APIS: &[&str] = &[
    "regopenkeyex",
    "regsetvalueex",
    "regqueryvalueex",
    "regcreatekeyex",
    "regdeletekey",
    "regdeletevalue",
    "ntsetvaluekey",
    "zwsetvaluekey",
];

static PACKER_SECTION_NAMES: &[&str] = &[
    ".upx", "upx0", "upx1", "upx2", ".aspack", ".adata", ".nsp0", ".nsp1", ".petite", ".mpress",
    ".themida", ".vmp0", ".vmp1", ".vmp2", ".enigma", ".npack", ".wwpack", ".fsg", ".yoda",
];

static NORMAL_SECTION_NAMES: &[&str] = &[
    ".text", ".data", ".rdata", ".bss", ".idata", ".edata", ".rsrc", ".reloc", ".tls", ".pdata",
    "code", "data", ".crt", ".ctors",
];

// ─────────────────────────────────────────────────────────────────────────────

/// Lightweight struct — all state is derived from the byte slice.
pub struct NoveltyExtractor;

impl Default for NoveltyExtractor {
    fn default() -> Self {
        Self
    }
}

impl NoveltyExtractor {
    pub fn new() -> Self {
        Self
    }

    /// Extract 42 novelty features from raw file bytes.
    ///
    /// Returns `vec![0.0; 42]` for non-PE files or parse failures.
    pub fn extract_from_bytes(&self, content: &[u8]) -> Vec<f64> {
        let mut f = vec![0.0f64; NOVELTY_FEATURE_COUNT];
        if content.len() < 64 || &content[0..2] != b"MZ" {
            return f;
        }
        let Some(layout) = PeLayout::parse(content) else {
            return f;
        };

        self.section_features(content, &layout, &mut f); //  0.. 7
        self.import_features(content, &layout, &mut f); //  8..15
        self.export_features(content, &layout, &mut f); // 16..18
        self.header_features(content, &layout, &mut f); // 19..28
        self.string_features(content, &mut f); // 29..32
        self.packer_features(content, &layout, &mut f); // 33..37
        self.size_features(content, &layout, &mut f); // 38..41
        f
    }

    // ── Section entropy statistics [0..7] ────────────────────────────────────

    fn section_features(&self, content: &[u8], layout: &PeLayout, f: &mut Vec<f64>) {
        let mut entropies: Vec<f64> = Vec::new();
        let mut exec_count = 0u32;
        let mut write_count = 0u32;
        let mut abnormal: f64 = 0.0;

        for i in 0..layout.num_sections {
            let sec_off = layout.section_table + i * 40;
            if sec_off + 40 > content.len() {
                break;
            }

            let raw_ptr = u32::from_le_bytes([
                content[sec_off + 20],
                content[sec_off + 21],
                content[sec_off + 22],
                content[sec_off + 23],
            ]) as usize;
            let raw_size = u32::from_le_bytes([
                content[sec_off + 16],
                content[sec_off + 17],
                content[sec_off + 18],
                content[sec_off + 19],
            ]) as usize;
            let chars = u32::from_le_bytes([
                content[sec_off + 36],
                content[sec_off + 37],
                content[sec_off + 38],
                content[sec_off + 39],
            ]);

            if chars & 0x20000000 != 0 {
                exec_count += 1;
            }
            if chars & 0x80000000 != 0 {
                write_count += 1;
            }

            // Section entropy
            if raw_ptr > 0 && raw_size > 0 {
                let start = raw_ptr;
                let end = (raw_ptr + raw_size).min(content.len());
                if start < content.len() {
                    entropies.push(calculate_entropy(&content[start..end]));
                }
            }

            // Section name (8 bytes, null-padded)
            let name_raw = &content[sec_off..sec_off + 8];
            let name = String::from_utf8_lossy(name_raw)
                .trim_matches('\0')
                .to_lowercase();
            let trimmed = name.trim();
            if PACKER_SECTION_NAMES.contains(&trimmed) {
                abnormal += 1.0;
            } else if !trimmed.is_empty() && !NORMAL_SECTION_NAMES.contains(&trimmed) {
                abnormal += 0.5;
            }
        }

        if entropies.is_empty() {
            entropies.push(0.0);
        }

        let mean = entropies.iter().sum::<f64>() / entropies.len() as f64;
        let variance =
            entropies.iter().map(|e| (e - mean).powi(2)).sum::<f64>() / entropies.len() as f64;
        let std = variance.sqrt();
        let max = entropies.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let min = entropies.iter().cloned().fold(f64::INFINITY, f64::min);

        f[0] = mean;
        f[1] = std;
        f[2] = max;
        f[3] = min;
        f[4] = layout.num_sections as f64;
        f[5] = exec_count as f64;
        f[6] = write_count as f64;
        f[7] = abnormal;
    }

    // ── Import analysis [8..15] ───────────────────────────────────────────────

    fn import_features(&self, content: &[u8], layout: &PeLayout, f: &mut Vec<f64>) {
        let dlls = parse_imports(content, layout);

        let mut total_imports = 0u32;
        let mut networking = 0u32;
        let mut crypto = 0u32;
        let mut process = 0u32;
        let mut registry = 0u32;
        let mut suspicious = 0u32;

        for dll in &dlls {
            for func in &dll.functions {
                total_imports += 1;
                if NETWORKING_APIS.contains(&func.as_str()) {
                    networking += 1;
                }
                if CRYPTO_APIS.contains(&func.as_str()) {
                    crypto += 1;
                }
                if PROCESS_APIS.contains(&func.as_str()) {
                    process += 1;
                }
                if REGISTRY_APIS.contains(&func.as_str()) {
                    registry += 1;
                }
                if is_suspicious_import(func) {
                    suspicious += 1;
                }
            }
        }

        let total = total_imports.max(1) as f64;
        let known = (networking + crypto + process + registry) as f64;

        f[8] = total_imports as f64;
        f[9] = dlls.len() as f64;
        f[10] = suspicious as f64 / total;
        f[11] = known / total; // api_rarity_score (ratio of known-category APIs)
        f[12] = networking as f64;
        f[13] = crypto as f64;
        f[14] = process as f64;
        f[15] = registry as f64;
    }

    // ── Export statistics [16..18] ────────────────────────────────────────────

    fn export_features(&self, content: &[u8], layout: &PeLayout, f: &mut Vec<f64>) {
        let opt = layout.opt_offset;
        let dd_base = if layout.is_pe32_plus {
            opt + 112
        } else {
            opt + 96
        };

        // Export directory is data-directory entry 0
        let export_rva = if dd_base + 4 <= content.len() {
            u32::from_le_bytes([
                content[dd_base],
                content[dd_base + 1],
                content[dd_base + 2],
                content[dd_base + 3],
            ])
        } else {
            0
        };

        let mut export_count = 0u32;
        if export_rva > 0 {
            let exp_off = rva_to_offset(content, layout, export_rva as usize);
            // Number of named exports is at offset 24 in the export directory
            if exp_off + 28 <= content.len() {
                export_count = u32::from_le_bytes([
                    content[exp_off + 24],
                    content[exp_off + 25],
                    content[exp_off + 26],
                    content[exp_off + 27],
                ]);
            }
        }

        let import_count = f[8].max(1.0);
        f[16] = export_count as f64;
        f[17] = export_count as f64 / import_count;
        f[18] = if export_rva > 0 { 1.0 } else { 0.0 };
    }

    // ── PE header anomalies [19..28] ─────────────────────────────────────────

    fn header_features(&self, content: &[u8], layout: &PeLayout, f: &mut Vec<f64>) {
        let coff = layout.coff_offset;
        let opt = layout.opt_offset;

        // Timestamp (COFF +4)
        let timestamp = if coff + 8 <= content.len() {
            u32::from_le_bytes([
                content[coff + 4],
                content[coff + 5],
                content[coff + 6],
                content[coff + 7],
            ])
        } else {
            0
        };

        // Y2K epoch = 946684800
        // "Now" approximated as a constant near training time; using 2026-01-01 = 1767225600
        // Any timestamp > 1767225600 is "in the future", < 946684800 is "very old".
        const EPOCH_Y2K: u32 = 946_684_800;
        const EPOCH_NOW: u32 = 1_767_225_600;

        f[19] = if verify_pe_checksum(content) {
            1.0
        } else {
            0.0
        };
        f[20] = if timestamp > EPOCH_NOW { 1.0 } else { 0.0 };
        f[21] = if timestamp < EPOCH_Y2K && timestamp > 0 {
            1.0
        } else {
            0.0
        };

        // Optional header size (COFF +16)
        f[22] = if coff + 18 <= content.len() {
            u16::from_le_bytes([content[coff + 16], content[coff + 17]]) as f64
        } else {
            0.0
        };

        // SectionAlignment (opt +32), FileAlignment (opt +36)
        if opt + 40 <= content.len() {
            f[23] = u32::from_le_bytes([
                content[opt + 32],
                content[opt + 33],
                content[opt + 34],
                content[opt + 35],
            ]) as f64;
            f[24] = u32::from_le_bytes([
                content[opt + 36],
                content[opt + 37],
                content[opt + 38],
                content[opt + 39],
            ]) as f64;
        }

        // Subsystem (opt +68), DllCharacteristics (opt +70)
        if opt + 72 <= content.len() {
            f[25] = u16::from_le_bytes([content[opt + 68], content[opt + 69]]) as f64;
            f[26] = u16::from_le_bytes([content[opt + 70], content[opt + 71]]) as f64;
        }

        // SizeOfCode (opt +4)
        if opt + 8 <= content.len() {
            f[27] = u32::from_le_bytes([
                content[opt + 4],
                content[opt + 5],
                content[opt + 6],
                content[opt + 7],
            ]) as f64;
        }

        // AddressOfEntryPoint (opt +16)
        if opt + 20 <= content.len() {
            f[28] = u32::from_le_bytes([
                content[opt + 16],
                content[opt + 17],
                content[opt + 18],
                content[opt + 19],
            ]) as f64;
        }
    }

    // ── String analysis [29..32] ──────────────────────────────────────────────

    fn string_features(&self, content: &[u8], f: &mut Vec<f64>) {
        // Extract printable ASCII runs of length >= 4
        let mut strings: Vec<Vec<u8>> = Vec::new();
        let mut current: Vec<u8> = Vec::new();

        for &b in content {
            if b >= 0x20 && b < 0x7F {
                current.push(b);
            } else {
                if current.len() >= 4 {
                    strings.push(current.clone());
                }
                current.clear();
            }
        }
        if current.len() >= 4 {
            strings.push(current);
        }

        if strings.is_empty() {
            // f[29..32] stay 0
            return;
        }

        let entropies: Vec<f64> = strings.iter().map(|s| calculate_entropy(s)).collect();
        let mean_ent = entropies.iter().sum::<f64>() / entropies.len() as f64;
        let max_ent = entropies.iter().cloned().fold(0.0_f64, f64::max);

        let total_chars: usize = strings.iter().map(|s| s.len()).sum();
        let printable_ratio = (total_chars as f64 / content.len() as f64).min(1.0);

        let url_count = strings
            .iter()
            .filter(|s| {
                let t = String::from_utf8_lossy(s).to_lowercase();
                t.contains("http://")
                    || t.contains("https://")
                    || t.contains("ftp://")
                    || t.starts_with("www.")
            })
            .count();

        f[29] = mean_ent;
        f[30] = max_ent;
        f[31] = printable_ratio;
        f[32] = url_count.min(100) as f64;
    }

    // ── Packer indicators [33..37] ────────────────────────────────────────────

    fn packer_features(&self, content: &[u8], layout: &PeLayout, f: &mut Vec<f64>) {
        let mut packer_score: f64 = 0.0;
        let mut is_packed: f64 = 0.0;

        // Check section names and entropy
        for i in 0..layout.num_sections {
            let sec = layout.section_table + i * 40;
            if sec + 40 > content.len() {
                break;
            }

            let name_raw = &content[sec..sec + 8];
            let name = String::from_utf8_lossy(name_raw)
                .trim_matches('\0')
                .to_lowercase();
            let trimmed = name.trim();

            if PACKER_SECTION_NAMES.contains(&trimmed) {
                packer_score += 2.0;
                is_packed = 1.0;
            }

            let raw_ptr = u32::from_le_bytes([
                content[sec + 20],
                content[sec + 21],
                content[sec + 22],
                content[sec + 23],
            ]) as usize;
            let raw_size = u32::from_le_bytes([
                content[sec + 16],
                content[sec + 17],
                content[sec + 18],
                content[sec + 19],
            ]) as usize;

            if raw_ptr > 0 && raw_size > 0 {
                let start = raw_ptr;
                let end = (raw_ptr + raw_size).min(content.len());
                if start < content.len() {
                    let ent = calculate_entropy(&content[start..end]);
                    if ent > 7.0 {
                        packer_score += 1.0;
                        is_packed = 1.0;
                    }
                }
            }
        }

        // Overlay: bytes after the last section
        let mut max_section_end: usize = 0;
        for i in 0..layout.num_sections {
            let sec = layout.section_table + i * 40;
            if sec + 40 > content.len() {
                break;
            }
            let raw_ptr = u32::from_le_bytes([
                content[sec + 20],
                content[sec + 21],
                content[sec + 22],
                content[sec + 23],
            ]) as usize;
            let raw_size = u32::from_le_bytes([
                content[sec + 16],
                content[sec + 17],
                content[sec + 18],
                content[sec + 19],
            ]) as usize;
            if raw_ptr > 0 {
                max_section_end = max_section_end.max(raw_ptr + raw_size);
            }
        }

        let (overlay_size_ratio, overlay_entropy) =
            if max_section_end > 0 && max_section_end < content.len() {
                let overlay = &content[max_section_end..];
                let ratio = (overlay.len() as f64 / content.len() as f64).min(1.0);
                let ent = calculate_entropy(overlay);
                (ratio, ent)
            } else {
                (0.0, 0.0)
            };

        // Resource entropy: parse IMAGE_DIRECTORY_ENTRY_RESOURCE (index 2)
        let resource_entropy = self.resource_entropy(content, layout);

        f[33] = is_packed;
        f[34] = packer_score.min(10.0);
        f[35] = overlay_size_ratio;
        f[36] = overlay_entropy;
        f[37] = resource_entropy;
    }

    fn resource_entropy(&self, content: &[u8], layout: &PeLayout) -> f64 {
        let opt = layout.opt_offset;
        let dd_base = if layout.is_pe32_plus {
            opt + 112
        } else {
            opt + 96
        };

        // Resource directory is data-directory entry 2 (8 bytes per entry)
        let res_dd = dd_base + 2 * 8;
        if res_dd + 4 > content.len() {
            return 0.0;
        }

        let res_rva = u32::from_le_bytes([
            content[res_dd],
            content[res_dd + 1],
            content[res_dd + 2],
            content[res_dd + 3],
        ]) as usize;
        if res_rva == 0 {
            return 0.0;
        }

        let res_off = rva_to_offset(content, layout, res_rva);
        if res_off == 0 || res_off >= content.len() {
            return 0.0;
        }

        // Collect raw resource bytes (depth-first traversal of the resource tree)
        let mut collected: Vec<u8> = Vec::new();
        self.collect_resource_data(content, layout, res_off, res_off, &mut collected, 0);

        if collected.is_empty() {
            0.0
        } else {
            calculate_entropy(&collected)
        }
    }

    fn collect_resource_data(
        &self,
        content: &[u8],
        layout: &PeLayout,
        dir_off: usize,
        res_base: usize,
        collected: &mut Vec<u8>,
        depth: u32,
    ) {
        if depth > 3 {
            return;
        } // resource tree is at most 3 levels deep
        if dir_off + 16 > content.len() {
            return;
        }

        // IMAGE_RESOURCE_DIRECTORY header: 16 bytes
        // NumberOfNamedEntries at +12, NumberOfIdEntries at +14
        let named_entries =
            u16::from_le_bytes([content[dir_off + 12], content[dir_off + 13]]) as usize;
        let id_entries =
            u16::from_le_bytes([content[dir_off + 14], content[dir_off + 15]]) as usize;
        let total_entries = named_entries + id_entries;

        for i in 0..total_entries.min(64) {
            let entry_off = dir_off + 16 + i * 8;
            if entry_off + 8 > content.len() {
                break;
            }

            // Offset-to-data-or-subdirectory at +4
            let data_or_dir = u32::from_le_bytes([
                content[entry_off + 4],
                content[entry_off + 5],
                content[entry_off + 6],
                content[entry_off + 7],
            ]);

            if data_or_dir & 0x80000000 != 0 {
                // High bit set → subdirectory
                let sub_dir = res_base + (data_or_dir & 0x7FFFFFFF) as usize;
                self.collect_resource_data(
                    content,
                    layout,
                    sub_dir,
                    res_base,
                    collected,
                    depth + 1,
                );
            } else {
                // Leaf → IMAGE_RESOURCE_DATA_ENTRY
                let leaf_off = res_base + data_or_dir as usize;
                if leaf_off + 8 <= content.len() {
                    let data_rva = u32::from_le_bytes([
                        content[leaf_off],
                        content[leaf_off + 1],
                        content[leaf_off + 2],
                        content[leaf_off + 3],
                    ]) as usize;
                    let data_size = u32::from_le_bytes([
                        content[leaf_off + 4],
                        content[leaf_off + 5],
                        content[leaf_off + 6],
                        content[leaf_off + 7],
                    ]) as usize;

                    let data_off = rva_to_offset(content, layout, data_rva);
                    if data_off > 0
                        && data_off + data_size <= content.len()
                        && collected.len() + data_size <= 4 * 1024 * 1024
                    {
                        collected.extend_from_slice(&content[data_off..data_off + data_size]);
                    }
                }
            }
        }
    }

    // ── Size statistics [38..41] ──────────────────────────────────────────────

    fn size_features(&self, content: &[u8], layout: &PeLayout, f: &mut Vec<f64>) {
        let opt = layout.opt_offset;
        let file_size = content.len() as f64;

        let size_of_code = if opt + 8 <= content.len() {
            u32::from_le_bytes([
                content[opt + 4],
                content[opt + 5],
                content[opt + 6],
                content[opt + 7],
            ]) as f64
        } else {
            0.0
        };

        let size_of_init_data = if opt + 12 <= content.len() {
            u32::from_le_bytes([
                content[opt + 8],
                content[opt + 9],
                content[opt + 10],
                content[opt + 11],
            ]) as f64
        } else {
            0.0
        };

        let size_of_headers = if opt + 64 <= content.len() {
            // SizeOfHeaders is at optional_header + 60
            u32::from_le_bytes([
                content[opt + 60],
                content[opt + 61],
                content[opt + 62],
                content[opt + 63],
            ]) as f64
        } else {
            0.0
        };

        let (total_virtual, total_raw) = {
            let mut virt = 0u64;
            let mut raw = 0u64;
            for i in 0..layout.num_sections {
                let sec = layout.section_table + i * 40;
                if sec + 40 > content.len() {
                    break;
                }
                virt += u32::from_le_bytes([
                    content[sec + 8],
                    content[sec + 9],
                    content[sec + 10],
                    content[sec + 11],
                ]) as u64;
                raw += u32::from_le_bytes([
                    content[sec + 16],
                    content[sec + 17],
                    content[sec + 18],
                    content[sec + 19],
                ]) as u64;
            }
            (virt as f64, raw as f64)
        };

        f[38] = file_size.max(1.0).log10();
        f[39] = (size_of_code / size_of_init_data.max(1.0)).min(100.0);
        f[40] = size_of_headers / file_size.max(1.0);
        f[41] = (total_virtual / total_raw.max(1.0)).min(100.0);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PE layout helpers
// ─────────────────────────────────────────────────────────────────────────────

struct PeLayout {
    coff_offset: usize,
    opt_offset: usize,
    is_pe32_plus: bool,
    num_sections: usize,
    section_table: usize,
}

impl PeLayout {
    fn parse(content: &[u8]) -> Option<Self> {
        if content.len() < 64 || &content[0..2] != b"MZ" {
            return None;
        }

        let pe_off =
            u32::from_le_bytes([content[60], content[61], content[62], content[63]]) as usize;

        if pe_off + 24 > content.len() {
            return None;
        }
        if &content[pe_off..pe_off + 4] != b"PE\0\0" {
            return None;
        }

        let coff_offset = pe_off + 4;
        let num_sections =
            u16::from_le_bytes([content[coff_offset + 2], content[coff_offset + 3]]) as usize;

        let opt_header_size =
            u16::from_le_bytes([content[coff_offset + 16], content[coff_offset + 17]]) as usize;

        let opt_offset = coff_offset + 20;
        if opt_offset + 2 > content.len() {
            return None;
        }

        let magic = u16::from_le_bytes([content[opt_offset], content[opt_offset + 1]]);
        let is_pe32_plus = magic == 0x020B;

        let section_table = opt_offset + opt_header_size;

        Some(PeLayout {
            coff_offset,
            opt_offset,
            is_pe32_plus,
            num_sections,
            section_table,
        })
    }
}

/// Convert an RVA to a file offset using the section table.
fn rva_to_offset(content: &[u8], layout: &PeLayout, rva: usize) -> usize {
    for i in 0..layout.num_sections {
        let sec = layout.section_table + i * 40;
        if sec + 40 > content.len() {
            break;
        }

        let virt_addr = u32::from_le_bytes([
            content[sec + 12],
            content[sec + 13],
            content[sec + 14],
            content[sec + 15],
        ]) as usize;
        let virt_size = u32::from_le_bytes([
            content[sec + 8],
            content[sec + 9],
            content[sec + 10],
            content[sec + 11],
        ]) as usize;
        let raw_ptr = u32::from_le_bytes([
            content[sec + 20],
            content[sec + 21],
            content[sec + 22],
            content[sec + 23],
        ]) as usize;

        if rva >= virt_addr && rva < virt_addr + virt_size.max(1) {
            return raw_ptr + (rva - virt_addr);
        }
    }
    rva // fallback: treat RVA as file offset (raw sections at load address 0)
}

// ─────────────────────────────────────────────────────────────────────────────
// Import parsing (DLL names + function names)
// ─────────────────────────────────────────────────────────────────────────────

struct ImportedDll {
    functions: Vec<String>,
}

fn parse_imports(content: &[u8], layout: &PeLayout) -> Vec<ImportedDll> {
    let mut dlls: Vec<ImportedDll> = Vec::new();
    let opt = layout.opt_offset;

    // Import directory is data-directory entry 1
    let imp_dd = if layout.is_pe32_plus {
        opt + 120
    } else {
        opt + 104
    };
    if imp_dd + 8 > content.len() {
        return dlls;
    }

    let imp_rva = u32::from_le_bytes([
        content[imp_dd],
        content[imp_dd + 1],
        content[imp_dd + 2],
        content[imp_dd + 3],
    ]) as usize;
    if imp_rva == 0 {
        return dlls;
    }

    let imp_off = rva_to_offset(content, layout, imp_rva);
    if imp_off == 0 || imp_off + 20 > content.len() {
        return dlls;
    }

    let entry_size_thunk: usize = if layout.is_pe32_plus { 8 } else { 4 };

    let mut desc = imp_off;
    for _ in 0..256 {
        if desc + 20 > content.len() {
            break;
        }

        let ilt_rva = u32::from_le_bytes([
            content[desc],
            content[desc + 1],
            content[desc + 2],
            content[desc + 3],
        ]) as usize;
        let name_rva = u32::from_le_bytes([
            content[desc + 12],
            content[desc + 13],
            content[desc + 14],
            content[desc + 15],
        ]) as usize;

        if name_rva == 0 {
            break;
        } // null terminator descriptor

        // Parse function names from the Import Lookup Table
        let mut functions: Vec<String> = Vec::new();
        let table_rva = if ilt_rva != 0 {
            ilt_rva
        } else {
            // Fall back to IAT (FirstThunk) if no OriginalFirstThunk
            u32::from_le_bytes([
                content[desc + 16],
                content[desc + 17],
                content[desc + 18],
                content[desc + 19],
            ]) as usize
        };

        if table_rva != 0 {
            let table_off = rva_to_offset(content, layout, table_rva);
            if table_off != 0 {
                let mut entry = table_off;
                for _ in 0..1024 {
                    if entry + entry_size_thunk > content.len() {
                        break;
                    }

                    let (is_ordinal, ibn_rva) = if layout.is_pe32_plus {
                        let val = u64::from_le_bytes([
                            content[entry],
                            content[entry + 1],
                            content[entry + 2],
                            content[entry + 3],
                            content[entry + 4],
                            content[entry + 5],
                            content[entry + 6],
                            content[entry + 7],
                        ]);
                        if val == 0 {
                            break;
                        }
                        (
                            val & 0x8000_0000_0000_0000 != 0,
                            (val & 0x7FFF_FFFF_FFFF_FFFF) as usize,
                        )
                    } else {
                        let val = u32::from_le_bytes([
                            content[entry],
                            content[entry + 1],
                            content[entry + 2],
                            content[entry + 3],
                        ]);
                        if val == 0 {
                            break;
                        }
                        (val & 0x8000_0000 != 0, (val & 0x7FFF_FFFF) as usize)
                    };

                    if !is_ordinal {
                        // ibn_rva → IMAGE_IMPORT_BY_NAME { Hint: u16, Name: [u8] }
                        let ibn_off = rva_to_offset(content, layout, ibn_rva);
                        if ibn_off + 2 < content.len() {
                            let func_name = read_cstring(content, ibn_off + 2).to_lowercase();
                            if !func_name.is_empty() {
                                functions.push(func_name);
                            }
                        }
                    }

                    entry += entry_size_thunk;
                }
            }
        }

        dlls.push(ImportedDll { functions });
        desc += 20;
    }

    dlls
}

fn read_cstring(content: &[u8], offset: usize) -> String {
    if offset >= content.len() {
        return String::new();
    }
    let mut s = String::new();
    for i in 0..256 {
        if offset + i >= content.len() {
            break;
        }
        let b = content[offset + i];
        if b == 0 {
            break;
        }
        if b.is_ascii() {
            s.push(b as char);
        }
    }
    s
}

fn is_suspicious_import(name: &str) -> bool {
    const SUSPICIOUS: &[&str] = &[
        "isdebuggerpresent",
        "checkremotedebuggerpresent",
        "ntqueryinformationprocess",
        "gettickcount64",
        "queryperformancecounter",
        "outputdebugstring",
        "setwindowshookex",
        "keybd_event",
        "getasynckeystate",
        "getforegroundwindow",
    ];
    SUSPICIOUS.contains(&name)
}

// ─────────────────────────────────────────────────────────────────────────────
// PE checksum verification
// ─────────────────────────────────────────────────────────────────────────────

/// Returns true if the stored PE checksum matches the computed value.
/// Returns false for files with a zero checksum (not computed) or a mismatch.
fn verify_pe_checksum(content: &[u8]) -> bool {
    if content.len() < 64 || &content[0..2] != b"MZ" {
        return false;
    }

    let pe_off = u32::from_le_bytes([content[60], content[61], content[62], content[63]]) as usize;
    if pe_off + 24 > content.len() {
        return false;
    }
    if &content[pe_off..pe_off + 4] != b"PE\0\0" {
        return false;
    }

    let opt_off = pe_off + 24;
    // CheckSum is at optional_header + 64 for both PE32 and PE32+
    let ck_off = opt_off + 64;
    if ck_off + 4 > content.len() {
        return false;
    }

    let stored = u32::from_le_bytes([
        content[ck_off],
        content[ck_off + 1],
        content[ck_off + 2],
        content[ck_off + 3],
    ]);
    if stored == 0 {
        return false;
    }

    // Compute checksum: sum all 16-bit LE words, skipping the CheckSum field
    let len = content.len();
    let num_words = (len + 1) / 2;
    let mut sum: u64 = 0;

    for i in 0..num_words {
        let off = i * 2;
        if off == ck_off || off == ck_off + 2 {
            continue;
        }
        let lo = content[off] as u64;
        let hi = if off + 1 < len {
            content[off + 1] as u64
        } else {
            0
        };
        sum += lo | (hi << 8);
    }
    // Fold carries into 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum += len as u64;

    (sum as u32) == stored
}

// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn novelty_extractor_empty_returns_zeros() {
        let ext = NoveltyExtractor::new();
        let f = ext.extract_from_bytes(&[]);
        assert_eq!(f.len(), NOVELTY_FEATURE_COUNT);
        assert!(f.iter().all(|&v| v == 0.0));
    }

    #[test]
    fn novelty_extractor_non_pe_returns_zeros() {
        let ext = NoveltyExtractor::new();
        let data = b"This is not a PE file, just some text".to_vec();
        let f = ext.extract_from_bytes(&data);
        assert_eq!(f.len(), NOVELTY_FEATURE_COUNT);
        assert!(f.iter().all(|&v| v == 0.0));
    }

    #[test]
    fn novelty_extractor_mz_header_no_crash() {
        let ext = NoveltyExtractor::new();
        let mut data = vec![0u8; 200];
        data[0] = b'M';
        data[1] = b'Z';
        let f = ext.extract_from_bytes(&data);
        assert_eq!(f.len(), NOVELTY_FEATURE_COUNT);
    }

    #[test]
    fn novelty_extractor_feature_count() {
        let ext = NoveltyExtractor::new();
        let f = ext.extract_from_bytes(&[0u8; 1000]);
        assert_eq!(f.len(), NOVELTY_FEATURE_COUNT);
    }
}
