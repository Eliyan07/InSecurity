//! PE Loader for Emulation
//! Parses PE files and maps sections into emulated memory

use pelite::pe32;
use pelite::pe64::{Pe, PeFile};
use std::collections::HashMap;

/// loaded PE section in memory
#[derive(Debug, Clone)]
pub struct LoadedSection {
    pub name: String,
    pub virtual_address: u64,
    pub virtual_size: u64,
    pub raw_data: Vec<u8>,
    pub characteristics: u32,
}

///  loaded PE file ready for emulation
#[derive(Debug)]
pub struct LoadedPe {
    pub is_64bit: bool,
    pub image_base: u64,
    pub entry_point: u64,
    pub sections: Vec<LoadedSection>,
    pub imports: HashMap<String, Vec<ImportedFunction>>,
    pub size_of_image: u64,
}

#[derive(Debug, Clone)]
pub struct ImportedFunction {
    pub dll_name: String,
    pub function_name: String,
    pub ordinal: Option<u16>,
    pub iat_address: u64, // Address in Import Address Table
}

pub struct PeLoader;

impl PeLoader {
    pub fn load(file_data: &[u8]) -> Result<LoadedPe, PeLoaderError> {
        if file_data.len() < 64 {
            return Err(PeLoaderError::InvalidPe("File too small".into()));
        }

        if &file_data[0..2] != b"MZ" {
            return Err(PeLoaderError::InvalidPe("Invalid DOS signature".into()));
        }

        let pe_offset = u32::from_le_bytes([
            file_data[0x3C],
            file_data[0x3D],
            file_data[0x3E],
            file_data[0x3F],
        ]) as usize;

        if pe_offset + 6 > file_data.len() {
            return Err(PeLoaderError::InvalidPe("Invalid PE offset".into()));
        }

        if &file_data[pe_offset..pe_offset + 4] != b"PE\0\0" {
            return Err(PeLoaderError::InvalidPe("Invalid PE signature".into()));
        }

        let machine = u16::from_le_bytes([file_data[pe_offset + 4], file_data[pe_offset + 5]]);

        let is_64bit = machine == 0x8664; // AMD64

        if is_64bit {
            Self::load_pe64(file_data)
        } else {
            Self::load_pe32(file_data)
        }
    }

    fn load_pe64(file_data: &[u8]) -> Result<LoadedPe, PeLoaderError> {
        let pe = PeFile::from_bytes(file_data)
            .map_err(|e| PeLoaderError::ParseError(format!("{:?}", e)))?;

        let optional_header = pe.optional_header();
        let image_base = optional_header.ImageBase;
        let entry_point = image_base + optional_header.AddressOfEntryPoint as u64;
        let size_of_image = optional_header.SizeOfImage as u64;

        let mut sections = Vec::new();
        for section in pe.section_headers() {
            let name = section
                .name()
                .map_err(|_| PeLoaderError::ParseError("Invalid section name".into()))?
                .to_string();

            let virtual_address = image_base + section.VirtualAddress as u64;
            let virtual_size = section.VirtualSize as u64;

            let raw_data = if section.SizeOfRawData > 0 {
                let start = section.PointerToRawData as usize;
                let end = start
                    .checked_add(section.SizeOfRawData as usize)
                    .ok_or_else(|| PeLoaderError::ParseError("Section size overflow".into()))?;
                if end <= file_data.len() {
                    file_data[start..end].to_vec()
                } else {
                    vec![0u8; section.SizeOfRawData as usize]
                }
            } else {
                Vec::new()
            };

            sections.push(LoadedSection {
                name,
                virtual_address,
                virtual_size,
                raw_data,
                characteristics: section.Characteristics,
            });
        }

        let imports = Self::parse_imports_64(&pe, image_base)?;

        Ok(LoadedPe {
            is_64bit: true,
            image_base,
            entry_point,
            sections,
            imports,
            size_of_image,
        })
    }

    fn load_pe32(file_data: &[u8]) -> Result<LoadedPe, PeLoaderError> {
        let pe = pe32::PeFile::from_bytes(file_data)
            .map_err(|e| PeLoaderError::ParseError(format!("{:?}", e)))?;

        let optional_header = pe.optional_header();
        let image_base = optional_header.ImageBase as u64;
        let entry_point = image_base + optional_header.AddressOfEntryPoint as u64;
        let size_of_image = optional_header.SizeOfImage as u64;

        let mut sections = Vec::new();
        for section in pe.section_headers() {
            let name = section
                .name()
                .map_err(|_| PeLoaderError::ParseError("Invalid section name".into()))?
                .to_string();

            let virtual_address = image_base + section.VirtualAddress as u64;
            let virtual_size = section.VirtualSize as u64;

            let raw_data = if section.SizeOfRawData > 0 {
                let start = section.PointerToRawData as usize;
                let end = start
                    .checked_add(section.SizeOfRawData as usize)
                    .ok_or_else(|| PeLoaderError::ParseError("Section size overflow".into()))?;
                if end <= file_data.len() {
                    file_data[start..end].to_vec()
                } else {
                    vec![0u8; section.SizeOfRawData as usize]
                }
            } else {
                Vec::new()
            };

            sections.push(LoadedSection {
                name,
                virtual_address,
                virtual_size,
                raw_data,
                characteristics: section.Characteristics,
            });
        }

        let imports = Self::parse_imports_32(&pe, image_base)?;

        Ok(LoadedPe {
            is_64bit: false,
            image_base,
            entry_point,
            sections,
            imports,
            size_of_image,
        })
    }

    fn parse_imports_64(
        pe: &PeFile,
        image_base: u64,
    ) -> Result<HashMap<String, Vec<ImportedFunction>>, PeLoaderError> {
        let mut imports: HashMap<String, Vec<ImportedFunction>> = HashMap::new();

        if let Ok(import_dir) = pe.imports() {
            for desc in import_dir {
                if let Ok(dll_name) = desc.dll_name() {
                    let dll = dll_name.to_string();
                    let mut funcs = Vec::new();

                    if let Ok(iat) = desc.iat() {
                        for (idx, entry) in iat.iter().enumerate() {
                            let iat_addr =
                                image_base + desc.image().FirstThunk as u64 + (idx * 8) as u64;

                            // Try to get function name from INT
                            if let Ok(int) = desc.int() {
                                if let Some(int_entry) = int.get(idx) {
                                    if let Ok(pelite::pe64::imports::Import::ByName {
                                        name, ..
                                    }) = int_entry
                                    {
                                        funcs.push(ImportedFunction {
                                            dll_name: dll.clone(),
                                            function_name: name.to_string(),
                                            ordinal: None,
                                            iat_address: iat_addr,
                                        });
                                        continue;
                                    }
                                }
                            }

                            // Fallback: ordinal or unknown
                            funcs.push(ImportedFunction {
                                dll_name: dll.clone(),
                                function_name: format!("Ordinal_{}", entry),
                                ordinal: Some((entry & 0xFFFF) as u16),
                                iat_address: iat_addr,
                            });
                        }
                    }

                    imports.insert(dll, funcs);
                }
            }
        }

        Ok(imports)
    }

    fn parse_imports_32(
        pe: &pe32::PeFile,
        image_base: u64,
    ) -> Result<HashMap<String, Vec<ImportedFunction>>, PeLoaderError> {
        let mut imports: HashMap<String, Vec<ImportedFunction>> = HashMap::new();

        if let Ok(import_dir) = pe.imports() {
            for desc in import_dir {
                if let Ok(dll_name) = desc.dll_name() {
                    let dll = dll_name.to_string();
                    let mut funcs = Vec::new();

                    if let Ok(iat) = desc.iat() {
                        for (idx, entry) in iat.iter().enumerate() {
                            let iat_addr =
                                image_base + desc.image().FirstThunk as u64 + (idx * 4) as u64;

                            if let Ok(int) = desc.int() {
                                if let Some(int_entry) = int.get(idx) {
                                    if let Ok(pelite::pe32::imports::Import::ByName {
                                        name, ..
                                    }) = int_entry
                                    {
                                        funcs.push(ImportedFunction {
                                            dll_name: dll.clone(),
                                            function_name: name.to_string(),
                                            ordinal: None,
                                            iat_address: iat_addr,
                                        });
                                        continue;
                                    }
                                }
                            }

                            funcs.push(ImportedFunction {
                                dll_name: dll.clone(),
                                function_name: format!("Ordinal_{}", entry),
                                ordinal: Some((entry & 0xFFFF) as u16),
                                iat_address: iat_addr,
                            });
                        }
                    }

                    imports.insert(dll, funcs);
                }
            }
        }

        Ok(imports)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PeLoaderError {
    #[error("Invalid PE file: {0}")]
    InvalidPe(String),
    #[error("Parse error: {0}")]
    ParseError(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}
