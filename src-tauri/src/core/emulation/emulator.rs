//! Main Emulator
//! Orchestrates CPU, Memory, and API emulation for PE analysis

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use unicorn_engine::{Arch, HookType, Mode, Unicorn};

use super::api_hooks::{ApiCall, ApiError, ApiHandler};
use super::cpu_emulator::{CpuContext, CpuEmulator, CpuError};
use super::memory_manager::{MemoryError, MemoryManager};
use super::pe_loader::{LoadedPe, PeLoader, PeLoaderError};

#[derive(Debug, Clone)]
pub struct EmulationConfig {
    pub max_instructions: u64,
    pub timeout: Duration,
    pub trace_instructions: bool,
    pub trace_memory: bool,
    /// Stop at original entry point (OEP) detection
    pub detect_oep: bool,
    pub max_memory_bytes: u64,
    pub max_stack_size: u64,
    pub max_heap_size: u64,
}

impl Default for EmulationConfig {
    fn default() -> Self {
        Self {
            max_instructions: 1_000_000,
            timeout: Duration::from_secs(30),
            trace_instructions: false,
            trace_memory: false,
            detect_oep: true,
            // Conservative memory limits to prevent host exhaustion
            max_memory_bytes: 128 * 1024 * 1024, // 128MB total per emulation
            max_stack_size: 2 * 1024 * 1024,     // 2MB stack (realistic)
            max_heap_size: 32 * 1024 * 1024,     // 32MB heap
        }
    }
}

#[derive(Debug)]
pub struct EmulationResult {
    pub success: bool,
    pub instructions_executed: u64,
    pub final_context: CpuContext,
    /// Detected original entry point (if unpacking detected)
    pub detected_oep: Option<u64>,
    /// API calls made during emulation
    pub api_calls: Vec<ApiCall>,
    /// Suspicious behaviors detected
    pub suspicious_behaviors: Vec<String>,
    /// Memory dumps (section_name -> data)
    pub memory_dumps: Vec<MemoryDump>,
    /// Error message if failed
    pub error: Option<String>,
    pub execution_time: Duration,
}

#[derive(Debug, Clone)]
pub struct MemoryDump {
    pub name: String,
    pub base_address: u64,
    pub data: Vec<u8>,
}

struct EmulationState {
    api_handler: ApiHandler,
    instruction_count: u64,
    should_stop: bool,
    last_written_exec_addr: Option<u64>,
    oep_candidates: Vec<u64>,
    trace_log: Vec<String>,
}

pub struct Emulator {
    config: EmulationConfig,
}

impl Emulator {
    pub fn new(config: EmulationConfig) -> Self {
        Self { config }
    }

    pub fn emulate_file(&self, file_path: &str) -> Result<EmulationResult, EmulatorError> {
        let file_data =
            std::fs::read(file_path).map_err(|e| EmulatorError::IoError(e.to_string()))?;

        self.emulate_bytes(&file_data)
    }

    pub fn emulate_bytes(&self, file_data: &[u8]) -> Result<EmulationResult, EmulatorError> {
        let start_time = Instant::now();

        let pe = PeLoader::load(file_data)?;
        log::info!(
            "Loaded PE: {} entry=0x{:X} sections={}",
            if pe.is_64bit { "x64" } else { "x86" },
            pe.entry_point,
            pe.sections.len()
        );

        let (arch, mode) = if pe.is_64bit {
            (Arch::X86, Mode::MODE_64)
        } else {
            (Arch::X86, Mode::MODE_32)
        };

        let mut emu = Unicorn::new(arch, mode)
            .map_err(|e| EmulatorError::UnicornError(format!("{:?}", e)))?;

        let mut mem_manager = MemoryManager::new();
        mem_manager.initialize(&mut emu)?;
        mem_manager.map_pe_sections(&mut emu, pe.image_base, pe.size_of_image, &pe.sections)?;

        let cpu = CpuEmulator::new(pe.is_64bit);
        let stack_ptr = mem_manager.get_stack_pointer();
        cpu.initialize_registers(&mut emu, pe.entry_point, stack_ptr)?;

        let mut api_handler = ApiHandler::new(pe.is_64bit);
        api_handler.register_imports(&pe.imports);

        let state = Arc::new(Mutex::new(EmulationState {
            api_handler,
            instruction_count: 0,
            should_stop: false,
            last_written_exec_addr: None,
            oep_candidates: Vec::new(),
            trace_log: Vec::new(),
        }));

        let state_clone = Arc::clone(&state);
        let max_instructions = self.config.max_instructions;
        let trace_instr = self.config.trace_instructions;

        emu.add_hook(HookType::CODE, 0, u64::MAX, move |_uc, address, size| {
            if let Ok(mut s) = state_clone.lock() {
                s.instruction_count += 1;

                if trace_instr {
                    s.trace_log.push(format!("0x{:X}: {} bytes", address, size));
                }

                if s.instruction_count >= max_instructions {
                    s.should_stop = true;
                }
            }
        })
        .map_err(|e| EmulatorError::UnicornError(format!("{:?}", e)))?;

        if self.config.detect_oep {
            let state_clone = Arc::clone(&state);
            let code_base = pe.image_base;
            let code_end = pe.image_base + pe.size_of_image;

            emu.add_hook(
                HookType::MEM_WRITE,
                code_base,
                code_end,
                move |_uc, _type, address, _size, _value| {
                    if let Ok(mut s) = state_clone.lock() {
                        // Track writes to code section (potential unpacking)
                        s.last_written_exec_addr = Some(address);
                    }
                    true
                },
            )
            .map_err(|e| EmulatorError::UnicornError(format!("{:?}", e)))?;
        }

        let timeout_us = self.config.timeout.as_micros() as u64;
        let result = emu.emu_start(
            pe.entry_point,
            0,
            timeout_us,
            self.config.max_instructions as usize,
        );

        let final_context = cpu.capture_context(&emu)?;
        let execution_time = start_time.elapsed();

        let (api_calls, suspicious_behaviors, instruction_count, oep_candidates, trace_log) = {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            (
                s.api_handler.get_call_log().to_vec(),
                s.api_handler.analyze_behavior(),
                s.instruction_count,
                s.oep_candidates.clone(),
                s.trace_log.clone(),
            )
        };

        let mut memory_dumps = Vec::new();
        for section in &pe.sections {
            if let Ok(data) = mem_manager.dump_region(
                &emu,
                section.virtual_address,
                section.virtual_size.min(0x100000),
            ) {
                memory_dumps.push(MemoryDump {
                    name: section.name.clone(),
                    base_address: section.virtual_address,
                    data,
                });
            }
        }

        let (success, error) = match result {
            Ok(_) => (true, None),
            Err(e) => (false, Some(format!("{:?}", e))),
        };

        let detected_oep = oep_candidates.first().copied();

        Ok(EmulationResult {
            success,
            instructions_executed: instruction_count,
            final_context,
            detected_oep,
            api_calls,
            suspicious_behaviors,
            memory_dumps,
            error,
            execution_time,
        })
    }

    pub fn detect_unpacking(&self, file_data: &[u8]) -> Result<bool, EmulatorError> {
        let config = EmulationConfig {
            max_instructions: 100_000,
            timeout: Duration::from_secs(5),
            detect_oep: true,
            ..Default::default()
        };

        let emu = Emulator::new(config);
        let result = emu.emulate_bytes(file_data)?;

        Ok(result.detected_oep.is_some())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EmulatorError {
    #[error("PE loader error: {0}")]
    PeError(#[from] PeLoaderError),
    #[error("Memory error: {0}")]
    MemoryError(#[from] MemoryError),
    #[error("CPU error: {0}")]
    CpuError(#[from] CpuError),
    #[error("API error: {0}")]
    ApiError(#[from] ApiError),
    #[error("Unicorn error: {0}")]
    UnicornError(String),
    #[error("IO error: {0}")]
    IoError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_emulation_config_default() {
        let config = EmulationConfig::default();
        assert_eq!(config.max_instructions, 1_000_000);
        assert_eq!(config.timeout, Duration::from_secs(30));
        assert!(!config.trace_instructions);
        assert!(config.detect_oep);
    }

    #[test]
    fn test_emulator_creation() {
        let config = EmulationConfig::default();
        let _emu = Emulator::new(config);
    }
}
