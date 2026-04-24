//! CPU Emulator
//! Manages CPU state, registers, and instruction execution

use unicorn_engine::{RegisterX86, Unicorn};

#[derive(Debug, Clone, Default)]
pub struct CpuContext {
    // General purpose registers (x64)
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    // Instruction pointer
    pub rip: u64,
    // Flags
    pub rflags: u64,
    // Segment registers
    pub cs: u64,
    pub ds: u64,
    pub es: u64,
    pub fs: u64,
    pub gs: u64,
    pub ss: u64,
}

pub struct CpuEmulator {
    is_64bit: bool,
}

impl CpuEmulator {
    pub fn new(is_64bit: bool) -> Self {
        Self { is_64bit }
    }

    pub fn initialize_registers<'a>(
        &self,
        emu: &mut Unicorn<'a, ()>,
        entry_point: u64,
        stack_pointer: u64,
    ) -> Result<(), CpuError> {
        if self.is_64bit {
            self.init_x64_registers(emu, entry_point, stack_pointer)
        } else {
            self.init_x86_registers(emu, entry_point, stack_pointer)
        }
    }

    fn init_x64_registers<'a>(
        &self,
        emu: &mut Unicorn<'a, ()>,
        entry_point: u64,
        stack_pointer: u64,
    ) -> Result<(), CpuError> {
        // Set instruction pointer
        emu.reg_write(RegisterX86::RIP, entry_point)
            .map_err(|e| CpuError::RegisterError(format!("{:?}", e)))?;

        // Set stack pointer
        emu.reg_write(RegisterX86::RSP, stack_pointer)
            .map_err(|e| CpuError::RegisterError(format!("{:?}", e)))?;

        // Set base pointer
        emu.reg_write(RegisterX86::RBP, stack_pointer)
            .map_err(|e| CpuError::RegisterError(format!("{:?}", e)))?;

        // Clear general purpose registers
        emu.reg_write(RegisterX86::RAX, 0).ok();
        emu.reg_write(RegisterX86::RBX, 0).ok();
        emu.reg_write(RegisterX86::RCX, 0).ok();
        emu.reg_write(RegisterX86::RDX, 0).ok();
        emu.reg_write(RegisterX86::RSI, 0).ok();
        emu.reg_write(RegisterX86::RDI, 0).ok();
        emu.reg_write(RegisterX86::R8, 0).ok();
        emu.reg_write(RegisterX86::R9, 0).ok();
        emu.reg_write(RegisterX86::R10, 0).ok();
        emu.reg_write(RegisterX86::R11, 0).ok();
        emu.reg_write(RegisterX86::R12, 0).ok();
        emu.reg_write(RegisterX86::R13, 0).ok();
        emu.reg_write(RegisterX86::R14, 0).ok();
        emu.reg_write(RegisterX86::R15, 0).ok();

        // Set GS register to point to TEB (Windows x64 convention)
        emu.reg_write(
            RegisterX86::GS_BASE,
            super::memory_manager::MemoryManager::TEB_BASE,
        )
        .map_err(|e| CpuError::RegisterError(format!("{:?}", e)))?;

        // Set default flags
        emu.reg_write(RegisterX86::EFLAGS, 0x202) // IF flag set
            .map_err(|e| CpuError::RegisterError(format!("{:?}", e)))?;

        Ok(())
    }

    fn init_x86_registers<'a>(
        &self,
        emu: &mut Unicorn<'a, ()>,
        entry_point: u64,
        stack_pointer: u64,
    ) -> Result<(), CpuError> {
        // Set instruction pointer
        emu.reg_write(RegisterX86::EIP, entry_point as u64)
            .map_err(|e| CpuError::RegisterError(format!("{:?}", e)))?;

        // Set stack pointer
        emu.reg_write(RegisterX86::ESP, stack_pointer as u64)
            .map_err(|e| CpuError::RegisterError(format!("{:?}", e)))?;

        // Set base pointer
        emu.reg_write(RegisterX86::EBP, stack_pointer as u64)
            .map_err(|e| CpuError::RegisterError(format!("{:?}", e)))?;

        // Clear general purpose registers
        emu.reg_write(RegisterX86::EAX, 0).ok();
        emu.reg_write(RegisterX86::EBX, 0).ok();
        emu.reg_write(RegisterX86::ECX, 0).ok();
        emu.reg_write(RegisterX86::EDX, 0).ok();
        emu.reg_write(RegisterX86::ESI, 0).ok();
        emu.reg_write(RegisterX86::EDI, 0).ok();

        // Set FS register to point to TEB (Windows x86 convention)
        emu.reg_write(
            RegisterX86::FS_BASE,
            super::memory_manager::MemoryManager::TEB_BASE,
        )
        .map_err(|e| CpuError::RegisterError(format!("{:?}", e)))?;

        // Set default flags
        emu.reg_write(RegisterX86::EFLAGS, 0x202)
            .map_err(|e| CpuError::RegisterError(format!("{:?}", e)))?;

        Ok(())
    }

    pub fn capture_context<'a>(&self, emu: &Unicorn<'a, ()>) -> Result<CpuContext, CpuError> {
        if self.is_64bit {
            Ok(CpuContext {
                rax: emu.reg_read(RegisterX86::RAX).unwrap_or(0),
                rbx: emu.reg_read(RegisterX86::RBX).unwrap_or(0),
                rcx: emu.reg_read(RegisterX86::RCX).unwrap_or(0),
                rdx: emu.reg_read(RegisterX86::RDX).unwrap_or(0),
                rsi: emu.reg_read(RegisterX86::RSI).unwrap_or(0),
                rdi: emu.reg_read(RegisterX86::RDI).unwrap_or(0),
                rbp: emu.reg_read(RegisterX86::RBP).unwrap_or(0),
                rsp: emu.reg_read(RegisterX86::RSP).unwrap_or(0),
                r8: emu.reg_read(RegisterX86::R8).unwrap_or(0),
                r9: emu.reg_read(RegisterX86::R9).unwrap_or(0),
                r10: emu.reg_read(RegisterX86::R10).unwrap_or(0),
                r11: emu.reg_read(RegisterX86::R11).unwrap_or(0),
                r12: emu.reg_read(RegisterX86::R12).unwrap_or(0),
                r13: emu.reg_read(RegisterX86::R13).unwrap_or(0),
                r14: emu.reg_read(RegisterX86::R14).unwrap_or(0),
                r15: emu.reg_read(RegisterX86::R15).unwrap_or(0),
                rip: emu.reg_read(RegisterX86::RIP).unwrap_or(0),
                rflags: emu.reg_read(RegisterX86::EFLAGS).unwrap_or(0),
                cs: emu.reg_read(RegisterX86::CS).unwrap_or(0),
                ds: emu.reg_read(RegisterX86::DS).unwrap_or(0),
                es: emu.reg_read(RegisterX86::ES).unwrap_or(0),
                fs: emu.reg_read(RegisterX86::FS).unwrap_or(0),
                gs: emu.reg_read(RegisterX86::GS).unwrap_or(0),
                ss: emu.reg_read(RegisterX86::SS).unwrap_or(0),
            })
        } else {
            Ok(CpuContext {
                rax: emu.reg_read(RegisterX86::EAX).unwrap_or(0),
                rbx: emu.reg_read(RegisterX86::EBX).unwrap_or(0),
                rcx: emu.reg_read(RegisterX86::ECX).unwrap_or(0),
                rdx: emu.reg_read(RegisterX86::EDX).unwrap_or(0),
                rsi: emu.reg_read(RegisterX86::ESI).unwrap_or(0),
                rdi: emu.reg_read(RegisterX86::EDI).unwrap_or(0),
                rbp: emu.reg_read(RegisterX86::EBP).unwrap_or(0),
                rsp: emu.reg_read(RegisterX86::ESP).unwrap_or(0),
                rip: emu.reg_read(RegisterX86::EIP).unwrap_or(0),
                rflags: emu.reg_read(RegisterX86::EFLAGS).unwrap_or(0),
                ..Default::default()
            })
        }
    }

    /// Get current instruction pointer
    pub fn get_ip<'a>(&self, emu: &Unicorn<'a, ()>) -> u64 {
        if self.is_64bit {
            emu.reg_read(RegisterX86::RIP).unwrap_or(0)
        } else {
            emu.reg_read(RegisterX86::EIP).unwrap_or(0)
        }
    }

    /// Get current stack pointer
    pub fn get_sp<'a>(&self, emu: &Unicorn<'a, ()>) -> u64 {
        if self.is_64bit {
            emu.reg_read(RegisterX86::RSP).unwrap_or(0)
        } else {
            emu.reg_read(RegisterX86::ESP).unwrap_or(0)
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CpuError {
    #[error("Register error: {0}")]
    RegisterError(String),
    #[error("Execution error: {0}")]
    ExecutionError(String),
}
