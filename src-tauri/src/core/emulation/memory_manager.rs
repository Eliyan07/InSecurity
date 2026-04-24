//! Memory Manager for Emulation
//! Handles virtual memory regions, stack, heap, and section mapping

use std::collections::HashMap;
use unicorn_engine::{Permission, Unicorn};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryRegionType {
    Code,
    Data,
    Stack,
    Heap,
    Import,
    Teb, // Thread Environment Block
    Peb, // Process Environment Block
}

#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub base: u64,
    pub size: u64,
    pub region_type: MemoryRegionType,
    pub permissions: Permission,
    pub name: String,
}

pub struct MemoryManager {
    regions: HashMap<u64, MemoryRegion>,
    heap_base: u64,
    heap_current: u64,
    heap_size: u64,
    stack_base: u64,
    stack_size: u64,
    total_allocated: u64,
    max_total_memory: u64,
}

impl MemoryManager {
    // Default memory layout constants
    pub const DEFAULT_STACK_BASE: u64 = 0x7FFE_0000;
    pub const DEFAULT_STACK_SIZE: u64 = 0x20_0000; // 2MB stack (realistic)
    pub const DEFAULT_HEAP_BASE: u64 = 0x1000_0000;
    pub const DEFAULT_HEAP_SIZE: u64 = 0x200_0000; // 32MB heap
    pub const DEFAULT_MAX_MEMORY: u64 = 128 * 1024 * 1024; // 128MB total limit
    pub const TEB_BASE: u64 = 0x7FFD_E000;
    pub const PEB_BASE: u64 = 0x7FFD_C000;

    pub fn new() -> Self {
        Self {
            regions: HashMap::new(),
            heap_base: Self::DEFAULT_HEAP_BASE,
            heap_current: Self::DEFAULT_HEAP_BASE,
            heap_size: Self::DEFAULT_HEAP_SIZE,
            stack_base: Self::DEFAULT_STACK_BASE,
            stack_size: Self::DEFAULT_STACK_SIZE,
            total_allocated: 0,
            max_total_memory: Self::DEFAULT_MAX_MEMORY,
        }
    }

    /// Create with custom memory limits
    pub fn with_limits(max_memory: u64, stack_size: u64, heap_size: u64) -> Self {
        Self {
            regions: HashMap::new(),
            heap_base: Self::DEFAULT_HEAP_BASE,
            heap_current: Self::DEFAULT_HEAP_BASE,
            heap_size: heap_size.min(max_memory / 2), // Heap can't exceed half of total
            stack_base: Self::DEFAULT_STACK_BASE,
            stack_size: stack_size.min(max_memory / 4), // Stack can't exceed quarter of total
            total_allocated: 0,
            max_total_memory: max_memory,
        }
    }

    /// Initialize memory layout in Unicorn
    pub fn initialize<'a>(&mut self, emu: &mut Unicorn<'a, ()>) -> Result<(), MemoryError> {
        // Map stack
        self.map_region(
            emu,
            self.stack_base - self.stack_size,
            self.stack_size,
            Permission::READ | Permission::WRITE,
            MemoryRegionType::Stack,
            "stack".to_string(),
        )?;

        // Map heap
        self.map_region(
            emu,
            self.heap_base,
            self.heap_size,
            Permission::READ | Permission::WRITE,
            MemoryRegionType::Heap,
            "heap".to_string(),
        )?;

        // Map TEB (Thread Environment Block)
        self.map_region(
            emu,
            Self::TEB_BASE,
            0x1000,
            Permission::READ | Permission::WRITE,
            MemoryRegionType::Teb,
            "teb".to_string(),
        )?;

        // Map PEB (Process Environment Block)
        self.map_region(
            emu,
            Self::PEB_BASE,
            0x1000,
            Permission::READ | Permission::WRITE,
            MemoryRegionType::Peb,
            "peb".to_string(),
        )?;

        // Initialize TEB with PEB pointer
        let peb_ptr = Self::PEB_BASE.to_le_bytes();
        emu.mem_write(Self::TEB_BASE + 0x30, &peb_ptr) // TEB.ProcessEnvironmentBlock
            .map_err(|e| MemoryError::WriteError(format!("{:?}", e)))?;

        Ok(())
    }

    pub fn map_region<'a>(
        &mut self,
        emu: &mut Unicorn<'a, ()>,
        base: u64,
        size: u64,
        perms: Permission,
        region_type: MemoryRegionType,
        name: String,
    ) -> Result<(), MemoryError> {
        let aligned_base = base & !0xFFF;
        let aligned_size = ((size + 0xFFF) & !0xFFF).max(0x1000);

        if self.total_allocated + aligned_size > self.max_total_memory {
            log::warn!(
                "Memory limit exceeded: requested {} bytes, already allocated {}, max {}",
                aligned_size,
                self.total_allocated,
                self.max_total_memory
            );
            return Err(MemoryError::MemoryLimitExceeded {
                requested: aligned_size,
                allocated: self.total_allocated,
                max: self.max_total_memory,
            });
        }

        // Check for overlapping regions
        for (existing_base, region) in &self.regions {
            let existing_end = existing_base + region.size;
            let new_end = aligned_base + aligned_size;

            if aligned_base < existing_end && new_end > *existing_base {
                log::debug!(
                    "Region {} overlaps with existing region {}",
                    name,
                    region.name
                );
                return Ok(());
            }
        }

        emu.mem_map(aligned_base, aligned_size as usize, perms)
            .map_err(|e| MemoryError::MapError(format!("{:?}", e)))?;

        self.total_allocated += aligned_size;

        self.regions.insert(
            aligned_base,
            MemoryRegion {
                base: aligned_base,
                size: aligned_size,
                region_type,
                permissions: perms,
                name,
            },
        );

        Ok(())
    }

    pub fn map_pe_sections<'a>(
        &mut self,
        emu: &mut Unicorn<'a, ()>,
        image_base: u64,
        size_of_image: u64,
        sections: &[super::pe_loader::LoadedSection],
    ) -> Result<(), MemoryError> {
        let aligned_size = ((size_of_image + 0xFFF) & !0xFFF).max(0x1000);

        self.map_region(
            emu,
            image_base,
            aligned_size,
            Permission::READ | Permission::WRITE | Permission::EXEC,
            MemoryRegionType::Code,
            "pe_image".to_string(),
        )?;

        for section in sections {
            if !section.raw_data.is_empty() {
                emu.mem_write(section.virtual_address, &section.raw_data)
                    .map_err(|e| MemoryError::WriteError(format!("{:?}", e)))?;
            }

            log::debug!(
                "Mapped section {} at 0x{:X} (size: 0x{:X})",
                section.name,
                section.virtual_address,
                section.virtual_size
            );
        }

        Ok(())
    }

    /// Allocate memory from the heap (simulates VirtualAlloc/HeapAlloc)
    pub fn allocate(&mut self, size: u64) -> Result<u64, MemoryError> {
        let aligned_size = (size + 0xFFF) & !0xFFF;

        if self.heap_current + aligned_size > self.heap_base + self.heap_size {
            return Err(MemoryError::OutOfMemory);
        }

        let addr = self.heap_current;
        self.heap_current += aligned_size;

        Ok(addr)
    }

    pub fn get_stack_pointer(&self) -> u64 {
        self.stack_base - 0x1000
    }

    /// Dump a memory region
    pub fn dump_region<'a>(
        &self,
        emu: &Unicorn<'a, ()>,
        base: u64,
        size: u64,
    ) -> Result<Vec<u8>, MemoryError> {
        let mut buffer = vec![0u8; size as usize];
        emu.mem_read(base, &mut buffer)
            .map_err(|e| MemoryError::ReadError(format!("{:?}", e)))?;
        Ok(buffer)
    }

    pub fn get_regions(&self) -> &HashMap<u64, MemoryRegion> {
        &self.regions
    }
}

impl Default for MemoryManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MemoryError {
    #[error("Failed to map memory: {0}")]
    MapError(String),
    #[error("Failed to read memory: {0}")]
    ReadError(String),
    #[error("Failed to write memory: {0}")]
    WriteError(String),
    #[error("Out of memory")]
    OutOfMemory,
    #[error("Memory limit exceeded: requested {requested} bytes, already allocated {allocated}, max {max}")]
    MemoryLimitExceeded {
        requested: u64,
        allocated: u64,
        max: u64,
    },
}
