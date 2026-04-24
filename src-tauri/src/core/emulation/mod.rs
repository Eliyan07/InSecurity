//! Emulation Module
//! Provides CPU, Memory, and API emulation using Unicorn Engine
//! for unpacking and dynamic analysis of packed/obfuscated binaries.

pub mod api_hooks;
pub mod cpu_emulator;
pub mod emulator;
pub mod memory_manager;
pub mod pe_loader;

pub use api_hooks::ApiHandler;
pub use emulator::{EmulationConfig, EmulationResult, Emulator};
pub use pe_loader::PeLoader;
