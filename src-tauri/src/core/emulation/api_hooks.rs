//! API Hooks / Stubs
//! Emulates Windows API calls during CPU emulation

use std::collections::HashMap;
use unicorn_engine::{RegisterX86, Unicorn};

#[derive(Debug, Clone)]
pub struct ApiCallResult {
    pub return_value: u64,
    pub should_continue: bool,
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct ApiCall {
    pub address: u64,
    pub function_name: String,
    pub dll_name: String,
    pub arguments: Vec<u64>,
    pub return_value: u64,
}

/// API handler that intercepts and emulates Windows API calls
pub struct ApiHandler {
    /// Map of address -> (dll_name, function_name)
    hooks: HashMap<u64, (String, String)>,
    /// Recorded API calls
    call_log: Vec<ApiCall>,
    /// Memory allocator state
    alloc_base: u64,
    /// File handle counter
    next_handle: u64,
    env_vars: HashMap<String, String>,
    is_64bit: bool,
}

impl ApiHandler {
    pub fn new(is_64bit: bool) -> Self {
        let mut env_vars = HashMap::new();
        env_vars.insert("TEMP".to_string(), "C:\\Temp".to_string());
        env_vars.insert("TMP".to_string(), "C:\\Temp".to_string());
        env_vars.insert("SYSTEMROOT".to_string(), "C:\\Windows".to_string());
        env_vars.insert("WINDIR".to_string(), "C:\\Windows".to_string());

        Self {
            hooks: HashMap::new(),
            call_log: Vec::new(),
            alloc_base: 0x2000_0000,
            next_handle: 0x1000,
            env_vars,
            is_64bit,
        }
    }

    /// Register hooks for imported functions
    pub fn register_imports(
        &mut self,
        imports: &HashMap<String, Vec<super::pe_loader::ImportedFunction>>,
    ) {
        for (dll, funcs) in imports {
            for func in funcs {
                self.hooks
                    .insert(func.iat_address, (dll.clone(), func.function_name.clone()));
            }
        }
        log::debug!("Registered {} API hooks", self.hooks.len());
    }

    pub fn is_hooked(&self, address: u64) -> bool {
        self.hooks.contains_key(&address)
    }

    pub fn handle_call<'a>(
        &mut self,
        emu: &mut Unicorn<'a, ()>,
        address: u64,
    ) -> Result<ApiCallResult, ApiError> {
        let (dll, func) = match self.hooks.get(&address) {
            Some((d, f)) => (d.clone(), f.clone()),
            None => return Err(ApiError::UnknownApi(address)),
        };

        let args = self.get_arguments(emu)?;
        let result = self.dispatch_api(&dll, &func, emu, &args)?;
        self.call_log.push(ApiCall {
            address,
            function_name: func.clone(),
            dll_name: dll,
            arguments: args,
            return_value: result.return_value,
        });
        if self.is_64bit {
            emu.reg_write(RegisterX86::RAX, result.return_value)
                .map_err(|e| ApiError::EmulationError(format!("{:?}", e)))?;
        } else {
            emu.reg_write(RegisterX86::EAX, result.return_value)
                .map_err(|e| ApiError::EmulationError(format!("{:?}", e)))?;
        }

        Ok(result)
    }

    fn get_arguments<'a>(&self, emu: &Unicorn<'a, ()>) -> Result<Vec<u64>, ApiError> {
        let mut args = Vec::new();

        if self.is_64bit {
            args.push(emu.reg_read(RegisterX86::RCX).unwrap_or(0));
            args.push(emu.reg_read(RegisterX86::RDX).unwrap_or(0));
            args.push(emu.reg_read(RegisterX86::R8).unwrap_or(0));
            args.push(emu.reg_read(RegisterX86::R9).unwrap_or(0));

            let rsp = emu.reg_read(RegisterX86::RSP).unwrap_or(0);
            for i in 0..4 {
                let mut buf = [0u8; 8];
                let addr = rsp + 0x28 + (i * 8); // Skip shadow space + return addr
                if emu.mem_read(addr, &mut buf).is_ok() {
                    args.push(u64::from_le_bytes(buf));
                }
            }
        } else {
            let esp = emu.reg_read(RegisterX86::ESP).unwrap_or(0);
            for i in 0..8 {
                let mut buf = [0u8; 4];
                let addr = esp + 4 + (i * 4); // Skip return address
                if emu.mem_read(addr, &mut buf).is_ok() {
                    args.push(u32::from_le_bytes(buf) as u64);
                }
            }
        }

        Ok(args)
    }

    fn dispatch_api<'a>(
        &mut self,
        dll: &str,
        func: &str,
        emu: &mut Unicorn<'a, ()>,
        args: &[u64],
    ) -> Result<ApiCallResult, ApiError> {
        let dll_lower = dll.to_lowercase();
        let func_lower = func.to_lowercase();

        match dll_lower.as_str() {
            "kernel32.dll" | "kernelbase.dll" => self.handle_kernel32(&func_lower, emu, args),
            "ntdll.dll" => self.handle_ntdll(&func_lower, emu, args),
            "user32.dll" => self.handle_user32(&func_lower, emu, args),
            "advapi32.dll" => self.handle_advapi32(&func_lower, emu, args),
            _ => Ok(ApiCallResult {
                return_value: 0,
                should_continue: true,
                description: format!("Unknown API: {}!{}", dll, func),
            }),
        }
    }

    fn handle_kernel32<'a>(
        &mut self,
        func: &str,
        emu: &mut Unicorn<'a, ()>,
        args: &[u64],
    ) -> Result<ApiCallResult, ApiError> {
        match func {
            "virtualalloc" => {
                let addr = args.get(0).copied().unwrap_or(0);
                let size = args.get(1).copied().unwrap_or(0x1000);
                let _alloc_type = args.get(2).copied().unwrap_or(0);
                let _protect = args.get(3).copied().unwrap_or(0);

                let alloc_addr = if addr == 0 {
                    let a = self.alloc_base;
                    self.alloc_base += (size + 0xFFF) & !0xFFF;
                    a
                } else {
                    addr
                };

                log::debug!(
                    "VirtualAlloc(0x{:X}, 0x{:X}) -> 0x{:X}",
                    addr,
                    size,
                    alloc_addr
                );

                Ok(ApiCallResult {
                    return_value: alloc_addr,
                    should_continue: true,
                    description: format!("VirtualAlloc({:#X}, {:#X})", addr, size),
                })
            }

            "virtualfree" => Ok(ApiCallResult {
                return_value: 1,
                should_continue: true,
                description: "VirtualFree".to_string(),
            }),

            "virtualprotect" => Ok(ApiCallResult {
                return_value: 1,
                should_continue: true,
                description: "VirtualProtect".to_string(),
            }),

            "heapalloc" | "localalloc" | "globalalloc" => {
                let size = args.get(1).copied().unwrap_or(0x100);
                let alloc_addr = self.alloc_base;
                self.alloc_base += (size + 0xFFF) & !0xFFF;

                Ok(ApiCallResult {
                    return_value: alloc_addr,
                    should_continue: true,
                    description: format!("{}({:#X})", func, size),
                })
            }

            "heapfree" | "localfree" | "globalfree" => Ok(ApiCallResult {
                return_value: 1,
                should_continue: true,
                description: func.to_string(),
            }),

            "getprocessheap" => Ok(ApiCallResult {
                return_value: 0x1000_0000,
                should_continue: true,
                description: "GetProcessHeap".to_string(),
            }),

            // Process/Module
            "getmodulehandlea" | "getmodulehandlew" => {
                let module_addr = args.get(0).copied().unwrap_or(0);
                // If NULL, return image base (main module)
                let handle = if module_addr == 0 {
                    0x0040_0000 // Typical image base
                } else {
                    self.next_handle
                };
                self.next_handle += 1;

                Ok(ApiCallResult {
                    return_value: handle,
                    should_continue: true,
                    description: "GetModuleHandle".to_string(),
                })
            }

            "getprocaddress" => {
                // Return a fake address for the requested function
                let proc_addr = self.alloc_base;
                self.alloc_base += 0x100;

                Ok(ApiCallResult {
                    return_value: proc_addr,
                    should_continue: true,
                    description: "GetProcAddress".to_string(),
                })
            }

            "loadlibrarya" | "loadlibraryw" | "loadlibraryexa" | "loadlibraryexw" => {
                let handle = self.next_handle;
                self.next_handle += 0x1000;

                Ok(ApiCallResult {
                    return_value: handle,
                    should_continue: true,
                    description: "LoadLibrary".to_string(),
                })
            }

            // File operations
            "createfilea" | "createfilew" => {
                let handle = self.next_handle;
                self.next_handle += 1;

                Ok(ApiCallResult {
                    return_value: handle,
                    should_continue: true,
                    description: "CreateFile".to_string(),
                })
            }

            "readfile" | "writefile" => {
                Ok(ApiCallResult {
                    return_value: 1, // TRUE
                    should_continue: true,
                    description: func.to_string(),
                })
            }

            "closehandle" => Ok(ApiCallResult {
                return_value: 1,
                should_continue: true,
                description: "CloseHandle".to_string(),
            }),

            // Environment
            "getenvironmentvariablea" | "getenvironmentvariablew" => {
                Ok(ApiCallResult {
                    return_value: 0, // Not found
                    should_continue: true,
                    description: "GetEnvironmentVariable".to_string(),
                })
            }

            "getsystemdirectorya" | "getsystemdirectoryw" => Ok(ApiCallResult {
                return_value: 19,
                should_continue: true,
                description: "GetSystemDirectory".to_string(),
            }),

            // Process termination - stop emulation
            "exitprocess" | "terminateprocess" => Ok(ApiCallResult {
                return_value: 0,
                should_continue: false,
                description: format!("{}({})", func, args.get(0).copied().unwrap_or(0)),
            }),

            // Thread operations
            "getcurrentthreadid" => Ok(ApiCallResult {
                return_value: 1000,
                should_continue: true,
                description: "GetCurrentThreadId".to_string(),
            }),

            "getcurrentprocessid" => Ok(ApiCallResult {
                return_value: 4000,
                should_continue: true,
                description: "GetCurrentProcessId".to_string(),
            }),

            "sleep" => Ok(ApiCallResult {
                return_value: 0,
                should_continue: true,
                description: format!("Sleep({})", args.get(0).copied().unwrap_or(0)),
            }),

            // String operations
            "lstrlena" | "lstrlenw" => Ok(ApiCallResult {
                return_value: 0,
                should_continue: true,
                description: "lstrlen".to_string(),
            }),

            // Default handler
            _ => {
                log::debug!("Unhandled kernel32 API: {}", func);
                Ok(ApiCallResult {
                    return_value: 0,
                    should_continue: true,
                    description: format!("kernel32!{} (unhandled)", func),
                })
            }
        }
    }

    fn handle_ntdll<'a>(
        &mut self,
        func: &str,
        _emu: &mut Unicorn<'a, ()>,
        _args: &[u64],
    ) -> Result<ApiCallResult, ApiError> {
        match func {
            "ntallocatevirtualmemory" => {
                let alloc_addr = self.alloc_base;
                self.alloc_base += 0x1000;

                Ok(ApiCallResult {
                    return_value: 0, // STATUS_SUCCESS
                    should_continue: true,
                    description: format!("NtAllocateVirtualMemory -> 0x{:X}", alloc_addr),
                })
            }

            "ntprotectvirtualmemory" => Ok(ApiCallResult {
                return_value: 0,
                should_continue: true,
                description: "NtProtectVirtualMemory".to_string(),
            }),

            "rtlallocateheap" => {
                let alloc_addr = self.alloc_base;
                self.alloc_base += 0x1000;

                Ok(ApiCallResult {
                    return_value: alloc_addr,
                    should_continue: true,
                    description: "RtlAllocateHeap".to_string(),
                })
            }

            "ntquerysysteminformation" => {
                Ok(ApiCallResult {
                    return_value: 0xC0000001, // STATUS_UNSUCCESSFUL
                    should_continue: true,
                    description: "NtQuerySystemInformation".to_string(),
                })
            }

            _ => {
                log::debug!("Unhandled ntdll API: {}", func);
                Ok(ApiCallResult {
                    return_value: 0,
                    should_continue: true,
                    description: format!("ntdll!{} (unhandled)", func),
                })
            }
        }
    }

    fn handle_user32<'a>(
        &mut self,
        func: &str,
        _emu: &mut Unicorn<'a, ()>,
        _args: &[u64],
    ) -> Result<ApiCallResult, ApiError> {
        match func {
            "messageboxa" | "messageboxw" => Ok(ApiCallResult {
                return_value: 1,
                should_continue: true,
                description: "MessageBox".to_string(),
            }),

            "getdesktopwindow" => Ok(ApiCallResult {
                return_value: 0x10000,
                should_continue: true,
                description: "GetDesktopWindow".to_string(),
            }),

            _ => {
                log::debug!("Unhandled user32 API: {}", func);
                Ok(ApiCallResult {
                    return_value: 0,
                    should_continue: true,
                    description: format!("user32!{} (unhandled)", func),
                })
            }
        }
    }

    fn handle_advapi32<'a>(
        &mut self,
        func: &str,
        _emu: &mut Unicorn<'a, ()>,
        _args: &[u64],
    ) -> Result<ApiCallResult, ApiError> {
        match func {
            "regopenkeyexa" | "regopenkeyexw" => {
                let handle = self.next_handle;
                self.next_handle += 1;

                Ok(ApiCallResult {
                    return_value: 0, // ERROR_SUCCESS
                    should_continue: true,
                    description: format!("RegOpenKeyEx -> handle {}", handle),
                })
            }

            "regclosekey" => Ok(ApiCallResult {
                return_value: 0,
                should_continue: true,
                description: "RegCloseKey".to_string(),
            }),

            _ => {
                log::debug!("Unhandled advapi32 API: {}", func);
                Ok(ApiCallResult {
                    return_value: 0,
                    should_continue: true,
                    description: format!("advapi32!{} (unhandled)", func),
                })
            }
        }
    }

    pub fn get_call_log(&self) -> &[ApiCall] {
        &self.call_log
    }

    pub fn clear_log(&mut self) {
        self.call_log.clear();
    }

    /// Get suspicious API call patterns
    pub fn analyze_behavior(&self) -> Vec<String> {
        let mut suspicious = Vec::new();

        let mut alloc_count = 0;
        let mut file_writes = 0;
        let mut process_ops = 0;

        for call in &self.call_log {
            let func_lower = call.function_name.to_lowercase();

            if func_lower.contains("virtualalloc") || func_lower.contains("heapalloc") {
                alloc_count += 1;
            }

            if func_lower.contains("writefile") || func_lower.contains("createfile") {
                file_writes += 1;
            }

            if func_lower.contains("createprocess") || func_lower.contains("shellexecute") {
                process_ops += 1;
                suspicious.push(format!("Process creation: {}", call.function_name));
            }

            if func_lower.contains("writeprocessmemory") {
                suspicious.push("Code injection: WriteProcessMemory".to_string());
            }

            if func_lower.contains("createremotethread") {
                suspicious.push("Remote thread creation".to_string());
            }
        }

        if alloc_count > 10 {
            suspicious.push(format!("High memory allocation count: {}", alloc_count));
        }

        if file_writes > 5 {
            suspicious.push(format!("Multiple file operations: {}", file_writes));
        }

        suspicious
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("Unknown API at address: 0x{0:X}")]
    UnknownApi(u64),
    #[error("Emulation error: {0}")]
    EmulationError(String),
}
