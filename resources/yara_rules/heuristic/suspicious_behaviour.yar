// resources/yara_rules/heuristic/suspicious_behaviour.yar
// Heuristic rules for suspicious behavior patterns

// ============================================
// Packer Detection - INFO level only
// These are informational, not malicious by themselves
// ============================================

rule Packer_UPX {
    meta:
        description = "UPX packed executable (legitimate packer)"
        severity = "info"
        false_positive = "Many legitimate applications use UPX"
    
    strings:
        $upx1 = "UPX0" ascii
        $upx2 = "UPX1" ascii
        $upx3 = "UPX!" ascii
    
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule Packer_Commercial {
    meta:
        description = "Commercial packer/protector detected"
        severity = "info"
        false_positive = "Legitimate software protection"
    
    strings:
        $themida = "Themida" ascii wide
        $vmprotect = "VMProtect" ascii wide
        $enigma = "Enigma protector" ascii wide nocase
    
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule Packer_Suspicious {
    meta:
        description = "Packer commonly associated with malware"
        severity = "medium"
    
    strings:
        // These packers are rarely used by legitimate software
        $nsp1 = "nsp0" ascii
        $nsp2 = "nsp1" ascii
        $fsg = { 87 25 ?? ?? ?? ?? 61 94 55 A4 B6 80 FF 13 }
        $mew = { E9 ?? ?? ?? FF 8D }
        $upack = "UpackByDwworng" ascii
    
    condition:
        uint16(0) == 0x5A4D and any of them
}

// ============================================
// Process Injection - Requires STRONG combinations
// ============================================

rule Process_Injection_Full_Chain {
    meta:
        description = "Complete process injection capability"
        severity = "high"
        // Requires the FULL injection chain, not just a few APIs
    
    strings:
        // Process targeting
        $proc1 = "OpenProcess" ascii
        $proc2 = "CreateToolhelp32Snapshot" ascii
        // Memory allocation in remote process
        $mem1 = "VirtualAllocEx" ascii
        $mem2 = "NtAllocateVirtualMemory" ascii
        // Writing to remote process
        $write1 = "WriteProcessMemory" ascii
        $write2 = "NtWriteVirtualMemory" ascii
        // Thread creation in remote process
        $thread1 = "CreateRemoteThread" ascii
        $thread2 = "NtCreateThreadEx" ascii
        $thread3 = "RtlCreateUserThread" ascii
    
    condition:
        uint16(0) == 0x5A4D and
        any of ($proc*) and
        any of ($mem*) and
        any of ($write*) and
        any of ($thread*)
}

rule Process_Hollowing {
    meta:
        description = "Process hollowing technique"
        severity = "high"
    
    strings:
        $unmap = "NtUnmapViewOfSection" ascii
        $alloc = "VirtualAllocEx" ascii
        $write = "WriteProcessMemory" ascii
        $ctx1 = "SetThreadContext" ascii
        $ctx2 = "NtSetContextThread" ascii
        $resume = "ResumeThread" ascii
    
    condition:
        uint16(0) == 0x5A4D and
        $unmap and $alloc and $write and 
        any of ($ctx*) and $resume
}

rule APC_Injection {
    meta:
        description = "APC injection technique"
        severity = "high"
    
    strings:
        $apc1 = "QueueUserAPC" ascii
        $apc2 = "NtQueueApcThread" ascii
        $alloc = "VirtualAllocEx" ascii
        $write = "WriteProcessMemory" ascii
        $open = "OpenThread" ascii
    
    condition:
        uint16(0) == 0x5A4D and
        any of ($apc*) and $alloc and $write and $open
}

// ============================================
// Credential Theft - High confidence patterns
// ============================================

rule Credential_Dumping_LSASS {
    meta:
        description = "LSASS memory access for credential theft"
        severity = "critical"
    
    strings:
        $lsass = "lsass.exe" ascii wide nocase
        $open = "OpenProcess" ascii
        $read = "ReadProcessMemory" ascii
        $mini = "MiniDumpWriteDump" ascii
        $dbg = "dbghelp" ascii wide nocase
    
    condition:
        uint16(0) == 0x5A4D and
        $lsass and $open and ($read or $mini or $dbg)
}

rule Credential_Dumping_SAM {
    meta:
        description = "SAM database access"
        severity = "high"
    
    strings:
        $sam1 = "SAM" wide
        $sam2 = "SECURITY" wide
        $sam3 = "SYSTEM" wide
        $reg1 = "RegSaveKey" ascii
        $reg2 = "RegOpenKeyEx" ascii
        $hive = "\\config\\SAM" ascii wide nocase
    
    condition:
        uint16(0) == 0x5A4D and
        2 of ($sam*) and (any of ($reg*) or $hive)
}

// ============================================
// Keylogger - Requires multiple indicators
// ============================================

rule Keylogger_Hook_Based {
    meta:
        description = "Hook-based keylogger"
        severity = "high"
        // SetWindowsHookEx alone is used by accessibility tools
        // Need additional indicators
    
    strings:
        $hook = "SetWindowsHookEx" ascii
        $key1 = "GetAsyncKeyState" ascii
        $key2 = "GetKeyboardState" ascii
        $key3 = "GetKeyState" ascii
        // Logging indicators
        $log1 = "[ENTER]" ascii wide
        $log2 = "[SHIFT]" ascii wide
        $log3 = "[CTRL]" ascii wide
        $log4 = "[BACKSPACE]" ascii wide
        $log5 = "keylog" ascii wide nocase
        $file = "CreateFile" ascii
    
    condition:
        uint16(0) == 0x5A4D and
        $hook and 
        2 of ($key*) and
        (any of ($log*) or $file)
}

rule Keylogger_Polling {
    meta:
        description = "Polling-based keylogger"
        severity = "medium"
    
    strings:
        $poll1 = "GetAsyncKeyState" ascii
        $poll2 = "GetKeyState" ascii
        $loop = { 0F B6 ?? 83 ?? 01 }  // Character processing loop
        $log1 = "[" ascii
        $log2 = "]" ascii
        $vk = "VK_" ascii
    
    condition:
        uint16(0) == 0x5A4D and
        all of ($poll*) and $loop and any of ($log*) and $vk
}

// ============================================
// Ransomware - Requires encryption + file operations
// ============================================

rule Ransomware_Behavior {
    meta:
        description = "Ransomware behavioral pattern"
        severity = "critical"
    
    strings:
        // Crypto APIs
        $cry1 = "CryptEncrypt" ascii
        $cry2 = "CryptGenKey" ascii
        $cry3 = "CryptAcquireContext" ascii
        $cry4 = "BCryptEncrypt" ascii
        // File enumeration
        $enum1 = "FindFirstFile" ascii
        $enum2 = "FindNextFile" ascii
        // File operations
        $file1 = "MoveFileEx" ascii
        $file2 = "DeleteFile" ascii
        // Shadow copy deletion (very specific to ransomware)
        $shadow1 = "vssadmin" ascii wide nocase
        $shadow2 = "delete shadows" ascii wide nocase
        $shadow3 = "wmic shadowcopy" ascii wide nocase
        // Ransom note indicators
        $note1 = "your files" ascii wide nocase
        $note2 = "encrypted" ascii wide nocase
        $note3 = "bitcoin" ascii wide nocase
        $note4 = "decrypt" ascii wide nocase
    
    condition:
        uint16(0) == 0x5A4D and
        (
            // Shadow deletion is almost always ransomware
            any of ($shadow*) or
            // Crypto + file enum + file ops + ransom keywords
            (2 of ($cry*) and all of ($enum*) and any of ($file*) and 2 of ($note*))
        )
}

// ============================================
// Downloader/Dropper - Context required
// ============================================

rule Dropper_Download_Execute {
    meta:
        description = "Download and execute pattern"
        severity = "medium"
    
    strings:
        // Download functions
        $dl1 = "URLDownloadToFile" ascii
        $dl2 = "URLDownloadToCacheFile" ascii
        // Execution
        $exec1 = "ShellExecute" ascii
        $exec2 = "CreateProcess" ascii
        $exec3 = "WinExec" ascii
        // Temp paths (where droppers typically write)
        $temp1 = "\\Temp\\" ascii wide
        $temp2 = "%TEMP%" ascii wide
        $temp3 = "GetTempPath" ascii
    
    condition:
        uint16(0) == 0x5A4D and
        any of ($dl*) and any of ($exec*) and any of ($temp*)
}

// ============================================
// Anti-Analysis - Only flag heavy usage
// ============================================

rule Anti_Analysis_Heavy {
    meta:
        description = "Heavy anti-analysis techniques"
        severity = "medium"
        // Light anti-debug is common in legitimate software
    
    strings:
        // Anti-debugging
        $dbg1 = "IsDebuggerPresent" ascii
        $dbg2 = "CheckRemoteDebuggerPresent" ascii
        $dbg3 = "NtQueryInformationProcess" ascii
        // Anti-VM
        $vm1 = "VIRTUAL" ascii wide
        $vm2 = "VMWARE" ascii wide nocase
        $vm3 = "VBOX" ascii wide nocase
        $vm4 = "QEMU" ascii wide nocase
        // Anti-sandbox
        $sb1 = "SbieDll" ascii wide
        $sb2 = "snxhk" ascii wide
        $sb3 = "cuckoomon" ascii wide nocase
        // Timing checks (multiple)
        $time1 = "GetTickCount" ascii
        $time2 = "QueryPerformanceCounter" ascii
        $time3 = "rdtsc" ascii
    
    condition:
        uint16(0) == 0x5A4D and
        (
            // Need 3+ anti-debug techniques
            (3 of ($dbg*)) or
            // Or anti-VM combined with anti-debug
            (any of ($dbg*) and 2 of ($vm*)) or
            // Or sandbox detection
            any of ($sb*) or
            // Or timing checks paired with anti-debugging
            (2 of ($time*) and any of ($dbg*))
        )
}

// ============================================
// PowerShell Abuse - High confidence patterns
// ============================================

rule PowerShell_Encoded_Command {
    meta:
        description = "Encoded PowerShell execution"
        severity = "high"
    
    strings:
        $ps = "powershell" ascii wide nocase
        $enc1 = "-enc " ascii wide nocase
        $enc2 = "-encodedcommand" ascii wide nocase
        $enc3 = "-e " ascii wide nocase
        $bypass1 = "-exec bypass" ascii wide nocase
        $bypass2 = "-executionpolicy bypass" ascii wide nocase
        $hidden = "-windowstyle hidden" ascii wide nocase
        $nop = "-nop" ascii wide nocase
    
    condition:
        $ps and (any of ($enc*) or (any of ($bypass*) and ($hidden or $nop)))
}

rule PowerShell_Download_Cradle {
    meta:
        description = "PowerShell download and execute"
        severity = "high"
    
    strings:
        $ps = "powershell" ascii wide nocase
        $dl1 = "downloadstring" ascii wide nocase
        $dl2 = "downloadfile" ascii wide nocase
        $dl3 = "invoke-webrequest" ascii wide nocase
        $dl4 = "wget" ascii wide nocase
        $dl5 = "curl" ascii wide nocase
        $iex1 = "iex" ascii wide nocase
        $iex2 = "invoke-expression" ascii wide nocase
        $net = "Net.WebClient" ascii wide nocase
    
    condition:
        $ps and (any of ($dl*) and any of ($iex*)) or ($net and any of ($iex*))
}

// ============================================
// AMSI/ETW Bypass - Security tool evasion
// ============================================

rule AMSI_Bypass {
    meta:
        description = "AMSI bypass attempt"
        severity = "high"
    
    strings:
        $amsi1 = "AmsiScanBuffer" ascii wide
        $amsi2 = "amsi.dll" ascii wide nocase
        $patch1 = { B8 57 00 07 80 }  // mov eax, 0x80070057 (E_INVALIDARG)
        $patch2 = { 31 C0 C3 }        // xor eax, eax; ret
        $patch3 = { 33 C0 C3 }        // xor eax, eax; ret
        $mem1 = "VirtualProtect" ascii
        $mem2 = "WriteProcessMemory" ascii
    
    condition:
        any of ($amsi*) and (any of ($patch*) or any of ($mem*))
}

rule ETW_Bypass {
    meta:
        description = "ETW bypass attempt"
        severity = "high"
    
    strings:
        $etw1 = "EtwEventWrite" ascii wide
        $etw2 = "NtTraceEvent" ascii wide
        $patch1 = { C2 14 00 }        // ret 0x14
        $patch2 = { 48 33 C0 C3 }     // xor rax, rax; ret
        $mem = "VirtualProtect" ascii
    
    condition:
        any of ($etw*) and (any of ($patch*) or $mem)
}

// ============================================
// Persistence - Requires specific combinations
// ============================================

rule Persistence_Registry_Run {
    meta:
        description = "Registry Run key persistence"
        severity = "low"
        false_positive = "Many legitimate apps add themselves to startup"
    
    strings:
        $key1 = "\\CurrentVersion\\Run" ascii wide nocase
        $key2 = "\\CurrentVersion\\RunOnce" ascii wide nocase
        $api1 = "RegSetValueEx" ascii
        $api2 = "RegCreateKeyEx" ascii
    
    condition:
        uint16(0) == 0x5A4D and
        any of ($key*) and any of ($api*)
}

rule Persistence_Scheduled_Task {
    meta:
        description = "Scheduled task creation"
        severity = "low"
        false_positive = "Legitimate software may create scheduled tasks"
    
    strings:
        $cmd1 = "schtasks" ascii wide nocase
        $cmd2 = "/create" ascii wide nocase
        $api1 = "ITaskScheduler" ascii wide
        $api2 = "ITaskService" ascii wide
    
    condition:
        uint16(0) == 0x5A4D and
        (($cmd1 and $cmd2) or any of ($api*))
}

rule Persistence_Service {
    meta:
        description = "Service creation for persistence"
        severity = "low"
        false_positive = "Legitimate software may create services"
    
    strings:
        $api1 = "CreateService" ascii
        $api2 = "OpenSCManager" ascii
        $cmd1 = "sc create" ascii wide nocase
        $cmd2 = "sc.exe" ascii wide nocase
    
    condition:
        uint16(0) == 0x5A4D and
        (all of ($api*) or ($cmd2 and $cmd1))
}

// ============================================
// Screen/Clipboard Capture - Context required
// ============================================

rule Screen_Capture_With_Exfil {
    meta:
        description = "Screen capture with potential exfiltration"
        severity = "medium"
        // Screen capture alone is legitimate (screenshot tools)
        // Only flag when combined with network
    
    strings:
        // Capture APIs
        $cap1 = "BitBlt" ascii
        $cap2 = "GetDC" ascii
        $cap3 = "CreateCompatibleBitmap" ascii
        // Plus network or file operations
        $net1 = "send" ascii
        $net2 = "WSASend" ascii
        $net3 = "InternetWriteFile" ascii
        $file1 = "CreateFile" ascii
        $file2 = "WriteFile" ascii
    
    condition:
        uint16(0) == 0x5A4D and
        all of ($cap*) and (any of ($net*) or all of ($file*))
}

rule Clipboard_Monitoring {
    meta:
        description = "Clipboard monitoring"
        severity = "low"
    
    strings:
        $clip1 = "GetClipboardData" ascii
        $clip2 = "SetClipboardViewer" ascii
        $clip3 = "AddClipboardFormatListener" ascii
        $loop = "while" ascii
        $sleep = "Sleep" ascii
    
    condition:
        uint16(0) == 0x5A4D and
        2 of ($clip*) and ($loop or $sleep)
}
