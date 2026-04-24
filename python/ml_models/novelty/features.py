"""
Novelty Feature Extractor
=========================
Extracts 42 behavioral features optimized for Isolation Forest.
NOT the full 2381 EMBER features - IF works better with fewer features.

Feature Categories:
- Section entropy statistics (8)
- Import analysis (8)
- Export statistics (3)
- PE header anomalies (10)
- String entropy (4)
- Packer indicators (5)
- Size statistics (4)
"""

import pefile
import math
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from collections import Counter
import numpy as np
import logging

logger = logging.getLogger(__name__)

NETWORKING_APIS = {
    'wsastartup', 'socket', 'connect', 'send', 'recv', 'bind', 'listen',
    'accept', 'gethostbyname', 'inet_addr', 'httpsendrequesta', 'internetopena',
    'internetopenurla', 'urldownloadtofile', 'winexec', 'ftpputfile',
}

CRYPTO_APIS = {
    'cryptencrypt', 'cryptdecrypt', 'crypthashdata', 'cryptacquirecontext',
    'cryptgenkey', 'cryptimportkey', 'bcryptencrypt', 'bcryptdecrypt',
}

PROCESS_APIS = {
    'createprocess', 'openprocess', 'virtualalloc', 'virtualallocex',
    'writeprocessmemory', 'readprocessmemory', 'createremotethread',
    'ntcreatethreadex', 'rtlcreateuserthread', 'terminateprocess',
}

REGISTRY_APIS = {
    'regopenkeyex', 'regsetvalueex', 'regqueryvalueex', 'regcreatekeyex',
    'regdeletekey', 'regdeletevalue', 'ntsetvaluekey', 'zwsetvaluekey',
}

SUSPICIOUS_APIS = {
    'isdebuggerpresent', 'checkremotedebuggerpresent', 'ntqueryinformationprocess',
    'gettickcont64', 'querperformancecounter', 'outputdebugstring',
    'setwindowshookex', 'keybd_event', 'getasynckeystate', 'getforegroundwindow',
}

PACKER_SECTION_NAMES = {
    '.upx', 'upx0', 'upx1', 'upx2', '.aspack', '.adata', '.nsp0', '.nsp1',
    '.petite', '.mpress', '.themida', '.vmp0', '.vmp1', '.vmp2',
    '.enigma', '.npack', '.wwpack', '.fsg', '.yoda',
}

NORMAL_SECTION_NAMES = {
    '.text', '.data', '.rdata', '.bss', '.idata', '.edata', '.rsrc',
    '.reloc', '.tls', '.pdata', 'code', 'data', '.crt', '.ctors',
}


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte data."""
    if not data:
        return 0.0
    
    byte_counts = Counter(data)
    total = len(data)
    entropy = 0.0
    
    for count in byte_counts.values():
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)
    
    return entropy


def extract_strings(data: bytes, min_length: int = 4) -> List[str]:
    """Extract printable ASCII strings from binary data."""
    strings = []
    current = []
    
    for byte in data:
        if 32 <= byte <= 126:
            current.append(chr(byte))
        else:
            if len(current) >= min_length:
                strings.append(''.join(current))
            current = []
    
    if len(current) >= min_length:
        strings.append(''.join(current))
    
    return strings


class NoveltyFeatureExtractor:
    """
    Feature extractor for Isolation Forest novelty detection.
    Produces 42 behavioral features.
    """
    
    FEATURE_NAMES = [
        "section_entropy_mean", "section_entropy_std", "section_entropy_max",
        "section_entropy_min", "section_count", "executable_section_count",
        "writable_section_count", "abnormal_section_names",
        "import_count", "import_dll_count", "suspicious_import_ratio",
        "api_rarity_score", "networking_api_count", "crypto_api_count",
        "process_api_count", "registry_api_count",
        "export_count", "export_to_import_ratio", "has_exports",
        "header_checksum_valid", "timestamp_in_future", "timestamp_very_old",
        "optional_header_size", "section_alignment", "file_alignment",
        "subsystem", "dll_characteristics", "size_of_code", "address_of_entry_point",
        "string_entropy_mean", "string_entropy_max", "printable_string_ratio", "url_count",
        "is_packed", "packer_score", "overlay_size_ratio", "overlay_entropy", "resource_entropy",
        "file_size_log", "code_to_data_ratio", "header_to_file_ratio", "virtual_to_raw_size_ratio",
    ]
    
    def __init__(self):
        self.feature_names = self.FEATURE_NAMES
    
    @property
    def num_features(self) -> int:
        return len(self.FEATURE_NAMES)
    
    # Skip novelty extraction for files larger than 20 MB.
    # pefile with fast_load=False iterates over every byte multiple times
    # in pure Python; on NSIS/large installers this hangs for minutes and
    # can crash CPython's resource-directory parser.
    MAX_FILE_SIZE = 20 * 1024 * 1024  # 20 MB

    def extract(self, file_path: str) -> Optional[np.ndarray]:
        """Extract 42 features from a PE file."""
        try:
            path = Path(file_path)
            if not path.exists():
                return None

            file_data = path.read_bytes()
            file_size = len(file_data)

            if file_size < 64:
                return None

            if file_size > self.MAX_FILE_SIZE:
                logger.debug(
                    "Skipping novelty extraction for large file "
                    f"({file_size / 1024 / 1024:.1f} MB > "
                    f"{self.MAX_FILE_SIZE / 1024 / 1024:.0f} MB limit): {file_path}"
                )
                return None

            pe = pefile.PE(data=file_data, fast_load=False)
            
            features = {}
            features.update(self._extract_section_features(pe))
            features.update(self._extract_import_features(pe))
            features.update(self._extract_export_features(pe))
            features.update(self._extract_header_features(pe, file_size))
            features.update(self._extract_string_features(file_data))
            features.update(self._extract_packer_features(pe, file_data))
            features.update(self._extract_size_features(pe, file_size))
            
            pe.close()
            
            return np.array([features[name] for name in self.FEATURE_NAMES], dtype=np.float32)
            
        except pefile.PEFormatError:
            return None
        except Exception as e:
            logger.error(f"Feature extraction failed: {e}")
            return None
    
    def _extract_section_features(self, pe: pefile.PE) -> Dict[str, float]:
        """Extract section features."""
        entropies = []
        executable_count = 0
        writable_count = 0
        abnormal_count = 0
        
        for section in pe.sections:
            try:
                data = section.get_data()
                entropies.append(calculate_entropy(data))
                
                chars = section.Characteristics
                if chars & 0x20000000:
                    executable_count += 1
                if chars & 0x80000000:
                    writable_count += 1
                
                name = section.Name.decode('utf-8', errors='ignore').strip('\x00').lower()
                if name in PACKER_SECTION_NAMES:
                    abnormal_count += 1
                elif name not in NORMAL_SECTION_NAMES and name:
                    abnormal_count += 0.5
            except Exception:
                continue
        
        if not entropies:
            entropies = [0.0]
        
        return {
            "section_entropy_mean": np.mean(entropies),
            "section_entropy_std": np.std(entropies),
            "section_entropy_max": np.max(entropies),
            "section_entropy_min": np.min(entropies),
            "section_count": len(pe.sections),
            "executable_section_count": executable_count,
            "writable_section_count": writable_count,
            "abnormal_section_names": abnormal_count,
        }
    
    def _extract_import_features(self, pe: pefile.PE) -> Dict[str, float]:
        """Extract import features."""
        import_count = 0
        dll_count = 0
        networking = crypto = process = registry = suspicious = 0
        
        try:
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                dll_count = len(pe.DIRECTORY_ENTRY_IMPORT)
                
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        import_count += 1
                        if imp.name:
                            name = imp.name.decode('utf-8', errors='ignore').lower()
                            if name in NETWORKING_APIS: networking += 1
                            if name in CRYPTO_APIS: crypto += 1
                            if name in PROCESS_APIS: process += 1
                            if name in REGISTRY_APIS: registry += 1
                            if name in SUSPICIOUS_APIS: suspicious += 1
        except Exception:
            pass
        
        total = max(import_count, 1)
        return {
            "import_count": import_count,
            "import_dll_count": dll_count,
            "suspicious_import_ratio": suspicious / total,
            "api_rarity_score": (networking + crypto + process + registry) / total,
            "networking_api_count": networking,
            "crypto_api_count": crypto,
            "process_api_count": process,
            "registry_api_count": registry,
        }
    
    def _extract_export_features(self, pe: pefile.PE) -> Dict[str, float]:
        """Extract export features."""
        export_count = 0
        has_exports = 0
        
        try:
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                has_exports = 1
                export_count = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
        except Exception:
            pass
        
        import_count = 0
        try:
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    import_count += len(entry.imports)
        except Exception:
            pass
        
        return {
            "export_count": export_count,
            "export_to_import_ratio": export_count / max(import_count, 1),
            "has_exports": has_exports,
        }
    
    def _extract_header_features(self, pe: pefile.PE, file_size: int) -> Dict[str, float]:
        """Extract header features."""
        import time
        
        try:
            checksum_valid = 1 if pe.verify_checksum() else 0
        except Exception:
            checksum_valid = 0
        
        timestamp = pe.FILE_HEADER.TimeDateStamp
        current = int(time.time())
        
        opt = pe.OPTIONAL_HEADER
        return {
            "header_checksum_valid": checksum_valid,
            "timestamp_in_future": 1 if timestamp > current else 0,
            "timestamp_very_old": 1 if timestamp < 946684800 else 0,
            "optional_header_size": pe.FILE_HEADER.SizeOfOptionalHeader,
            "section_alignment": getattr(opt, 'SectionAlignment', 0),
            "file_alignment": getattr(opt, 'FileAlignment', 0),
            "subsystem": getattr(opt, 'Subsystem', 0),
            "dll_characteristics": getattr(opt, 'DllCharacteristics', 0),
            "size_of_code": getattr(opt, 'SizeOfCode', 0),
            "address_of_entry_point": getattr(opt, 'AddressOfEntryPoint', 0),
        }
    
    def _extract_string_features(self, file_data: bytes) -> Dict[str, float]:
        """Extract string features."""
        strings = extract_strings(file_data)
        
        if not strings:
            return {
                "string_entropy_mean": 0.0,
                "string_entropy_max": 0.0,
                "printable_string_ratio": 0.0,
                "url_count": 0,
            }
        
        entropies = [calculate_entropy(s.encode()) for s in strings]
        url_pattern = re.compile(r'https?://|ftp://|www\.')
        url_count = sum(1 for s in strings if url_pattern.search(s))
        total_chars = sum(len(s) for s in strings)
        
        return {
            "string_entropy_mean": np.mean(entropies),
            "string_entropy_max": np.max(entropies),
            "printable_string_ratio": min(total_chars / len(file_data), 1.0),
            "url_count": min(url_count, 100),
        }
    
    def _extract_packer_features(self, pe: pefile.PE, file_data: bytes) -> Dict[str, float]:
        """Extract packer features."""
        packer_score = 0.0
        is_packed = 0
        
        for section in pe.sections:
            name = section.Name.decode('utf-8', errors='ignore').strip('\x00').lower()
            if name in PACKER_SECTION_NAMES:
                packer_score += 2.0
                is_packed = 1
        
        for section in pe.sections:
            try:
                if calculate_entropy(section.get_data()) > 7.0:
                    packer_score += 1
                    is_packed = 1
            except Exception:
                continue
        
        overlay_size = 0
        overlay_entropy = 0.0
        try:
            offset = pe.get_overlay_data_start_offset()
            if offset:
                overlay_data = file_data[offset:]
                overlay_size = len(overlay_data)
                if overlay_size > 0:
                    overlay_entropy = calculate_entropy(overlay_data)
        except Exception:
            pass
        
        resource_entropy = 0.0
        try:
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                resource_data = b''
                def collect(entry):
                    nonlocal resource_data
                    if hasattr(entry, 'data'):
                        try:
                            resource_data += pe.get_data(entry.data.struct.OffsetToData, entry.data.struct.Size)
                        except Exception:
                            pass
                    if hasattr(entry, 'directory'):
                        for e in entry.directory.entries:
                            collect(e)
                for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    collect(entry)
                if resource_data:
                    resource_entropy = calculate_entropy(resource_data)
        except Exception:
            pass
        
        return {
            "is_packed": is_packed,
            "packer_score": min(packer_score, 10.0),
            "overlay_size_ratio": min(overlay_size / len(file_data), 1.0) if file_data else 0,
            "overlay_entropy": overlay_entropy,
            "resource_entropy": resource_entropy,
        }
    
    def _extract_size_features(self, pe: pefile.PE, file_size: int) -> Dict[str, float]:
        """Extract size features."""
        opt = pe.OPTIONAL_HEADER
        size_of_code = getattr(opt, 'SizeOfCode', 0)
        size_of_data = getattr(opt, 'SizeOfInitializedData', 0)
        size_of_headers = getattr(opt, 'SizeOfHeaders', 0)
        
        total_virtual = sum(s.Misc_VirtualSize for s in pe.sections)
        total_raw = sum(s.SizeOfRawData for s in pe.sections)
        
        return {
            "file_size_log": math.log10(max(file_size, 1)),
            "code_to_data_ratio": min(size_of_code / max(size_of_data, 1), 100.0),
            "header_to_file_ratio": size_of_headers / max(file_size, 1),
            "virtual_to_raw_size_ratio": min(total_virtual / max(total_raw, 1), 100.0),
        }


def batch_extract(file_paths: List[str], show_progress: bool = True) -> Tuple[np.ndarray, List[str]]:
    """Extract features from multiple files."""
    extractor = NoveltyFeatureExtractor()
    features_list = []
    successful = []
    
    iterator = file_paths
    if show_progress:
        try:
            from tqdm import tqdm
            iterator = tqdm(file_paths, desc="Extracting features")
        except ImportError:
            pass
    
    for path in iterator:
        features = extractor.extract(path)
        if features is not None:
            features_list.append(features)
            successful.append(path)
    
    if not features_list:
        return np.array([]), []
    
    return np.vstack(features_list), successful
