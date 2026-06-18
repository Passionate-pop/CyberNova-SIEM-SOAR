from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Set


RANSOMWARE_EXTENSIONS: Set[str] = {
    ".crypted", ".locked", ".encrypted", ".enc", ".ransomware", ".crypt",
    ".locky", ".cerber", ".wallet", ".onion", ".cryptolocker", ".filock",
    ".scarab", ".dmde", ".vvv", ".xxx", ".ttt", ".micro", ".cry", ".crptr",
    ".ezzze", ".zepto", ".bla", ".aes", ".rijndael",
}

RANSOMWARE_FILES: Set[str] = {
    "ransomnote", "how_to_decrypt", "readme", "help_your_files",
    "help_restore", "how_to_back", "where_my_files", "recover",
    "decrypt_instructions", "restore_files", "contact_info",
}

RANSOMWARE_PROCESS_INDICATORS: Set[str] = {
    "vssadmin.exe", "wmic.exe", "bcdedit.exe", "powershell.exe",
    "schtasks.exe", "reg.exe", "cipher.exe", "wevtutil.exe",
}

HIGH_RISK_COMMANDS: List[str] = [
    "vssadmin delete shadows",
    "wmic shadowcopy delete",
    "bcdedit /set {default} recoveryenabled no",
    "bcdedit /set {default} bootstatuspolicy ignoreallfailures",
    "wevtutil cl",
    "cipher /w:",
    "reg delete",
    "fsutil behavior set disablelastaccess",
    "netsh advfirewall set allprofiles state off",
    "sc config windefend start= disabled",
    "net stop",
    "schtasks /change /disable",
]

SHADOW_COPY_DELETION_TOOLS: List[str] = [
    "vssadmin.exe", "wmic.exe", "powershell.exe",
]

ENCRYPTION_TOOLS: List[str] = [
    "gpg.exe", "openssl.exe", "certutil.exe",
]

SENSITIVE_DIRECTORIES: List[str] = [
    "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy",
    "C:\\Windows\\System32\\winevt\\Logs",
    "C:\\Windows\\System32\\config",
]


@dataclass
class RansomwareIndicator:
    name: str
    description: str
    stage: int
    weight: float
    mitre_technique: str = ""
    mitre_id: str = ""


PRE_EXECUTION_INDICATORS: List[RansomwareIndicator] = [
    RansomwareIndicator("reconnaissance_shares", "Scanning network shares", 1, 0.2, "Network Share Discovery", "T1135"),
    RansomwareIndicator("defense_disabled", "Security tool/service disabled", 1, 0.3, "Disable or Modify Tools", "T1562.001"),
    RansomwareIndicator("firewall_disabled", "Windows firewall disabled", 1, 0.25, "Disable or Modify System Firewall", "T1562.004"),
    RansomwareIndicator("shadow_copy_deletion", "Volume shadow copy deleted", 1, 0.4, "Inhibit System Recovery", "T1490"),
    RansomwareIndicator("backup_deletion", "Backup files deleted", 1, 0.35, "Data Destruction", "T1485"),
]

EXECUTION_INDICATORS: List[RansomwareIndicator] = [
    RansomwareIndicator("suspicious_process", "Ransomware-related process spawned", 2, 0.3, "User Execution", "T1204"),
    RansomwareIndicator("encoded_powershell", "Encoded PowerShell command detected", 2, 0.25, "Obfuscated Files or Info", "T1027"),
    RansomwareIndicator("privilege_escalation", "Privilege escalation attempt", 2, 0.2, "Privilege Escalation", "T1068"),
    RansomwareIndicator("persistence_installed", "Persistence mechanism installed", 2, 0.2, "Boot or Logon Persistence", "T1547"),
    RansomwareIndicator("lateral_movement", "Lateral movement detected", 2, 0.3, "Remote Services", "T1021"),
]

ENCRYPTION_INDICATORS: List[RansomwareIndicator] = [
    RansomwareIndicator("mass_file_modification", "Mass file encryption/modification", 3, 0.5, "Data Encrypted for Impact", "T1486"),
    RansomwareIndicator("ransomware_extension", "Files created with ransomware extension", 3, 0.45, "Data Encrypted for Impact", "T1486"),
    RansomwareIndicator("ransomware_note", "Ransom note created", 3, 0.4, "Data Encrypted for Impact", "T1486"),
    RansomwareIndicator("file_type_change", "Mass file type/header changed", 3, 0.45, "Data Encrypted for Impact", "T1486"),
    RansomwareIndicator("high_entropy_writes", "High entropy file writes detected", 3, 0.35, "Data Encrypted for Impact", "T1486"),
    RansomwareIndicator("mass_file_rename", "Mass file renaming", 3, 0.4, "Data Encrypted for Impact", "T1486"),
]

POST_EXECUTION_INDICATORS: List[RansomwareIndicator] = [
    RansomwareIndicator("c2_communication", "C2 communication established", 4, 0.3, "Application Layer Protocol", "T1071"),
    RansomwareIndicator("data_exfiltration", "Data exfiltration attempt", 4, 0.25, "Exfiltration Over C2 Channel", "T1041"),
    RansomwareIndicator("ransomnote_display", "Ransom note displayed to user", 4, 0.35, "Impact", "T1491"),
    RansomwareIndicator("system_locked", "System locked or desktop changed", 4, 0.3, "System Shutdown/Reboot", "T1529"),
]

ALL_INDICATORS: List[RansomwareIndicator] = (
    PRE_EXECUTION_INDICATORS + EXECUTION_INDICATORS +
    ENCRYPTION_INDICATORS + POST_EXECUTION_INDICATORS
)

STAGE_NAMES: Dict[int, str] = {
    1: "Pre-Execution",
    2: "Execution",
    3: "Encryption",
    4: "Post-Execution",
}
