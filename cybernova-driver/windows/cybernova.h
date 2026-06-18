/*
 * CyberNova Antivirus Minifilter Driver
 * 
 * Registers for IRP_MJ_CREATE and checks file hashes against
 * a runtime-updatable blocklist. Blocks execution of known-bad files.
 */

#pragma once

#define CYBERNOVA_POOL_TAG 'vNBC'
#define CYBERNOVA_BLOCKLIST_MAX 65536
#define CYBERNOVA_COMM_PORT_NAME L"\\CyberNovaPort"
#define CYBERNOVA_DEVICE_NAME L"\\Device\\CyberNovaAV"
#define CYBERNOVA_SYMLINK_NAME L"\\DosDevices\\CyberNovaAV"

// IOCTL codes for userspace communication
#define IOCTL_CYBERNOVA_UPDATE_BLOCKLIST \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CYBERNOVA_CLEAR_BLOCKLIST \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CYBERNOVA_GET_STATS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Blocklist entry in the hash table
typedef struct _BLOCKLIST_ENTRY {
    LIST_ENTRY ListEntry;
    UCHAR Hash[32];            // SHA-256 hash
    UINT64 AddedTimestamp;     // When this entry was added
    UINT32 Severity;           // 0-100 severity
    WCHAR Description[128];    // Human-readable description
    BOOLEAN IsActive;
} BLOCKLIST_ENTRY, *PBLOCKLIST_ENTRY;

// Communication from userspace to update blocklist
typedef struct _BLOCKLIST_UPDATE {
    UINT32 NumEntries;
    UINT32 Reserved;
    // Followed by BLOCKLIST_UPDATE_ENTRY entries
} BLOCKLIST_UPDATE, *PBLOCKLIST_UPDATE;

typedef struct _BLOCKLIST_UPDATE_ENTRY {
    UCHAR Hash[32];
    UINT32 Severity;
    WCHAR Description[128];
} BLOCKLIST_UPDATE_ENTRY, *PBLOCKLIST_UPDATE_ENTRY;

// Driver statistics
typedef struct _CYBERNOVA_STATS {
    UINT64 TotalCreateAttempts;
    UINT64 TotalBlocks;
    UINT64 TotalPasses;
    UINT32 BlocklistEntries;
    UINT32 BlocklistVersion;
} CYBERNOVA_STATS, *PCYBERNOVA_STATS;

// Global driver state
typedef struct _CYBERNOVA_GLOBALS {
    PFLT_FILTER FilterHandle;
    PDEVICE_OBJECT DeviceObject;
    PFLT_PORT CommPort;
    LIST_ENTRY BlocklistHead;
    FAST_MUTEX BlocklistMutex;
    KSPIN_LOCK HashLock;
    CYBERNOVA_STATS Stats;
    UINT32 BlocklistVersion;
    BOOLEAN ShuttingDown;
} CYBERNOVA_GLOBALS, *PCYBERNOVA_GLOBALS;

extern CYBERNOVA_GLOBALS g_CyberNova;
