/*
 * CyberNova — Blocklist Management
 * Hash-table backed blocklist for the minifilter driver.
 * Supports hot-update via IOCTL or filter communication port.
 */

#include <fltKernel.h>
#include <wdm.h>
#include "cybernova.h"

#define BLOCKLIST_BUCKETS 8192

static LIST_ENTRY s_Buckets[BLOCKLIST_BUCKETS];
static FAST_MUTEX s_BucketLocks[BLOCKLIST_BUCKETS];

//
// Jenkins one-at-a-time hash over the SHA-256 to pick a bucket
//
static UINT32
_HashBucket(
    _In_reads_(32) PUCHAR Hash
)
{
    UINT32 h = 0;
    for (UINT32 i = 0; i < 32; i++) {
        h += Hash[i];
        h += (h << 10);
        h ^= (h >> 6);
    }
    h += (h << 3);
    h ^= (h >> 11);
    h += (h << 15);
    return h % BLOCKLIST_BUCKETS;
}

//
// Compare two SHA-256 hashes
//
static BOOLEAN
_HashEqual(
    _In_reads_(32) PUCHAR A,
    _In_reads_(32) PUCHAR B
)
{
    for (UINT32 i = 0; i < 32; i++) {
        if (A[i] != B[i]) return FALSE;
    }
    return TRUE;
}

//
// Initialize the blocklist subsystem
//
NTSTATUS
BlInitialize(VOID)
{
    for (UINT32 i = 0; i < BLOCKLIST_BUCKETS; i++) {
        InitializeListHead(&s_Buckets[i]);
        ExInitializeFastMutex(&s_BucketLocks[i]);
    }
    InitializeListHead(&g_CyberNova.BlocklistHead);
    ExInitializeFastMutex(&g_CyberNova.BlocklistMutex);
    return STATUS_SUCCESS;
}

//
// Teardown — free all entries
//
VOID
BlTeardown(VOID)
{
    g_CyberNova.ShuttingDown = TRUE;

    for (UINT32 i = 0; i < BLOCKLIST_BUCKETS; i++) {
        ExAcquireFastMutex(&s_BucketLocks[i]);
        while (!IsListEmpty(&s_Buckets[i])) {
            PLIST_ENTRY entry = RemoveHeadList(&s_Buckets[i]);
            PBLOCKLIST_ENTRY bl = CONTAINING_RECORD(entry, BLOCKLIST_ENTRY, ListEntry);
            ExFreePoolWithTag(bl, CYBERNOVA_POOL_TAG);
        }
        ExReleaseFastMutex(&s_BucketLocks[i]);
    }
}

//
// Look up a hash in the blocklist
// Returns TRUE if the hash is blocked, FALSE if allowed
//
BOOLEAN
BlLookup(
    _In_reads_(32) PUCHAR Hash
)
{
    UINT32 bucket = _HashBucket(Hash);
    BOOLEAN blocked = FALSE;

    ExAcquireFastMutex(&s_BucketLocks[bucket]);
    {
        PLIST_ENTRY current = s_Buckets[bucket].Flink;
        while (current != &s_Buckets[bucket]) {
            PBLOCKLIST_ENTRY bl = CONTAINING_RECORD(current, BLOCKLIST_ENTRY, ListEntry);
            if (bl->IsActive && _HashEqual(Hash, bl->Hash)) {
                blocked = TRUE;
                break;
            }
            current = current->Flink;
        }
    }
    ExReleaseFastMutex(&s_BucketLocks[bucket]);

    return blocked;
}

//
// Add an entry to the blocklist
//
NTSTATUS
BlAddEntry(
    _In_reads_(32) PUCHAR Hash,
    _In_ UINT32 Severity,
    _In_ PCWSTR Description
)
{
    PBLOCKLIST_ENTRY entry = (PBLOCKLIST_ENTRY)
        ExAllocatePoolWithTag(NonPagedPool, sizeof(BLOCKLIST_ENTRY), CYBERNOVA_POOL_TAG);
    if (!entry) return STATUS_INSUFFICIENT_RESOURCES;

    RtlCopyMemory(entry->Hash, Hash, 32);
    entry->AddedTimestamp = KeQueryInterruptTime();
    entry->Severity = min(Severity, 100);
    entry->IsActive = TRUE;

    RtlZeroMemory(entry->Description, sizeof(entry->Description));
    if (Description) {
        RtlStringCbCopyW(entry->Description, sizeof(entry->Description), Description);
    }

    UINT32 bucket = _HashBucket(Hash);
    ExAcquireFastMutex(&s_BucketLocks[bucket]);
    InsertTailList(&s_Buckets[bucket], &entry->ListEntry);
    ExReleaseFastMutex(&s_BucketLocks[bucket]);

    InterlockedIncrement((LONG*)&g_CyberNova.Stats.BlocklistEntries);
    return STATUS_SUCCESS;
}

//
// Clear all entries from the blocklist
//
NTSTATUS
BlClearAll(VOID)
{
    for (UINT32 i = 0; i < BLOCKLIST_BUCKETS; i++) {
        ExAcquireFastMutex(&s_BucketLocks[i]);
        while (!IsListEmpty(&s_Buckets[i])) {
            PLIST_ENTRY entry = RemoveHeadList(&s_Buckets[i]);
            PBLOCKLIST_ENTRY bl = CONTAINING_RECORD(entry, BLOCKLIST_ENTRY, ListEntry);
            ExFreePoolWithTag(bl, CYBERNOVA_POOL_TAG);
        }
        ExReleaseFastMutex(&s_BucketLocks[i]);
    }

    g_CyberNova.Stats.BlocklistEntries = 0;
    g_CyberNova.BlocklistVersion = 0;
    return STATUS_SUCCESS;
}

//
// Batch update — replaces entire blocklist from userspace buffer
//
NTSTATUS
BlBatchUpdate(
    _In_reads_bytes_(BufferSize) PUCHAR Buffer,
    _In_ ULONG BufferSize
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PBLOCKLIST_UPDATE update = (PBLOCKLIST_UPDATE)Buffer;

    if (BufferSize < sizeof(BLOCKLIST_UPDATE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    // Clear existing
    BlClearAll();

    UINT32 numEntries = update->NumEntries;
    ULONG expectedSize = sizeof(BLOCKLIST_UPDATE) +
        numEntries * sizeof(BLOCKLIST_UPDATE_ENTRY);

    if (BufferSize < expectedSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    PBLOCKLIST_UPDATE_ENTRY entries =
        (PBLOCKLIST_UPDATE_ENTRY)(Buffer + sizeof(BLOCKLIST_UPDATE));

    for (UINT32 i = 0; i < numEntries; i++) {
        status = BlAddEntry(
            entries[i].Hash,
            entries[i].Severity,
            entries[i].Description
        );
        if (!NT_SUCCESS(status)) {
            break;
        }
    }

    g_CyberNova.BlocklistVersion++;
    return status;
}
