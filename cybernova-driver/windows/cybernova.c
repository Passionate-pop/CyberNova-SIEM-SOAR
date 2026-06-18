/*
 * CyberNova Antivirus — Windows Minifilter Driver
 *
 * Registers a minifilter with the Filter Manager.
 * Pre-create + post-create pattern to compute file SHA-256
 * and check against the runtime blocklist WITHOUT TOCTOU:
 *   - Pre-create: identify execute requests
 *   - Post-create: read file content via FltReadFile on the
 *     already-opened stream (same file object, no re-open race)
 *   - If malicious: FltCancelFileOpen + STATUS_ACCESS_DENIED
 *
 * Userspace communication via FilterSendMessage (filter port) or IOCTL.
 */

#include <fltKernel.h>
#include <wdm.h>
#include <ntstrsafe.h>
#include <bcrypt.h>
#include "cybernova.h"

CYBERNOVA_GLOBALS g_CyberNova = {0};

#define CYBERNOVA_DRIVER_VERSION 0x0100

//
// Completion context — passed from pre-create to post-create
//
typedef struct _SCAN_CONTEXT {
    BOOLEAN ScanRequired;
} SCAN_CONTEXT, *PSCAN_CONTEXT;

//
// Forward declarations
//
DRIVER_INITIALIZE DriverEntry;
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT, _In_ PUNICODE_STRING);
NTSTATUS CyberNovaInstanceSetup(_In_ PCFLT_RELATED_OBJECTS, _In_ FLT_INSTANCE_SETUP_FLAGS,
                                 _In_ DEVICE_TYPE, _In_ FLT_FILESYSTEM_TYPE);
NTSTATUS CyberNovaInstanceQueryTeardown(_In_ PCFLT_RELATED_OBJECTS, _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS);
VOID CyberNovaUnload(_In_ FLT_FILTER_UNLOAD_FLAGS);
FLT_PREOP_CALLBACK_STATUS CyberNovaPreCreate(_Inout_ PFLT_CALLBACK_DATA,
                                              _In_ PCFLT_RELATED_OBJECTS,
                                              _Flt_CompletionContext_ OutOpt_ PVOID *);
FLT_POSTOP_CALLBACK_STATUS CyberNovaPostCreate(_Inout_ PFLT_CALLBACK_DATA,
                                                _In_ PCFLT_RELATED_OBJECTS,
                                                _In_opt_ PVOID CompletionContext,
                                                _In_ FLT_POST_OPERATION_FLAGS Flags);
NTSTATUS CyberNovaCommPortReply(_In_ PFLT_PORT, _In_reads_bytes_opt_(Size) PVOID,
                                 _In_ ULONG Size, _Out_writes_bytes_opt_(*Size) PVOID,
                                 _Out_ PULONG Size);
VOID CyberNovaCommPortDisconnect(_In_opt_ PVOID);

//
// Hash file content via the already-opened file object (no TOCTOU)
//
static NTSTATUS
_ComputeHashFromFileObject(
    _In_ PFILE_OBJECT FileObject,
    _In_ PFLT_INSTANCE Instance,
    _Out_writes_bytes_(32) PUCHAR HashOut
)
{
    NTSTATUS status;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    LARGE_INTEGER byteOffset = {0};
    UCHAR buffer[65536];
    ULONG hashLength = 32;
    ULONG bytesRead = 0;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) return status;

    status = BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return status;
    }

    while (TRUE) {
        status = FltReadFile(Instance, FileObject, &byteOffset,
                             sizeof(buffer), buffer, FLTFL_IO_SYNCHRONOUS,
                             &bytesRead, NULL, NULL);
        if (!NT_SUCCESS(status)) {
            break;
        }
        if (bytesRead == 0) break;

        BCryptHashData(hHash, buffer, bytesRead, 0);
        byteOffset.QuadPart += bytesRead;
    }

    // EOF is expected — hash what we read
    if (status == STATUS_END_OF_FILE) {
        status = STATUS_SUCCESS;
    }

    if (NT_SUCCESS(status)) {
        BCryptFinishHash(hHash, HashOut, hashLength, 0);
    }

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return status;
}

//
// Pre-create callback — identify execute requests
//
FLT_PREOP_CALLBACK_STATUS
CyberNovaPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_ OutOpt_ PVOID *CompletionContext
)
{
    UNREFERENCED_PARAMETER(CompletionContext);

    if (g_CyberNova.ShuttingDown) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    InterlockedIncrement64(&g_CyberNova.Stats.TotalCreateAttempts);

    // Skip directories and non-file opens
    if (Data->Iopb->TargetFileObject == NULL ||
        Data->Iopb->TargetFileObject->FsContext == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Only check on create dispositions that would execute the file
    UCHAR createDisposition = Data->Iopb->Parameters.Create.Options >> 24;
    if (createDisposition != FILE_CREATE &&
        createDisposition != FILE_OPEN &&
        createDisposition != FILE_OVERWRITE) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Check if it's an executable image
    if (!(Data->Iopb->OperationFlags & SL_OPEN_PAGING_FILE) &&
        (Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess &
         (FILE_EXECUTE | PROCESS_CREATE_PROCESS | PROCESS_CREATE_THREAD))) {

        // Allocate completion context for post-create scanning
        PSCAN_CONTEXT ctx = (PSCAN_CONTEXT)ExAllocatePoolWithTag(
            NonPagedPool, sizeof(SCAN_CONTEXT), CYBERNOVA_POOL_TAG);
        if (ctx) {
            ctx->ScanRequired = TRUE;
            *CompletionContext = ctx;
            return FLT_PREOP_SUCCESS_WITH_CALLBACK;
        }
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

//
// Post-create callback — read file content and check blocklist
// Uses the already-opened file object: NO TOCTOU RACE possible.
//
FLT_POSTOP_CALLBACK_STATUS
CyberNovaPostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{
    PSCAN_CONTEXT ctx = (PSCAN_CONTEXT)CompletionContext;

    if (!ctx || !ctx->ScanRequired) {
        goto done;
    }

    // If the create itself failed, nothing to scan
    if (!NT_SUCCESS(Data->IoStatus.Status)) {
        goto done;
    }

    // Skip if the file object is not valid for reading
    if (FltObjects->FileObject == NULL) {
        goto done;
    }

    // Compute hash from the existing file object (no TOCTOU!)
    UCHAR fileHash[32];
    NTSTATUS status = _ComputeHashFromFileObject(
        FltObjects->FileObject, FltObjects->Instance, fileHash);

    if (!NT_SUCCESS(status)) {
        // Fail-closed: cannot verify = deny
        InterlockedIncrement64(&g_CyberNova.Stats.TotalBlocks);
        FltCancelFileOpen(FltObjects->Instance, FltObjects->FileObject);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        goto done;
    }

    if (BlLookup(fileHash)) {
        InterlockedIncrement64(&g_CyberNova.Stats.TotalBlocks);
        FltCancelFileOpen(FltObjects->Instance, FltObjects->FileObject);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        goto done;
    }

    InterlockedIncrement64(&g_CyberNova.Stats.TotalPasses);

done:
    if (ctx) {
        ExFreePoolWithTag(ctx, CYBERNOVA_POOL_TAG);
    }
    return FLT_POSTOP_FINISHED_PROCESSING;
}

//
// Filter port message handler — receive blocklist updates
//
NTSTATUS
CyberNovaCommPortReply(
    _In_ PFLT_PORT Port,
    _In_reads_bytes_opt_(Size) PVOID Buffer,
    _In_ ULONG Size,
    _Out_writes_bytes_opt_(*Size) PVOID ReplyBuffer,
    _Out_ PULONG ReplySize
)
{
    UNREFERENCED_PARAMETER(Port);
    NTSTATUS status = STATUS_SUCCESS;

    if (Size >= sizeof(BLOCKLIST_UPDATE)) {
        status = BlBatchUpdate((PUCHAR)Buffer, Size);
    }

    if (ReplyBuffer && ReplySize && *ReplySize >= sizeof(NTSTATUS)) {
        *(NTSTATUS*)ReplyBuffer = status;
        *ReplySize = sizeof(NTSTATUS);
    }

    return STATUS_SUCCESS;
}

VOID
CyberNovaCommPortDisconnect(
    _In_opt_ PVOID ConnectionCookie
)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);
}

//
// Instance setup — attach to NTFS/ReFS volumes only
//
NTSTATUS
CyberNovaInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    if (VolumeDeviceType == FILE_DEVICE_CD_ROM ||
        VolumeDeviceType == FILE_DEVICE_VIDEO) {
        return STATUS_FLT_DO_NOT_ATTACH;
    }

    if (VolumeFilesystemType != FLT_FSTYPE_NTFS &&
        VolumeFilesystemType != FLT_FSTYPE_REFS) {
        return STATUS_FLT_DO_NOT_ATTACH;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
CyberNovaInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    return STATUS_SUCCESS;
}

//
// IOCTL dispatch for direct userspace communication
//
static NTSTATUS
_DispatchIoctl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG ioctl = stack->Parameters.DeviceIoControl.IoControlCode;
    PVOID buf = Irp->AssociatedIrp.SystemBuffer;
    ULONG inSize = stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outSize = stack->Parameters.DeviceIoControl.OutputBufferLength;

    switch (ioctl) {
    case IOCTL_CYBERNOVA_UPDATE_BLOCKLIST:
        if (buf && inSize >= sizeof(BLOCKLIST_UPDATE)) {
            status = BlBatchUpdate((PUCHAR)buf, inSize);
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case IOCTL_CYBERNOVA_CLEAR_BLOCKLIST:
        status = BlClearAll();
        break;

    case IOCTL_CYBERNOVA_GET_STATS:
        if (buf && outSize >= sizeof(CYBERNOVA_STATS)) {
            RtlCopyMemory(buf, &g_CyberNova.Stats, sizeof(CYBERNOVA_STATS));
            Irp->IoStatus.Information = sizeof(CYBERNOVA_STATS);
            status = STATUS_SUCCESS;
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

//
// Driver entry
//
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;
    FLT_REGISTRATION reg = {0};

    reg.Size = sizeof(FLT_REGISTRATION);
    reg.Version = FLT_REGISTRATION_VERSION;
    reg.Flags = 0;
    reg.FilterUnloadCallback = CyberNovaUnload;
    reg.InstanceSetupCallback = CyberNovaInstanceSetup;
    reg.InstanceQueryTeardownCallback = CyberNovaInstanceQueryTeardown;
    reg.InstanceTeardownStartCallback = NULL;
    reg.InstanceTeardownCompleteCallback = NULL;

    // Register pre-create + post-create operations
    FLT_OPERATION_REGISTRATION opReg[] = {
        {IRP_MJ_CREATE, 0, CyberNovaPreCreate, CyberNovaPostCreate},
        {IRP_OPERATION_REGISTRATION_END}
    };
    reg.OperationRegistration = opReg;

    // Normalize name suffix
    FLT_NAME_CONTROL nameCtl;
    nameCtl.FilterName.Buffer = NULL;
    nameCtl.FilterName.MaximumLength = 0;
    nameCtl.FilterInstanceName.Buffer = NULL;
    nameCtl.FilterInstanceName.MaximumLength = 0;

    // Register with filter manager
    status = FltRegisterFilter(DriverObject, &reg, &g_CyberNova.FilterHandle);
    if (!NT_SUCCESS(status)) return status;

    // Initialize blocklist
    BlInitialize();

    // Create communication port for userspace
    UNICODE_STRING portName;
    RtlInitUnicodeString(&portName, CYBERNOVA_COMM_PORT_NAME);

    status = FltCreateCommunicationPort(
        g_CyberNova.FilterHandle,
        &g_CyberNova.CommPort,
        &portName,
        NULL, NULL,
        CyberNovaCommPortReply,
        CyberNovaCommPortDisconnect,
        NULL, 0
    );
    if (!NT_SUCCESS(status)) {
        DbgPrint("CyberNova: Failed to create comm port: 0x%08x\n", status);
    }

    // Create control device for IOCTL
    UNICODE_STRING devName, symLink;
    RtlInitUnicodeString(&devName, CYBERNOVA_DEVICE_NAME);
    RtlInitUnicodeString(&symLink, CYBERNOVA_SYMLINK_NAME);

    status = IoCreateDevice(DriverObject, 0, &devName,
                            FILE_DEVICE_UNKNOWN, 0, FALSE,
                            &g_CyberNova.DeviceObject);
    if (NT_SUCCESS(status)) {
        IoCreateSymbolicLink(&symLink, &devName);
        DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = _DispatchIoctl;
        g_CyberNova.DeviceObject->Flags |= DO_DIRECT_IO;
    }

    // Start filtering
    status = FltStartFiltering(g_CyberNova.FilterHandle);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(g_CyberNova.FilterHandle);
        return status;
    }

    DbgPrint("CyberNova v%d.%d loaded (TOCTOU-free post-create scanning)\n",
             (CYBERNOVA_DRIVER_VERSION >> 8) & 0xFF,
             CYBERNOVA_DRIVER_VERSION & 0xFF);

    return STATUS_SUCCESS;
}

//
// Unload
//
VOID
CyberNovaUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Flags);

    g_CyberNova.ShuttingDown = TRUE;

    if (g_CyberNova.CommPort) {
        FltCloseCommunicationPort(g_CyberNova.CommPort);
    }

    BlTeardown();

    if (g_CyberNova.DeviceObject) {
        UNICODE_STRING symLink;
        RtlInitUnicodeString(&symLink, CYBERNOVA_SYMLINK_NAME);
        IoDeleteSymbolicLink(&symLink);
        IoDeleteDevice(g_CyberNova.DeviceObject);
    }

    if (g_CyberNova.FilterHandle) {
        FltUnregisterFilter(g_CyberNova.FilterHandle);
    }

    DbgPrint("CyberNova unloaded\n");
}
