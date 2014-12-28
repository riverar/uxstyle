#include "uxpatch.h"

// Device Object I create for user-moders
PDEVICE_OBJECT        pDeviceObject = NULL;
// These are used for the lookaside list.
LIST_ENTRY            g_ListHead;
NPAGED_LOOKASIDE_LIST g_PgdLookList;
KSPIN_LOCK            g_Lock;

// Logging Info structure
LOGINFO g_liLog;

// Function: OnUnload
// Arg: PDRIVER_OBJECT
// Purpose: So I can unload my driver. Will delete the symbolic link 
//          created by DriverEntry, will delete the device object it
//          created also, and any saved entries in my linked list.
VOID
OnUnload( __in PDRIVER_OBJECT pDriverObject)
{
    ULONG_PTR ulPatched = 0x0;
    UNICODE_STRING usSymLink;

    UNREFERENCED_PARAMETER(pDriverObject);

#ifdef DEBUG
    DbgPrint("Entered OnUnload\n");
#endif

    if (g_liLog.ulLoggingEnabled) LogToFile(g_liLog, "Tearing it all down.\r\n");

    RtlInitUnicodeString(&usSymLink, DOSDEVNAME);
    IoDeleteSymbolicLink(&usSymLink);
    
    IoDeleteDevice(pDeviceObject);
    
    UnPatchAddress(&ulPatched);
    
    ExDeleteNPagedLookasideList(&g_PgdLookList);
}


// Function: DriverEntry
// Arguments: PDRIVER_OBJECT and PUNICODE_STRING
// Purpose: Create device object and symlink to itt so service can access it and send IO_CTLS to
//          the driver. Also will setup a pagable lookaside list for saving virtual addresses
//          that get modified.
NTSTATUS
DriverEntry( __in PDRIVER_OBJECT pDriverObject,
             __in PUNICODE_STRING pRegistryPath )
{
    NTSTATUS Status = STATUS_SUCCESS;
    UNICODE_STRING usSymLink;
    UNICODE_STRING usDevName;
    UNICODE_STRING usUxPatchAcl;
    int i = 0;
    CHAR szErrorMsgBuffer[255];

    InitLogFile(&g_liLog, pRegistryPath);

    if (g_liLog.ulLoggingEnabled) LogToFile(g_liLog, "Initializing\r\n");

    Status = DetermineVersionCompat();

    if (!NT_SUCCESS(Status))
    {
#ifdef DEBUG
        DbgPrint("Windows Version not supported.\n");
#endif
        if (g_liLog.ulLoggingEnabled) LogToFile(g_liLog, "Windows Version is not supported.\r\n");
        return Status;
    }

    RtlInitUnicodeString(&usDevName, DEVNAME);
    RtlInitUnicodeString(&usSymLink, DOSDEVNAME);
    RtlInitUnicodeString(&usUxPatchAcl, UXPATCH_ACL);

    /*Status = IoCreateDevice(pDriverObject,
                            0x0,
                            &usDevName,
                            FILE_DEVICE_UNKNOWN,
                            FILE_DEVICE_SECURE_OPEN,
                            FALSE,
                            &pDeviceObject);*/
    Status = IoCreateDeviceSecure(pDriverObject,
                                  0x0,
                                  &usDevName,
                                  FILE_DEVICE_UNKNOWN,
                                  FILE_DEVICE_SECURE_OPEN,
                                  FALSE,
                                  &usUxPatchAcl,
                                  &UXPATCH_GUID,
                                  &pDeviceObject);
    if ( !NT_SUCCESS(Status) )
    {
#ifdef DEBUG
        DbgPrint("Error IoCreateDevice : %.08X\n", Status);
#endif
        
        if (g_liLog.ulLoggingEnabled) 
        {
            RtlStringCchPrintfA(szErrorMsgBuffer, sizeof(szErrorMsgBuffer), "Critical error in device inti: 0x.08X\r\n", Status);
            LogToFile(g_liLog, szErrorMsgBuffer);
        }
        return Status;
    }

    Status = IoCreateSymbolicLink(&usSymLink, &usDevName);

    if ( !NT_SUCCESS(Status) )
    {
#ifdef DEBUG
        DbgPrint("IoCreateSymLink failed: %.08X\n", Status);
#endif
        if (g_liLog.ulLoggingEnabled)
        {
            RtlStringCchPrintfA(szErrorMsgBuffer, sizeof(szErrorMsgBuffer), "Critical error in sym link init: 0x.08X\r\n", Status);
            LogToFile(g_liLog, szErrorMsgBuffer);
        }
        IoDeleteDevice(pDeviceObject);
        return Status;
    }

    for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
    {
        pDriverObject->MajorFunction[i] = &DispatchMain;
    }

    pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = &DispatchDevCtl;
    pDriverObject->DriverUnload = &OnUnload;
    
    SetFlags(pDeviceObject->Flags, DO_BUFFERED_IO);
    ClearFlags(pDeviceObject->Flags, DO_DEVICE_INITIALIZING);

    KeInitializeSpinLock(&g_Lock);
    ExInitializeNPagedLookasideList(&g_PgdLookList, NULL, NULL, 0, sizeof(SAVEDINFO), TAGSAVEDBYTES, 0);
    InitializeListHead(&g_ListHead);

#ifdef DEBUG
    DbgPrint("Exiting DriverEntry with %.08X\n", Status);
#endif
    return Status;
}