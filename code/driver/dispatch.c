#include "uxpatch.h"

// Function: DispatchDevCtl
// Arguments: PDEVICE_OBJECT, PIRP
// Return: NTSTATUS
// Purpose: Receives IO_CTLs sent by either usermode applications via DeviceIoControl or
//          by other drivers that sent it IRP's with IoBuildDeviceIoControlRequest.
//          It currently supports two calls, IOCTL_PATCH_ADDR and IOCTL_UNPATCH_ADDR.
//          IOCTL_PATCH_ADDR will patch virtual addresses given in a buffer and IOCTL_UNPATCH_ADDR
//          will unpatch those addresses. WARNING! You must be in the usermode context that sent the
//          initially PATCH_ADDR code or you may overwrite random parts of physical memory when trying
//          to unpatch the addresses.
NTSTATUS
DispatchDevCtl( __in PDEVICE_OBJECT pDevObj,
                __in PIRP pIrp )
{  
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG_PTR ulInfo = 0x1;
    PIO_STACK_LOCATION pIoStackLoc = IoGetCurrentIrpStackLocation(pIrp);

    UNREFERENCED_PARAMETER(pDevObj);

    switch ( pIoStackLoc->Parameters.DeviceIoControl.IoControlCode)
    {
        case IOCTL_PATCH_ADDR:
#ifdef DEBUG
            DbgPrint("Received IOCTL_PATCH_ADDR..\n");
#endif
            Status = PatchAddress(pIrp, pIoStackLoc, &ulInfo);
            break;
        case IOCTL_UNPATCH_ADDR:
#ifdef DEBUG
            DbgPrint("Received IOCTL_UNPATCH_ADDR..\n");
#endif
            Status = UnPatchAddress(&ulInfo);
#ifdef DEBUG
            DbgPrint("%X\n", (ULONG)ulInfo);
#endif
            break;
        case IOCTL_DUMP_PATCHED_ADDR:
#ifdef DEBUG
            DbgPrint("Dumping patched addresses.\n");
#endif
            Status = DumpPatchedAddresses();
            break;
        default:
            break;// Do Nothing Yet.
    }

    pIrp->IoStatus.Status = Status;
    pIrp->IoStatus.Information = ulInfo;

    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return Status;
}


// Function: DispatchMain
// Arguments: PDEVICE_OBJECT, PIRP
// Return: NSTATUS
// Purpose: receives IRPs sent by usermode applications/kernel mode drivers via any XxReadFile(Ex), 
//          XxWriteFile(Ex) or the like. Kernel mode drivers can send IRPS via IoCallDriver and
//          probably could hit this depending on the code set. At the moment this does nothing,
//          the main work is done with custom IO_CTL_CODES setup and dispatched from DispatchDevCtl().
NTSTATUS
DispatchMain( __in PDEVICE_OBJECT pDevObj,
              __in PIRP pIrp )
{
    NTSTATUS Status = STATUS_SUCCESS;
    PIO_STACK_LOCATION pIoStackLoc = IoGetCurrentIrpStackLocation(pIrp);

    UNREFERENCED_PARAMETER(pDevObj);

    switch( pIoStackLoc->MajorFunction )
    {
    default:
        break;//Do Nothing Yet.
    }
    
    pIrp->IoStatus.Status = Status;
    pIrp->IoStatus.Information = 0x0;

    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return Status;
}