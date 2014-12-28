#include "uxpatch.h"

LONG g_TotalEntries = 0x0;

// Function: PatchAddress
// Arguments: PIRP, IO_STACK_LOCATION
// Return: NTSTATUS
// Purpose: After receiving a IOCTL_PATCH_ADDR code we will extract the VA sent by
//          a program of the pages we want to patch. We check the buffer sent to make
//          sure it doesn't want to patch a billion pages and then create a doubly-linked
//          list with each virtual address entry in it. After that we send it to ApplyPatch()
//          to perform the patching with our codebytes.
NTSTATUS
PatchAddress( __in PIRP pIrp,
              __in PIO_STACK_LOCATION pIoStackLoc,
              __inout PULONG_PTR p_ulPatched )
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    ULONG_PTR ulPatched = 0x0;
    ULONG_PTR pAddress = *(PULONG_PTR)pIrp->AssociatedIrp.SystemBuffer;
    CHAR szErrorMsgBuffer[250];

    UNREFERENCED_PARAMETER(pIoStackLoc);

    if ( pAddress != 0x0 )
    {
        // We probably are only going to need to patch 3 different addresses
        // but ill put the limit at 10 anyways.
        if ( g_TotalEntries <= PATCH_LIMIT )
        {
            PSAVEDINFO pItem = CreatePatchAddrLists(pAddress);
            if (pItem != NULL)
            {
                Status = ApplyPatch(FALSE, pItem);
                *p_ulPatched = ulPatched;
            }
            else
            {
#ifdef DEBUG
                DbgPrint("Returned struct was null.\n");
#endif
            }
        }
        else
        {
#ifdef DEBUG
            DbgPrint("No more than %d patches at a time!\n", PATCH_LIMIT);
#endif
            if (g_liLog.ulLoggingEnabled)
            {
                RtlStringCchPrintfA(szErrorMsgBuffer, sizeof(szErrorMsgBuffer), "No more than %d patches at a time!\r\n", PATCH_LIMIT);
                LogToFile(g_liLog, szErrorMsgBuffer);
            }
        }
    }

    return Status;
}

// Funtion: UnPatchAddress
// Arguments: PULONG
// Return: NTSTATUS
// Purpose: This function unpatches the virtual addresses we patched earlier in PatchAddress().
//          We first check to see that the list isnt empty, if it is then we have nothing to 
//          patch. Then call ApplyPatch() and have it unpatch them thar addresses. When all done
//          delete all our entries from our doubly-linked list.
NTSTATUS
UnPatchAddress( __inout PULONG_PTR p_ulPatched )
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    //ULONG_PTR ulPatched = 0x0;
    
    if (IsListEmpty(&g_ListHead))
    {
#ifdef DEBUG
        DbgPrint("No entries to revert back!\n");
#endif
    }
    else
    {
        PSAVEDINFO pPatches = NULL;

        for(pPatches = (PSAVEDINFO)(g_ListHead.Flink);
            pPatches->Entry.Flink != g_ListHead.Flink;
            pPatches = (PSAVEDINFO)(pPatches->Entry.Flink))
        {
            Status = ApplyPatch(TRUE, pPatches);
            *p_ulPatched += 1;
        }
        DeletePatchAddrLists();
    }

    return Status;
}


// Function: ApplyPatch
// Arguments: BOOLEAN, PSAVEDINFO
// Return: NTSTATUS
// Purpose: The work horse of the driver. This function takes either TRUE or FALSE. TRUE
//          specifies that we want to revert our changes we made on a previous call on 
//          the virtual addresses to patch. FALSE specifies the opposite, patch the virtual
//          addresses. Open's up \Device\PhysicalMemory and calc's the virtual addresses
//          physical address and patches it. Will create an MDL first and lock the pages
//          in memory if they are not present. It will set the PULONG argument with how
//          many successful patches occured.
NTSTATUS
ApplyPatch( __in BOOLEAN bRevert, __in PSAVEDINFO siItemToPatch )
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    HANDLE hPhysMem = NULL;
    ULONG j = 0x0;
    WORD wOffset = 0x0;
    PVOID pVirtualAddress = NULL;
    PUCHAR pByte = NULL;
    SIZE_T iLen = PAGE_SIZE * 2;
    PHYSICAL_ADDRESS paPhysAddr;
    PMDL pMdl = NULL;
    PMDL pPdeMdl = NULL;
    CHAR szErrorMsgBuffer[250];

    Status = OpenPhysicalMemory(&hPhysMem);

    if ( !NT_SUCCESS(Status) )
    {
#ifdef DEBUG
        DbgPrint("OpenPhysicalMemory() failed : 0x%08X\n", Status);
#endif
        if (g_liLog.ulLoggingEnabled)
        {
            RtlStringCchPrintfA(szErrorMsgBuffer, sizeof(szErrorMsgBuffer), "Failed to open mem: %.08X\r\n", Status);
            LogToFile(g_liLog, szErrorMsgBuffer);
        }
        return Status;
    }
    
    try
    {
#ifdef DEBUG
        DbgPrint("ulVirtualAddress = 0x%p", siItemToPatch->ulVirtualAddress);
#endif
        pMdl = IoAllocateMdl((PVOID)siItemToPatch->ulVirtualAddress, PAGE_SIZE * 2, FALSE, FALSE, NULL);
        
        if ( NULL == pMdl )
        {
            Status = STATUS_INSUFFICIENT_RESOURCES;
#ifdef DEBUG
            DbgPrint("Could not allocate mdl.\n");
#endif
            if (g_liLog.ulLoggingEnabled) LogToFile(g_liLog, "Could not allocate mdl.\r\n");
            goto Cleanup;
        }

        MmProbeAndLockPages(pMdl, UserMode, IoReadAccess);
        paPhysAddr = MmGetPhysicalAddress((PVOID)siItemToPatch->ulVirtualAddress);
#ifdef DEBUG
        DbgPrint("PhysAddr: %X - VirtualAddr: %X\n", (ULONG)paPhysAddr.LowPart, siItemToPatch->ulVirtualAddress);
#endif
        
        if (paPhysAddr.LowPart == 0x0)
        {
#ifdef DEBUG
            DbgPrint("Requested page is not in memory!\n");
#endif
            if (g_liLog.ulLoggingEnabled) LogToFile(g_liLog, "Requested page is not available.\r\n");
            MmUnlockPages(pMdl);
            IoFreeMdl(pMdl);
            goto Cleanup;
        }
        wOffset = ByteOffset(paPhysAddr.LowPart);

#ifdef DEBUG
        DbgPrint("Mapping view of section from given physical address..\n");
#endif
        Status = ZwMapViewOfSection(hPhysMem, 
                                    NtCurrentProcess(),
                                    (PVOID*)&pVirtualAddress,
                                    0x0L,
                                    PAGE_SIZE * 2,
                                    &paPhysAddr,
                                    &iLen,
                                    ViewUnmap,
                                    0x0L,
                                    PAGE_READWRITE);

        if ( !NT_SUCCESS(Status) )
        {
#ifdef DEBUG
            DbgPrint("Unabled to map view: %.08X\n", Status);
#endif
            if (g_liLog.ulLoggingEnabled)
            {
                RtlStringCchPrintfA(szErrorMsgBuffer, sizeof(szErrorMsgBuffer), "Unable to map view: %.08X\r\n", Status);
                LogToFile(g_liLog, szErrorMsgBuffer);
            }
            MmUnlockPages(pMdl);
            IoFreeMdl(pPdeMdl);
            goto Cleanup;
        }

#ifdef DEBUG
        DbgPrint("Mapped view success!\n");
#endif

        pByte = (PUCHAR)pVirtualAddress + wOffset;

#ifdef DEBUG
        //DbgPrint("Code Before: ");
        //PRINTBYTES(x, pByte)
        //DbgPrint("\n");
#endif
    
        if (g_liLog.ulLoggingEnabled) 
        {
            PrintBytesToLog("Code Before: ", pByte);
        }

        for ( j = 0x0; j < g_CodeBytes.ulByteCount; j++)
        {
            if (bRevert)
            {
                *pByte = siItemToPatch->bSavedBytes[j];
                pByte++;
            }
            else
            {
                siItemToPatch->bSavedBytes[j] = *pByte;
                *pByte = g_CodeBytes.pBytes[j];
                pByte++;
            }
        }

        if (bRevert)
            siItemToPatch->bPatched = FALSE;
        else
            siItemToPatch->bPatched = TRUE;

        pByte = (PUCHAR)pVirtualAddress + wOffset;

        if (g_liLog.ulLoggingEnabled) 
        {
            PrintBytesToLog("Code After: ", pByte);
        }

#ifdef DEBUG
        //DbgPrint("Code After: ");
        //PRINTBYTES(x, pByte)
        //DbgPrint("\n");
#endif

        Status = ZwUnmapViewOfSection(NtCurrentProcess(), pVirtualAddress);
#ifdef DEBUG
        DbgPrint("Unmapview status: %08X.\n", Status);
#endif
        RtlZeroMemory(&paPhysAddr, sizeof(PHYSICAL_ADDRESS));
        
        MmUnlockPages(pMdl);
        IoFreeMdl(pMdl);
    }
    except(EXCEPTION_EXECUTE_HANDLER)
    {
#ifdef DEBUG
        DbgPrint("Exception 0x%08X\n", GetExceptionCode());
#endif
        
        if (pMdl)
            IoFreeMdl(pMdl);
        Status = STATUS_UNSUCCESSFUL;
    }

Cleanup:
#ifdef DEBUG
    DbgPrint("Closing PhysicalMemory section..\n");
#endif
    ZwClose(hPhysMem);
    
    return Status;
}