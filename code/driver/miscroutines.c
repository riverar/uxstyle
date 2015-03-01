#include "uxpatch.h"

PATCHBYTES g_CodeBytes;

#if defined (__AMD64__) || defined (AMD64)
BOOLEAN g_bIs64Bit = TRUE;
#else
BOOLEAN g_bIs64Bit = FALSE;
#endif

// Function: OpenPhysicalMemory
// Arguments: PHANDLE
// Return: NTSTATUS
// Purpose: To open up a handle to \Device\PhysicalMemory and return that
//          handle through the supplied parameter.
NTSTATUS
OpenPhysicalMemory( __inout PHANDLE hPhysMem )
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	HANDLE hTemp;
	UNICODE_STRING usPhysMem;
	OBJECT_ATTRIBUTES oaObjAttrib;

	RtlInitUnicodeString(&usPhysMem, PHYSICALMEM);

	InitializeObjectAttributes(&oaObjAttrib,
		                       &usPhysMem,
							   OBJ_KERNEL_HANDLE|OBJ_CASE_INSENSITIVE,
							   NULL,
							   NULL);
#ifdef DEBUG
	DbgPrint("Opening PhysicalMemory section..\n");
#endif
	Status = ZwOpenSection(&hTemp, GENERIC_READ|GENERIC_WRITE, &oaObjAttrib);
	
	if ( NT_SUCCESS(Status) )
		*hPhysMem = hTemp;
	
	return Status;
}

// Function: CreatePatchAddrLists
// Arguments: PULONG
// Return: NTSTATUS
// Purpose: To take a custom array and create a doubly-linked list
//          from it's contents. The first element in the array specifies
//          how many virtual addresses there are after it.
PSAVEDINFO
CreatePatchAddrLists( __in ULONG_PTR pAddress)
{
	PSAVEDINFO SavedInfo = NULL;

	InterlockedIncrement(&g_TotalEntries);

	SavedInfo = (PSAVEDINFO)ExAllocateFromNPagedLookasideList(&g_PgdLookList);
	SavedInfo->ulVirtualAddress = pAddress;
	SavedInfo->ulEntryNumber = g_TotalEntries;
	if (IsListEmpty(&g_ListHead))
		ExInterlockedInsertHeadList(&g_ListHead, &SavedInfo->Entry, &g_Lock);
	else
		ExInterlockedInsertTailList(&g_ListHead, &SavedInfo->Entry, &g_Lock);
	SavedInfo->bSavedBytes = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, g_CodeBytes.ulByteCount, 'SBYT');
	SavedInfo->bPatched = FALSE;

	return SavedInfo;
}

// Function: DeletePatchAddrLists
// Arguments: VOID
// Return: VOID
// Purpose: To simply free all entries in the linked list.
VOID
DeletePatchAddrLists(VOID)
{
	PSAVEDINFO SavedInfo = NULL;
	while ( !IsListEmpty(&g_ListHead) )
	{
		SavedInfo = (PSAVEDINFO)RemoveTailList(&g_ListHead);
		if (SavedInfo)
		{
#ifdef DEBUG
			DbgPrint("%d - 0x%08X\n", SavedInfo->ulEntryNumber, SavedInfo->ulVirtualAddress);
#endif
			ExFreePoolWithTag((PVOID)SavedInfo->bSavedBytes, 'SBYT');
			ExFreeToNPagedLookasideList(&g_PgdLookList, (PVOID)SavedInfo);
			InterlockedDecrement(&g_TotalEntries);
		}
	}
	RemoveHeadList(&g_ListHead);
	return;
}

// Function: DumpPatchedAddresses
// Arguments: VOID
// Return: NTSTATUS
// Purpose: Dumps all currently patched addresses to DbgPrint
NTSTATUS
DumpPatchedAddresses(VOID)
{
	NTSTATUS status = STATUS_SUCCESS;
	PSAVEDINFO pPatches = NULL;

	for(pPatches = (PSAVEDINFO)(g_ListHead.Flink);
		pPatches->Entry.Flink != g_ListHead.Flink;
		pPatches = (PSAVEDINFO)(pPatches->Entry.Flink))
	{
#ifdef DEBUG
		DbgPrint("Entry: %d, Address: 0x%X\n", pPatches->ulEntryNumber, pPatches->ulVirtualAddress);
#endif
	}

	return status;
}

NTSTATUS
DetermineVersionCompat( VOID )
{
	NTSTATUS Status = STATUS_SUCCESS;
	RTL_OSVERSIONINFOW osVer;

	osVer.dwOSVersionInfoSize = sizeof(osVer);
	RtlGetVersion(&osVer);

	g_CodeBytes.ulByteCount = 0x0;
	g_CodeBytes.pBytes = NULL;

	if (g_bIs64Bit)
	{
		if ((osVer.dwMajorVersion == 6 && osVer.dwMinorVersion < 3))
		{
			g_CodeBytes.ulByteCount = sizeof(g_CodeBytes_64bit_WinVista_greater);
			g_CodeBytes.pBytes = (PUCHAR)&g_CodeBytes_64bit_WinVista_greater;
		}
		else if ((osVer.dwMajorVersion == 6 && osVer.dwMinorVersion > 3) || (osVer.dwMajorVersion == 10 && osVer.dwMinorVersion == 0))
		{
			g_CodeBytes.ulByteCount = sizeof(g_CodeBytes_64bit_Win8_greater);
			g_CodeBytes.pBytes = (PUCHAR)&g_CodeBytes_64bit_Win8_greater;
		}
		else
		{
			Status = STATUS_UNSUCCESSFUL;
		}
	}
	else
	{
		if ((osVer.dwMajorVersion == 5) && (osVer.dwMinorVersion >= 1))
		{
			g_CodeBytes.ulByteCount = sizeof(g_CodeBytes_32bit_WinXP_WinServer03);
			g_CodeBytes.pBytes = (PUCHAR)&g_CodeBytes_32bit_WinXP_WinServer03;
		}
        else if (osVer.dwMajorVersion == 6 || (osVer.dwMajorVersion == 10 && osVer.dwMinorVersion == 0))
		{
			g_CodeBytes.ulByteCount = sizeof(g_CodeBytes_32bit_WinVista_greater);
			g_CodeBytes.pBytes = (PUCHAR)&g_CodeBytes_32bit_WinVista_greater;
		}
		else
		{
			Status = STATUS_UNSUCCESSFUL;
		}
	}

	return Status;
}