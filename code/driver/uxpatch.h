#include <ntddk.h>
#include <wdmsec.h>
#include <ntstatus.h>
#include <ntstrsafe.h>

#pragma once

#ifndef UXPATCH_HDR
#define UXPATCH_HDR

// Macros and other shit
typedef unsigned short WORD;

typedef struct _SAVEDINFO
{
	LIST_ENTRY Entry;
	ULONG_PTR ulEntryNumber;
	ULONG_PTR ulVirtualAddress;
	BOOLEAN bPatched;
	//UCHAR bSavedBytes[6];
	PUCHAR bSavedBytes;
} SAVEDINFO, *PSAVEDINFO;

typedef struct _PATCHBYTES
{
	ULONG  ulByteCount;
	PUCHAR pBytes;
} PATCHBYTES, *PPATCHBYTES;

typedef struct _LOGINFO
{
	ULONG  ulLoggingEnabled;
	PWCHAR pwszFilePath;
} LOGINFO, *PLOGINFO;

#define ClearFlags(f, x) (f) &= (~x)
#define SetFlags(f, x)   (f) |= (x)
#define ByteOffset(va)   (WORD)(va) & 0x0FFF

#define PRINTBYTES(i, x) for (i = 0x0; i < g_CodeBytes.ulByteCount; i++) DbgPrint("0x%X ", x[i]);

#define IOCTL_PATCH_ADDR	CTL_CODE(FILE_DEVICE_UNKNOWN,\
	                                 0x800,              \
								     METHOD_BUFFERED,    \
								     FILE_READ_DATA)

#define IOCTL_UNPATCH_ADDR	CTL_CODE(FILE_DEVICE_UNKNOWN,\
	                                 0x801,              \
								     METHOD_NEITHER,    \
								     0X0)

#define IOCTL_DUMP_PATCHED_ADDR	CTL_CODE(FILE_DEVICE_UNKNOWN,\
	                                     0x802,              \
								         METHOD_NEITHER,    \
								         0X0)

#define DEVNAME L"\\Device\\uxstyle"
#define DOSDEVNAME L"\\DosDevices\\uxstyle"
#define PHYSICALMEM L"\\Device\\PhysicalMemory"
#define TAGSAVEDBYTES 'TBVS'
#define PARAM L"\\Parameters"
#define DOSDEVICES L"\\??\\"
#define TIMEFMT "%.02d-%.02d-%.04d %.02d:%.02d:%.02d -- "
#define PATCH_LIMIT 10

// {76F9ABD8-2CB5-4d55-B2DD-1082752E0D32}
static const GUID UXPATCH_GUID = 
{ 0x76f9abd8, 0x2cb5, 0x4d55, { 0xb2, 0xdd, 0x10, 0x82, 0x75, 0x2e, 0xd, 0x32 } };
#define UXPATCH_ACL L"D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)"
// End Macros and other shit

NTSTATUS
DriverEntry( __in PDRIVER_OBJECT,
			 __in PUNICODE_STRING );

VOID
OnUnload( __in PDRIVER_OBJECT );

NTSTATUS
DispatchDevCtl( __in PDEVICE_OBJECT,
		        __in PIRP );

NTSTATUS
DispatchMain( __in PDEVICE_OBJECT,
		      __in PIRP );
NTSTATUS
PatchAddress( __in PIRP,
			  __in PIO_STACK_LOCATION,
			  __inout PULONG_PTR );

NTSTATUS
UnPatchAddress( __inout PULONG_PTR );

NTSTATUS
ApplyPatch( __in BOOLEAN, 
		    __in PSAVEDINFO );

NTSTATUS
OpenPhysicalMemory( __inout PHANDLE );

PSAVEDINFO
CreatePatchAddrLists( __in ULONG_PTR );

VOID
DeletePatchAddrLists( VOID );

NTSTATUS
InitLogFile( __in PLOGINFO, 
			 __in PUNICODE_STRING );

NTSTATUS
LogToFile( __in LOGINFO,
		   __in PCHAR );

NTSTATUS
DumpPatchedAddresses( VOID );

NTSTATUS
DetermineVersionCompat( VOID );

VOID
PrintBytesToLog( __in PCHAR, 
				 __in PUCHAR );

// Keep all procedures pagable to help save on 
// System Driver Area PTE's. These procedures 
// should never be called above PASSIVE.
#if PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, OnUnload)
#pragma alloc_text(PAGE, PatchAddress)
#pragma alloc_text(PAGE, UnPatchAddress)
#pragma alloc_text(PAGE, ApplyPatch)
#pragma alloc_text(PAGE, OpenPhysicalMemory)
#pragma alloc_text(PAGE, CreatePatchAddrLists)
#pragma alloc_text(PAGE, DeletePatchAddrLists)
#pragma alloc_text(PAGE, DispatchMain)
#pragma alloc_text(PAGE, DispatchDevCtl)
#endif

// Globals
// Bytes that will overwrite parts of code.

static const UCHAR g_CodeBytes_64bit_Win8_greater[] = {0x33,0xC0,0x3B,0xC0,0x5F,0xC3};

// These bytes are for Windows Vista SP(X) and greater 64bit editions.
static const UCHAR g_CodeBytes_64bit_WinVista_greater[] = {0x33,0xC0,0x3B,0xC0,0x5F,0x5E,0x5B,0xC3};

// These bytes are for Windows Vista SP(X) and greater 32bit editions.
static const UCHAR g_CodeBytes_32bit_WinVista_greater[] = {0x33,0xC0,0xC9,0xC2,0x04,0x00};

// These bytes are for Windows XP SP(X) and Windows Server 2003 SP(X) 32bit editions.
static const UCHAR g_CodeBytes_32bit_WinXP_WinServer03[] = {0x33,0xF6,0x8B,0xC6,0xC9,0xC2,0x08,0x00};

extern PATCHBYTES g_CodeBytes;

// These are used for the doubly-list
extern LIST_ENTRY g_ListHead;
extern NPAGED_LOOKASIDE_LIST g_PgdLookList;
extern KSPIN_LOCK g_Lock;
extern LONG g_TotalEntries;

extern LOGINFO g_liLog;
// End Globals

#endif // UXPATCH_HDR //