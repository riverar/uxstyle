#include "uxpatch.h"

VOID
GetCurrentTime(PTIME_FIELDS ptfTime)
{
	LARGE_INTEGER liSystemTime;
	LARGE_INTEGER liLocalTime;

	RtlZeroMemory((PVOID)ptfTime, sizeof(TIME_FIELDS));

	KeQuerySystemTime(&liSystemTime);
	ExSystemTimeToLocalTime(&liSystemTime, &liLocalTime);

	RtlTimeToTimeFields(&liLocalTime, ptfTime);

	return;
}

NTSTATUS
LogToFile(IN LOGINFO lLog,
		  IN PCHAR szDebugMessage)
{
	NTSTATUS NtStatus = STATUS_SUCCESS;
	LARGE_INTEGER liFileOffset;
	HANDLE hFile = NULL;
	OBJECT_ATTRIBUTES oaFile;
	UNICODE_STRING usFile;
	IO_STATUS_BLOCK sbStatus;
	TIME_FIELDS tfTime;

	RtlInitUnicodeString(&usFile, lLog.pwszFilePath);

	InitializeObjectAttributes(&oaFile,
		                       &usFile,
							   OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
							   NULL,
							   NULL);

	NtStatus = ZwCreateFile(&hFile,
		                  GENERIC_WRITE,
						  &oaFile,
						  &sbStatus,
						  NULL,
						  FILE_ATTRIBUTE_NORMAL,
						  0,
						  FILE_OPEN_IF,
						  0x0,
						  NULL,
						  0);
	if ( NT_SUCCESS(NtStatus) )
	{
		PCHAR szMessage = NULL;
		size_t ulMsgSize = 0x0;
		CHAR szTimeBuf[24];

		liFileOffset.HighPart = -1;
		liFileOffset.LowPart = FILE_WRITE_TO_END_OF_FILE;

		GetCurrentTime(&tfTime);

		ulMsgSize = sizeof(szTimeBuf) + strlen(szDebugMessage);

		szMessage = (PCHAR)ExAllocatePoolWithTag(PagedPool, ulMsgSize, 'zsxu');

		if (szMessage != NULL)
		{
			RtlStringCchPrintfA(szTimeBuf, sizeof(szTimeBuf), TIMEFMT, tfTime.Month, tfTime.Day, tfTime.Year,
								  tfTime.Hour, tfTime.Minute, tfTime.Second);

			RtlStringCchPrintfA(szMessage, ulMsgSize, "%s%s", szTimeBuf, szDebugMessage);
			
			NtStatus = ZwWriteFile(hFile,
								 NULL,
								 NULL,
								 NULL,
								 &sbStatus,
								 (PVOID)szMessage,
								 (ULONG)(ulMsgSize - 1),
								 &liFileOffset,
								 NULL);

			ExFreePoolWithTag((PVOID)szMessage, 'zsxu');
		}
		ZwClose(hFile);
	}
	
	return NtStatus;
}

NTSTATUS
ReadParameter( __in HANDLE hKey, 
			   __in PWCHAR pwszValue,
			   __inout PVOID *pValueBuffer )
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	PKEY_VALUE_PARTIAL_INFORMATION kvbiValue;
	ULONG ulResultLen = 0x0;
	UNICODE_STRING usValue;

	if (!pwszValue)
		return STATUS_UNSUCCESSFUL;
	
	RtlInitUnicodeString(&usValue, pwszValue);
	
	// This first read is to get the data value's size.
	ntStatus = ZwQueryValueKey(hKey,
							   &usValue,
		                       KeyValuePartialInformation,
							   NULL,
							   0x0,
							   &ulResultLen);

	// Check the status and make sure the length is bigger than 0.
	if (STATUS_BUFFER_TOO_SMALL == ntStatus && ulResultLen > 0x0)
	{
		// Allocate memory based on the result length for our partial info struct.
		kvbiValue = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(PagedPool, ulResultLen, 'ibvk');
		if (kvbiValue != NULL)
		{
			// This time query the key's value and get the actual data.
			ntStatus = ZwQueryValueKey(hKey,
									   &usValue,
									   KeyValuePartialInformation,
									   kvbiValue,
									   ulResultLen,
									   &ulResultLen);

			if (NT_SUCCESS(ntStatus))
			{
				// We are expecting two types currently, string and dword.
				switch (kvbiValue->Type)
				{
				case REG_SZ:
					// Allocate the callers buffer and copy the data into it.
					*pValueBuffer = (PVOID)ExAllocatePoolWithTag(PagedPool, kvbiValue->DataLength, 'bsxu');
					if (*pValueBuffer != NULL)
						RtlCopyMemory(*pValueBuffer, kvbiValue->Data, kvbiValue->DataLength);
					else
						ntStatus = STATUS_INSUFFICIENT_RESOURCES;
					break;
				case REG_DWORD:
					*pValueBuffer = *(PVOID*)kvbiValue->Data;
					break;
				}
			}
			// Free up resources
			ExFreePoolWithTag((PVOID)kvbiValue, 'ibvk');
		}
		else
		{
			ntStatus = STATUS_INSUFFICIENT_RESOURCES;
		}
	}

	return ntStatus;
}

NTSTATUS
InitLogFile( __in PLOGINFO pliLogInfo, 
			 __in PUNICODE_STRING pRegistryPath )
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	HANDLE hFileKey = NULL;
	OBJECT_ATTRIBUTES oaKey;
	UNICODE_STRING usLogFileKey;
	PWCHAR szLogFileKeyName = NULL;
	size_t ulSizeOfString = 0x0;

	if (pliLogInfo == NULL)
		return STATUS_INVALID_PARAMETER_1;
    
    ASSERT(pliLogInfo != NULL);

	// Initialize the logging struct.
	pliLogInfo->ulLoggingEnabled = FALSE;
	pliLogInfo->pwszFilePath = NULL;

	// Setup the registry paths buffer size
	ulSizeOfString = pRegistryPath->Length + (wcslen(PARAM) * sizeof(WCHAR)) + sizeof(WCHAR);

	szLogFileKeyName = (PWCHAR)ExAllocatePoolWithTag(PagedPool, ulSizeOfString, 'bGOL');
	
	if (szLogFileKeyName == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;

	// We are copying the registry path to the driver that was passed in and then we concat
	// Parameters key to the path.
	RtlStringCchCopyW(szLogFileKeyName, ulSizeOfString, pRegistryPath->Buffer);
	RtlStringCchCatW(szLogFileKeyName, ulSizeOfString, PARAM);

	RtlInitUnicodeString(&usLogFileKey, szLogFileKeyName);

	InitializeObjectAttributes(&oaKey,
		                       &usLogFileKey,
							   OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
							   NULL,
							   NULL);

	// Open up the Parameters key
	ntStatus = ZwOpenKey(&hFileKey,
		                 KEY_ALL_ACCESS,
						 &oaKey);

	if (NT_SUCCESS(ntStatus))
	{
		// First check to see if we are even logging shit.
		ntStatus = ReadParameter(hFileKey, L"enablelogging", (PVOID*)&pliLogInfo->ulLoggingEnabled);
		if (NT_SUCCESS(ntStatus) && pliLogInfo->ulLoggingEnabled == TRUE)
		{
			// Get the path to the log file and log file's name.
			ntStatus = ReadParameter(hFileKey, L"logfile", (PVOID*)&pliLogInfo->pwszFilePath);
			if (NT_SUCCESS(ntStatus) && pliLogInfo->pwszFilePath != NULL)
			{
				/* Gotta prepend \??\ or \DosDevices\ to the file path. */
				size_t ulSizeOfFilePath = ((wcslen(DOSDEVICES) * sizeof(WCHAR)) + (wcslen(pliLogInfo->pwszFilePath) * sizeof(WCHAR)));
				PWCHAR pwszTmpStr = (PWCHAR)ExAllocatePoolWithTag(PagedPool, ulSizeOfFilePath, 'pflf');
				
				// Construct that bitch, bitches.
				RtlStringCchCopyW(pwszTmpStr, ulSizeOfFilePath, DOSDEVICES);
				RtlStringCchCatW(pwszTmpStr, ulSizeOfFilePath, pliLogInfo->pwszFilePath);

				// Free up the path we got from the registry.
				ExFreePoolWithTag((PVOID)pliLogInfo->pwszFilePath, 'bsxu');

				// Assign the modified one.
				pliLogInfo->pwszFilePath = pwszTmpStr;
			}
			else
			{
				// If there was a problem getting the file's path from the registry then turn logging off.
				pliLogInfo->ulLoggingEnabled = FALSE;
			}
		}
		ZwClose(hFileKey);
	}

	// Free up my registry key path.
	ExFreePoolWithTag((PVOID)szLogFileKeyName, 'bGOL');

	return ntStatus;
}

VOID
PrintBytesToLog(PCHAR pszMessage, PUCHAR pByte)
{
	ULONG i = 0x0;
	ULONG ulSizeOfBuf = 0x64;
	PCHAR pszTempBuffer = (PCHAR)ExAllocatePoolWithTag(PagedPool, ulSizeOfBuf, 'zsxu');

	if (pszTempBuffer)
	{
		RtlStringCchCopyA(pszTempBuffer, ulSizeOfBuf, pszMessage);

		for (i = 0x0; i < g_CodeBytes.ulByteCount; i++)
		{
			RtlStringCchPrintfA(pszTempBuffer, ulSizeOfBuf, "%s 0x%X", pszTempBuffer, pByte[i]);
		}
		RtlStringCchCatA(pszTempBuffer, ulSizeOfBuf, "\r\n");
		LogToFile(g_liLog, pszTempBuffer);
		ExFreePoolWithTag((PVOID)pszTempBuffer, 'zsxu');
	}
	return;
}