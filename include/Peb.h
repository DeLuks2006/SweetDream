#pragma once
#include "Common.h"

typedef struct _UnhookApi {
	NtProtectVirtualMemory_t NtProtectVirtualMemory;
	NtCreateFile_t NtCreateFile;
	NtCreateSection_t NtCreateSection;
	NtMapViewOfSection_t NtMapViewOfSection;
	NtUnmapViewOfSection_t NtUnmapViewOfSection;
	NtClose_t NtClose;
} UnhookApi;

PUNICODE_STRING sdGetModuleName(ULONG Hash);

PVOID sdGetModuleHandle(ULONG Hash);

DWORD64 sdGetProcAddress(PVOID Module, ULONG Hash);
