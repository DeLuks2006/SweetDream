#pragma once
#include "Native.h"
#include "Misc.h"

typedef struct _UnhookApi {
	fn_NtProtectVirtualMemory NtProtectVirtualMemory;
	fn_NtCreateFile NtCreateFile;
	fn_NtCreateSection NtCreateSection;
	fn_NtMapViewOfSection NtMapViewOfSection;
	fn_NtUnmapViewOfSection NtUnmapViewOfSection;
	fn_NtClose NtClose;
} UnhookApi;

PUNICODE_STRING sdGetModuleName(ULONG Hash);

PVOID sdGetModuleHandle(ULONG Hash);

DWORD64 sdGetProcAddress(PVOID Module, ULONG Hash);

BOOL sdUnhookDll(ULONG Hash, PVOID ModuleBase);