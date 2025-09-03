#include "../include/Peb.h"

D_SEC( B ) PUNICODE_STRING _sdGetModuleName(ULONG Hash, PLIST_ENTRY StartListEntry, PLIST_ENTRY ListEntry) {
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

D_SEC( B ) PUNICODE_STRING sdGetModuleName(ULONG Hash) {
	return _sdGetModuleName(Hash, NULL, NULL);
}

D_SEC( B )PVOID _sdGetModuleHandle(ULONG Hash, PLIST_ENTRY StartListEntry, PLIST_ENTRY ListEntry) {
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

D_SEC( B ) PVOID sdGetModuleHandle(ULONG Hash) {
	return _sdGetModuleHandle(Hash, NULL, NULL);
}

D_SEC( B ) DWORD64 _sdGetProcAddress(PVOID Module, ULONG Hash, ULONG Index) {
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

D_SEC( B ) DWORD64 sdGetProcAddress(PVOID Module, ULONG Hash) {
	return _sdGetProcAddress(Module, Hash, 0);
}
