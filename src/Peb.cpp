#include "../include/Peb.h"

PVOID _pdGetModuleHandle(ULONG Hash, PLIST_ENTRY StartListEntry, PLIST_ENTRY ListEntry) {
	if (StartListEntry == NULL && ListEntry == NULL) {
		PPEB_LDR_DATA Ldr = ((PPEB)__readgsqword(0x60))->Ldr;
		StartListEntry = &Ldr->InMemoryOrderModuleList;
		ListEntry = StartListEntry->Flink;
	}

	if (ListEntry == StartListEntry) {
		return NULL;
	}

	PLDR_DATA_TABLE_ENTRY pEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)ListEntry - sizeof(LIST_ENTRY));
	if (sdFowlerW((LPCWSTR)pEntry->FullDllName.Buffer) == Hash) {
		return (HMODULE)pEntry->DllBase;
	}

	return _pdGetModuleHandle(Hash, StartListEntry, ListEntry->Flink);
}

PVOID sdGetModuleHandle(ULONG Hash) {
	return _pdGetModuleHandle(Hash, NULL, NULL);
}

DWORD64 _pdGetProcAddress(PVOID Module, ULONG Hash, ULONG Index) {
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

	return _pdGetProcAddress(Module, Hash, Index + 1);
}

DWORD64 sdGetProcAddress(PVOID Module, ULONG Hash) {
	return _pdGetProcAddress(Module, Hash, 0);
}