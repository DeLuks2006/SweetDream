#include "../include/Loader.h"
#include "../include/Macros.h"
#include "../include/Peb.h"

int main(void) {
	// Loader Vars
	NTSTATUS NtStatus;
	PVOID PeBase = NULL;
	RELOC_CTX RelocCtx;
	IMPORT_CTX ImportCtx;
	ULONG dwOldProtect;
	PVOID NtDll = sdGetModuleHandle(NTDLL);
	/// TMP ///////////////////////////////////////////////////////////
	HANDLE hFile = NULL;
	DWORD dwFileSize = 0;
	DWORD dwBytesRead = 0;
	PBYTE pbBuffer = NULL;

	hFile = CreateFileA("C:\\Users\\infected\\Desktop\\dummy.dll", GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	dwFileSize = GetFileSize(hFile, NULL);
	pbBuffer = (PBYTE)VirtualAlloc(NULL, dwFileSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!ReadFile(hFile, pbBuffer, dwFileSize, &dwBytesRead, NULL)) {
		return 0;
	}
	/// TMP ///////////////////////////////////////////////////////////////
	PIMAGE_DOS_HEADER Dos = (PIMAGE_DOS_HEADER)(pbBuffer); // C_PTR( G_END() )
	PIMAGE_NT_HEADERS NtH = (PIMAGE_NT_HEADERS)((DWORD_PTR)Dos + Dos->e_lfanew);
	IMAGE_DATA_DIRECTORY ImportDir;
	PIMAGE_IMPORT_DESCRIPTOR ImportDesc;
	SIZE_T szSizeImage;
	DWORD_PTR pdwDelta;

	// Calc memory for image
	szSizeImage = NtH->OptionalHeader.SizeOfImage; //(((NtH->OptionalHeader.SizeOfImage) + 0x1000 - 1) & ~(0x1000 - 1));

	// Alloc memory for image
	fn_NtAllocateVirtualMemory pdNtAllocateVirtualMemory = (fn_NtAllocateVirtualMemory)sdGetProcAddress(NtDll, NT_VIRTUAL_ALLOC);
	NtStatus = pdNtAllocateVirtualMemory(
		((HANDLE)-1),
		&PeBase,
		0,
		&szSizeImage,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_READWRITE
	);
	if (NtStatus != STATUS_SUCCESS || PeBase == NULL) {
		return 0;
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
	RelocCtx.szRelocsProcessed = 0x0;
	RelocCtx.RelocDir = NtH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	RelocCtx.pdwRelocTable = RelocCtx.RelocDir.VirtualAddress + (DWORD_PTR)PeBase;
	RelocCtx.lpImgBase = PeBase;
	RelocCtx.pdNtReadVirtualMemory = (fn_NtReadVirtualMemory)sdGetProcAddress(NtDll, NT_VIRTUAL_READ);
	RelocCtx.NtStatus = 0x0;
	RelocCtx.pBlockCtx = nullptr;
	sdPerformRelocs(&RelocCtx, pdwDelta);

	// Change permissions to R_X
	SIZE_T textsize = NULL;
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(NtH);
	PVOID textptr = sdFindText(&textsize, section, PeBase);

	fn_NtProtectVirtualMemory pdNtProtectVirtualMemory = (fn_NtProtectVirtualMemory)sdGetProcAddress(NtDll, NT_VIRTUAL_PROTECT);
	NtStatus = pdNtProtectVirtualMemory(
		((HANDLE)-1),
		&textptr,
		&textsize,
		PAGE_EXECUTE_READ,
		&dwOldProtect
	);
	if (NtStatus != STATUS_SUCCESS) {
		return 0;
	}

	// Execute
	DLLMAIN_T Ent = (DLLMAIN_T)((DWORD_PTR)PeBase + NtH->OptionalHeader.AddressOfEntryPoint);
	(*Ent)((HINSTANCE)PeBase, DLL_PROCESS_ATTACH, 0);

	return 0;
}