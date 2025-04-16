#include "../include/Loader.h"
#include "../include/Macros.h"
#include "../include/Peb.h"

int main(void) {
	// Loader Vars
	NTSTATUS status;
	PVOID pe_base;
	RELOC_CTX rcRelocCtx;
	IMPORT_CTX import_ctx;
	ULONG dwOldProtect;
	PVOID ntdll = pdGetModuleHandle(NTDLL);
	// PE bullshit
	/// TMP ///////////////////////////////////////////////////////////
	HANDLE hFile = NULL;
	DWORD dwFileSize = 0;
	DWORD penis = 0;
	PBYTE pbBuffer = NULL;

	hFile = CreateFileA("C:\\Users\\infected\\Desktop\\dummy.dll", GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	dwFileSize = GetFileSize(hFile, NULL);
	pbBuffer = (PBYTE)VirtualAlloc(NULL, dwFileSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!ReadFile(hFile, pbBuffer, dwFileSize, &penis, NULL)) {
		return 0;
	}
	/// TMP ///////////////////////////////////////////////////////////////
	PIMAGE_DOS_HEADER Dos = (PIMAGE_DOS_HEADER)(pbBuffer);
	PIMAGE_NT_HEADERS NtH = (PIMAGE_NT_HEADERS)((DWORD_PTR)Dos + Dos->e_lfanew);
	IMAGE_DATA_DIRECTORY import_dir;
	PIMAGE_IMPORT_DESCRIPTOR import_desc;
	SIZE_T szSizeImage;
	DWORD_PTR pdwDelta;

	// Calc memory for image
	szSizeImage = NtH->OptionalHeader.SizeOfImage; //(((NtH->OptionalHeader.SizeOfImage) + 0x1000 - 1) & ~(0x1000 - 1));

	// Alloc memory for image
	fn_NtAllocateVirtualMemory pdNtAllocateVirtualMemory = (fn_NtAllocateVirtualMemory)pdGetProcAddress(ntdll, NT_VIRTUAL_ALLOC);
	status = pdNtAllocateVirtualMemory(
		((HANDLE)-1),
		&pe_base,
		0,
		&szSizeImage,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_READWRITE
	);
	if (status != STATUS_SUCCESS || pe_base == NULL) {
		return 0;
	}

	// Copy sections
	__builtin_memcpy(pe_base, pbBuffer, NtH->OptionalHeader.SizeOfHeaders);
	pdCopySections(IMAGE_FIRST_SECTION(NtH), NtH->FileHeader.NumberOfSections, 0, pe_base, C_PTR(pbBuffer)); // HERE BASE OF FILE
	
	// Resolve imports
	import_dir = NtH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	import_desc = (PIMAGE_IMPORT_DESCRIPTOR)(import_dir.VirtualAddress + (DWORD_PTR)pe_base);
	import_ctx.pdLdrGetProcedureAddress = (fn_LdrGetProcedureAddress)pdGetProcAddress(ntdll, LDR_GET_PROC_ADDR);
	import_ctx.pdLdrLoadDll = (fn_LdrLoadDll)pdGetProcAddress(ntdll, LDR_GET_DLL);
	import_ctx.pdRtlAnsiStringToUnicodeString = (fn_RtlAnsiStringToUnicodeString)pdGetProcAddress(ntdll, RTL_ANSI_TO_UNICODE);
	pdLoadImports(&import_ctx, import_desc, pe_base);

	// Perform relocations
	pdwDelta = (DWORD_PTR)pe_base - (DWORD_PTR)NtH->OptionalHeader.ImageBase;
	rcRelocCtx.szRelocsProcessed = 0;
	rcRelocCtx.iddRelocDir = NtH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	rcRelocCtx.pdwRelocTable = rcRelocCtx.iddRelocDir.VirtualAddress + (DWORD_PTR)pe_base;
	rcRelocCtx.lpImgBase = pe_base;
	rcRelocCtx.pdNtReadVirtualMemory = (fn_NtReadVirtualMemory)pdGetProcAddress(ntdll, NT_VIRTUAL_READ);
	pdPerformRelocs(&rcRelocCtx, pdwDelta);

	// Change permissions to R_X
	SIZE_T textsize = NULL;
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(NtH);
	PVOID textptr = pdFindText(&textsize, section, pe_base);

	fn_NtProtectVirtualMemory pdNtProtectVirtualMemory = (fn_NtProtectVirtualMemory)pdGetProcAddress(ntdll, NT_VIRTUAL_PROTECT);
	status = pdNtProtectVirtualMemory(
		((HANDLE)-1),
		&textptr,
		&textsize,
		PAGE_EXECUTE_READ,
		&dwOldProtect
	);
	if (status != STATUS_SUCCESS) {
		return 0;
	}

	// Execute
	DLLMAIN_T Ent = (DLLMAIN_T)((DWORD_PTR)pe_base + NtH->OptionalHeader.AddressOfEntryPoint);
	(*Ent)((HINSTANCE)pe_base, DLL_PROCESS_ATTACH, 0);

	return 0;
}