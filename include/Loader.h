#pragma once
#include "Common.h"

typedef struct BASE_RELOCATION_BLOCK {
	DWORD dwPageAddress;
	DWORD dwBlockSize;
} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
	USHORT usOffset : 12;
	USHORT usType : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

typedef struct RELOC_BLOCK_CTX {
	INT iCounter;
	DWORD dwRelocCount;
	PBASE_RELOCATION_ENTRY pRelocEntries;
	PBASE_RELOCATION_BLOCK pRelocBlock;
	DWORD_PTR pdwDelta;
} RELOC_BLOCK_CTX, * PRELOC_BLOCK_CTX;

typedef struct RELOC_CTX {
	NTSTATUS NtStatus;
	SIZE_T szRelocsProcessed;
	IMAGE_DATA_DIRECTORY RelocDir;
	DWORD_PTR pdwRelocTable;
	LPVOID lpImgBase;
	PRELOC_BLOCK_CTX pBlockCtx;
	NtReadVirtualMemory_t NtReadVirtualMemory;
} RELOC_CTX, * PRELOC_CTX;

typedef struct IMPORT_CTX {
	NTSTATUS NtStatus;
	LdrLoadDll_t LdrLoadDll;
	LdrGetProcedureAddress_t LdrGetProcedureAddress;
	RtlAnsiStringToUnicodeString_t RtlAnsiStringToUnicodeString;
} IMPORT_CTX, *PIMPORT_CTX;

D_SEC( B ) void sdCopySections(PIMAGE_SECTION_HEADER shSection, DWORD dwNumSections, DWORD dwSectionsProcessed, LPVOID lpImgBase, LPVOID lpFile);

D_SEC( B ) void sdPerformRelocs(PRELOC_CTX prcRelocCtx, DWORD_PTR pdwDelta);

D_SEC( B ) void sdLoadImports(PIMPORT_CTX ctx, PIMAGE_IMPORT_DESCRIPTOR pidImportDescriptor, LPVOID lpImgBase);
