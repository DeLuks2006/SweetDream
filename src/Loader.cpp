#include "../include/Loader.h"

void pdCopySections(PIMAGE_SECTION_HEADER shSection, DWORD dwNumSections, DWORD dwSectionsProcessed, LPVOID lpImgBase, LPVOID lpFile) {
	PVOID lpDestination;
	PVOID lpBytes;

	if (dwNumSections == dwSectionsProcessed) {
		return;
	}

	lpDestination = (PVOID)((DWORD_PTR)lpImgBase + (DWORD_PTR)shSection->VirtualAddress);
	lpBytes = (PVOID)((DWORD_PTR)lpFile + (DWORD_PTR)shSection->PointerToRawData);

	__builtin_memcpy(lpDestination, lpBytes, shSection->SizeOfRawData);

	pdCopySections(shSection + 1, dwNumSections, dwSectionsProcessed + 1, lpImgBase, lpFile);
	
}

void pdRelocateBlock(PRELOC_BLOCK_CTX prbcRelocCtx) {
	DWORD_PTR pdwRelocRVA;
	DWORD_PTR pdwPatchPtr;

	if (prbcRelocCtx->iCounter == prbcRelocCtx->dwRelocCount) {
		return;
	}

	if (prbcRelocCtx->preRelocEntries[prbcRelocCtx->iCounter].usType == 0) {
		prbcRelocCtx->iCounter += 1;
		prbcRelocCtx->prcRelocCtx->szRelocsProcessed += sizeof(BASE_RELOCATION_ENTRY);
		return pdRelocateBlock(prbcRelocCtx);
	}

	pdwRelocRVA = prbcRelocCtx->prbRelocBlock->dwPageAddress + prbcRelocCtx->preRelocEntries[prbcRelocCtx->iCounter].usOffset;
	pdwPatchPtr = 0;
	prbcRelocCtx->status = prbcRelocCtx->prcRelocCtx->pdNtReadVirtualMemory(
		(HANDLE)((HANDLE)-1),
		(LPVOID)((DWORD_PTR)prbcRelocCtx->prcRelocCtx->lpImgBase + pdwRelocRVA),
		&pdwPatchPtr,
		sizeof(DWORD_PTR),
		NULL
	);
	if (prbcRelocCtx->status != STATUS_SUCCESS) {
		return;
	}
	pdwPatchPtr += prbcRelocCtx->pdwDelta;
	__builtin_memcpy((PVOID)((DWORD_PTR)prbcRelocCtx->prcRelocCtx->lpImgBase + pdwRelocRVA), &pdwPatchPtr, sizeof(DWORD_PTR));
	
	prbcRelocCtx->iCounter += 1;
	prbcRelocCtx->prcRelocCtx->szRelocsProcessed += sizeof(BASE_RELOCATION_ENTRY);
	return pdRelocateBlock(prbcRelocCtx);
}

void pdPerformRelocs(PRELOC_CTX prcRelocCtx, DWORD_PTR pdwDelta) {
	RELOC_BLOCK_CTX rbcRelocCtx;

	if (prcRelocCtx->szRelocsProcessed >= prcRelocCtx->iddRelocDir.Size) {
		return;
	}

	rbcRelocCtx.prcRelocCtx = prcRelocCtx;
	rbcRelocCtx.prbRelocBlock = (PBASE_RELOCATION_BLOCK)(prcRelocCtx->pdwRelocTable + prcRelocCtx->szRelocsProcessed);
	prcRelocCtx->szRelocsProcessed += sizeof(BASE_RELOCATION_BLOCK);
	rbcRelocCtx.dwRelocCount = (rbcRelocCtx.prbRelocBlock->dwBlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
	rbcRelocCtx.preRelocEntries = (PBASE_RELOCATION_ENTRY)(prcRelocCtx->pdwRelocTable + prcRelocCtx->szRelocsProcessed);
	rbcRelocCtx.iCounter = 0;
	rbcRelocCtx.pdwDelta = pdwDelta;
	rbcRelocCtx.status = 0x0;

	
	pdRelocateBlock(&rbcRelocCtx);

	return pdPerformRelocs(prcRelocCtx, pdwDelta);
}

void pdImportFunction(PIMPORT_CTX ctx, LPVOID lpImgBase, PVOID hLib, PIMAGE_THUNK_DATA tThunk, PIMAGE_THUNK_DATA tLookupThunk) {
	PIMAGE_IMPORT_BY_NAME impFnName;
	ANSI_STRING AnsiString;
	LPCSTR strFnOrdinal;
	PVOID pFunction;

	if (tThunk->u1.AddressOfData == 0) {
		return;
	}

	if (IMAGE_SNAP_BY_ORDINAL(tLookupThunk->u1.Ordinal)) {
		ctx->status = ctx->pdLdrGetProcedureAddress(hLib, NULL, IMAGE_ORDINAL(tLookupThunk->u1.Ordinal), &pFunction);
		if (ctx->status == STATUS_SUCCESS) {
			tThunk->u1.Function = (ULONGLONG)pFunction;
		}
	}
	else {
		impFnName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)lpImgBase + tLookupThunk->u1.AddressOfData);
		pdRtlInitAnsiString(&AnsiString, impFnName->Name);
		ctx->status = ctx->pdLdrGetProcedureAddress(hLib, &AnsiString, 0, &pFunction);
		if (ctx->status == STATUS_SUCCESS) {
			tThunk->u1.Function = (ULONGLONG)pFunction;
		}
	}

	return pdImportFunction(ctx, lpImgBase, hLib, tThunk+1, tLookupThunk+1);
}

void pdLoadImports(PIMPORT_CTX ctx, PIMAGE_IMPORT_DESCRIPTOR pidImportDescriptor, LPVOID lpImgBase) {
	LPCSTR strLibName;
	PVOID hLibrary;
	PIMAGE_THUNK_DATA tLookupThunk;
	PIMAGE_THUNK_DATA tThunk;
	ANSI_STRING AnsiString;
	UNICODE_STRING UnicodeString;

	__builtin_memset(&AnsiString, 0x00, sizeof(AnsiString));
	__builtin_memset(&UnicodeString, 0x00, sizeof(UnicodeString));

	if (pidImportDescriptor->Name == '\0') {
		return;
	}
	
	pdRtlInitAnsiString(&AnsiString, (LPCSTR)pidImportDescriptor->Name + (DWORD_PTR)lpImgBase);

	ctx->status = ctx->pdRtlAnsiStringToUnicodeString(&UnicodeString, &AnsiString, TRUE);
	if (ctx->status != STATUS_SUCCESS) {
		return;
	}

	ctx->status = ctx->pdLdrLoadDll(0, 0, &UnicodeString, &hLibrary);
	if (ctx->status != STATUS_SUCCESS) {
		return;
	}

	if (hLibrary) {
		tThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)lpImgBase + pidImportDescriptor->FirstThunk);
		tLookupThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)lpImgBase + pidImportDescriptor->OriginalFirstThunk);
		pdImportFunction(ctx, lpImgBase, hLibrary, tThunk, tLookupThunk);
	}

	return pdLoadImports(ctx, pidImportDescriptor + 1, lpImgBase);
}
