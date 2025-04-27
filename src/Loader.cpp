#include "../include/Loader.h"

void sdCopySections(PIMAGE_SECTION_HEADER shSection, DWORD dwNumSections, DWORD dwSectionsProcessed, LPVOID lpImgBase, LPVOID lpFile) {
	PVOID lpDestination;
	PVOID lpBytes;

	if (dwNumSections == dwSectionsProcessed) {
		return;
	}

	lpDestination = (PVOID)((DWORD_PTR)lpImgBase + (DWORD_PTR)shSection->VirtualAddress);
	lpBytes = (PVOID)((DWORD_PTR)lpFile + (DWORD_PTR)shSection->PointerToRawData);

	__builtin_memcpy(lpDestination, lpBytes, shSection->SizeOfRawData);

	sdCopySections(shSection + 1, dwNumSections, dwSectionsProcessed + 1, lpImgBase, lpFile);
	
}

void sdRelocateBlock(PRELOC_CTX pRelocCtx) {
	DWORD_PTR pdwRelocRVA;
	DWORD_PTR pdwPatchPtr;
	PRELOC_BLOCK_CTX ctx = pRelocCtx->pBlockCtx;
	int i = pRelocCtx->pBlockCtx->iCounter;

	if (i == ctx->dwRelocCount) {
		return;
	}

	if (ctx->pRelocEntries[i].usType == 0) {
		ctx->iCounter += 1;
		pRelocCtx->szRelocsProcessed += sizeof(BASE_RELOCATION_ENTRY);
		return sdRelocateBlock(pRelocCtx);
	}

	pdwRelocRVA = ctx->pRelocBlock->dwPageAddress + ctx->pRelocEntries[i].usOffset;
	pdwPatchPtr = 0;
	pRelocCtx->NtStatus = pRelocCtx->NtReadVirtualMemory(((HANDLE)-1), (LPVOID)((DWORD_PTR)pRelocCtx->lpImgBase + pdwRelocRVA), &pdwPatchPtr, sizeof(DWORD_PTR), NULL);
	if (pRelocCtx->NtStatus != STATUS_SUCCESS) {
		return;
	}
	pdwPatchPtr += ctx->pdwDelta;
	__builtin_memcpy((PVOID)((DWORD_PTR)pRelocCtx->lpImgBase + pdwRelocRVA), &pdwPatchPtr, sizeof(DWORD_PTR));
	
	pRelocCtx->pBlockCtx->iCounter += 1;
	pRelocCtx->szRelocsProcessed += sizeof(BASE_RELOCATION_ENTRY);
	return sdRelocateBlock(pRelocCtx);
}

void sdPerformRelocs(PRELOC_CTX ctx, DWORD_PTR pdwDelta) {
	RELOC_BLOCK_CTX rbcRelocCtx;
	ctx->pBlockCtx = &rbcRelocCtx;

	if (ctx->szRelocsProcessed >= ctx->RelocDir.Size) {
		return;
	}

	rbcRelocCtx.pRelocBlock = (PBASE_RELOCATION_BLOCK)(ctx->pdwRelocTable + ctx->szRelocsProcessed);
	ctx->szRelocsProcessed += sizeof(BASE_RELOCATION_BLOCK);
	rbcRelocCtx.dwRelocCount = (rbcRelocCtx.pRelocBlock->dwBlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
	rbcRelocCtx.pRelocEntries = (PBASE_RELOCATION_ENTRY)(ctx->pdwRelocTable + ctx->szRelocsProcessed);
	rbcRelocCtx.iCounter = 0;
	rbcRelocCtx.pdwDelta = pdwDelta;
	
	sdRelocateBlock(ctx);

	return sdPerformRelocs(ctx, pdwDelta);
}

void sdImportFunction(PIMPORT_CTX ctx, LPVOID lpImgBase, PVOID hLib, PIMAGE_THUNK_DATA tThunk, PIMAGE_THUNK_DATA tLookupThunk) {
	PIMAGE_IMPORT_BY_NAME impFnName;
	ANSI_STRING AnsiString;
	PVOID pFunction;

	if (tThunk->u1.AddressOfData == 0) {
		return;
	}

	if (IMAGE_SNAP_BY_ORDINAL(tLookupThunk->u1.Ordinal)) {
		ctx->NtStatus = ctx->LdrGetProcedureAddress(hLib, NULL, IMAGE_ORDINAL(tLookupThunk->u1.Ordinal), &pFunction);
		if (ctx->NtStatus == STATUS_SUCCESS) {
			tThunk->u1.Function = (ULONGLONG)pFunction;
		}
	}
	else {
		impFnName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)lpImgBase + tLookupThunk->u1.AddressOfData);
		sdRtlInitAnsiString(&AnsiString, impFnName->Name);
		ctx->NtStatus = ctx->LdrGetProcedureAddress(hLib, &AnsiString, 0, &pFunction);
		if (ctx->NtStatus == STATUS_SUCCESS) {
			tThunk->u1.Function = (ULONGLONG)pFunction;
		}
	}

	return sdImportFunction(ctx, lpImgBase, hLib, tThunk+1, tLookupThunk+1);
}

void sdLoadImports(PIMPORT_CTX ctx, PIMAGE_IMPORT_DESCRIPTOR pidImportDescriptor, LPVOID lpImgBase) {
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
	
	sdRtlInitAnsiString(&AnsiString, (LPCSTR)pidImportDescriptor->Name + (DWORD_PTR)lpImgBase);

	ctx->NtStatus = ctx->RtlAnsiStringToUnicodeString(&UnicodeString, &AnsiString, TRUE);
	if (ctx->NtStatus != STATUS_SUCCESS) {
		return;
	}

	ctx->NtStatus = ctx->LdrLoadDll(0, 0, &UnicodeString, &hLibrary);
	if (ctx->NtStatus != STATUS_SUCCESS) {
		return;
	}

	if (hLibrary) {
		tThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)lpImgBase + pidImportDescriptor->FirstThunk);
		tLookupThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)lpImgBase + pidImportDescriptor->OriginalFirstThunk);
		sdImportFunction(ctx, lpImgBase, hLibrary, tThunk, tLookupThunk);
	}

	return sdLoadImports(ctx, pidImportDescriptor + 1, lpImgBase);
}
