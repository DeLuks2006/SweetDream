#include "../include/Misc.h"

ULONG _sdFowlerA(LPCSTR String, ULONG Hash) {
	if (*String == '\0') {
		return Hash;
	}

	if (Hash == 0) {
		Hash = 0x811c9dc5;
	}

	Hash ^= (UCHAR)*String;
	Hash *= 0x01000193;

	return _sdFowlerA(++String, Hash);
}

ULONG _sdFowlerW(LPCWSTR String, ULONG Hash) {
	if (*String == L'\0') {
		return Hash;
	}

	if (Hash == 0) {
		Hash = 0x811c9dc5;
	}

	Hash ^= (UCHAR)*String;
	Hash *= 0x01000193;

	return _sdFowlerW(++String, Hash);
}

ULONG sdFowlerA(LPCSTR String) {
	return _sdFowlerA(String, 0);
}

ULONG sdFowlerW(LPCWSTR String) {
	return _sdFowlerW(String, 0);
}

SIZE_T sdStringLengthA(LPCSTR String) {
	return (*String == '\0') ? 0 : sdStringLengthA(String + 1) + 1;
}

SIZE_T sdStringLengthW(LPCWSTR String) {
	return (*String == L'\0') ? 0 : sdStringLengthW(String + 1) + 1;
}

// Stolen from vx-api :P
VOID sdRtlInitAnsiString(PANSI_STRING DestinationString, PCSTR SourceString) {
	SIZE_T Size;

	if (SourceString) {
		Size = sdStringLengthA(SourceString);
		if (Size > (65535 - sizeof(CHAR))) {
			Size = 65535 - sizeof(CHAR);
		}
		DestinationString->Length = (USHORT)Size;
		DestinationString->MaximumLength = (USHORT)Size + sizeof(CHAR);
	}
	else {
		DestinationString->Length = 0;
		DestinationString->MaximumLength = 0;
	}

	DestinationString->Buffer = (PCHAR)SourceString;
}

// unsafe but idgaf
PVOID sdFindText(PSIZE_T Size, PIMAGE_SECTION_HEADER section, PVOID pe_base) {
	ULONG hash = sdFowlerA((LPCSTR)section->Name);
	if (hash == TEXT) {
		*Size = section->SizeOfRawData;
		return ((char*)pe_base + section->VirtualAddress);
	}
	return sdFindText(Size, ++section, pe_base);
}