#include "../include/Misc.h"

ULONG _pdFowlerA(LPCSTR String, ULONG Hash) {
	if (*String == '\0') {
		return Hash;
	}

	if (Hash == 0) {
		Hash = 0x811c9dc5;
	}

	Hash ^= (UCHAR)*String;
	Hash *= 0x01000193;

	return _pdFowlerA(++String, Hash);
}

ULONG _pdFowlerW(LPCWSTR String, ULONG Hash) {
	if (*String == L'\0') {
		return Hash;
	}

	if (Hash == 0) {
		Hash = 0x811c9dc5;
	}

	Hash ^= (UCHAR)*String;
	Hash *= 0x01000193;

	return _pdFowlerW(++String, Hash);
}

ULONG pdFowlerA(LPCSTR String) {
	return _pdFowlerA(String, 0);
}

ULONG pdFowlerW(LPCWSTR String) {
	return _pdFowlerW(String, 0);
}

SIZE_T pdStringLengthA(LPCSTR String) {
	return (*String == '\0') ? 0 : pdStringLengthA(String + 1) + 1;
}

SIZE_T pdStringLengthW(LPCWSTR String) {
	return (*String == L'\0') ? 0 : pdStringLengthW(String + 1) + 1;
}

// Stolen from vx-api :P
VOID pdRtlInitAnsiString(PANSI_STRING DestinationString, PCSTR SourceString) {
	SIZE_T Size;

	if (SourceString) {
		Size = pdStringLengthA(SourceString);
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
PVOID pdFindText(PSIZE_T Size, PIMAGE_SECTION_HEADER section, PVOID pe_base) {
	ULONG hash = pdFowlerA((LPCSTR)section->Name);
	if (hash == TEXT) {
		*Size = section->SizeOfRawData;
		return ((char*)pe_base + section->VirtualAddress);
	}
	return pdFindText(Size, ++section, pe_base);
}