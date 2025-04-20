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

VOID sdRtlInitUnicodeString(_Inout_ PUNICODE_STRING DestinationString, _In_ PCWSTR SourceString) {
	SIZE_T DestSize;
	if (SourceString) {
		DestSize = sdStringLengthW(SourceString) * sizeof(WCHAR);
		DestinationString->Length = (USHORT)DestSize;
		DestinationString->MaximumLength = (USHORT)DestSize + sizeof(WCHAR);
	}
	else {
		DestinationString->Length = 0;
		DestinationString->MaximumLength = 0;
	}
	DestinationString->Buffer = (PWCHAR)SourceString;
}

// unsafe but idgaf
PVOID sdFindText(PSIZE_T Size, PIMAGE_SECTION_HEADER section, PVOID pe_base) {
	ULONG hash = sdFowlerA((LPCSTR)section->Name);
	if (hash == TEXT) {
		*Size = section->SizeOfRawData;
		return (PVOID)((DWORD_PTR)pe_base + (DWORD_PTR)section->VirtualAddress);
	}
	return sdFindText(Size, ++section, pe_base);
}

PCHAR sdStringCopyA(PCHAR String1, LPCSTR String2) {
	PCHAR p = String1;
	if (*String2 == 0) {
		*p = 0;
		return String1;
	}
	*p = *String2;
	return sdStringCopyA(p + 1, String2 + 1);
}

PWCHAR sdStringCopyW(PWCHAR String1, LPCWSTR String2) {
	PWCHAR p = String1;
	if (*String2 == 0) {
		*p = 0;
		return String1;
	}
	*p = *String2;
	return sdStringCopyW(p + 1, String2 + 1);
}

PCHAR sdStringConcatA(PCHAR String1, LPCSTR String2) {
	return sdStringCopyA(&String1[sdStringLengthA(String1)], String2);
}

PWCHAR sdStringConcatW(PWCHAR String1, LPCWSTR String2) {
	return sdStringCopyW(&String1[sdStringLengthW(String1)], String2);
}

VOID _sdByteArrayToCharArrayA(PCHAR Destination, PBYTE Source, DWORD Length, DWORD dwX = 0) {
	if (dwX < Length) {
		Destination[dwX] = (BYTE)Source[dwX];
		return _sdByteArrayToCharArrayA(Destination, Source, Length, dwX + 1);
	}
}

VOID _sdByteArrayToCharArrayW(PWCHAR Destination, PBYTE Source, DWORD Length, DWORD dwX = 0) {
	if (dwX < Length) {
		Destination[dwX] = (BYTE)Source[dwX];
		return _sdByteArrayToCharArrayW(Destination, Source, Length, dwX + 1);
	}
}

VOID sdByteArrayToCharArrayA(PCHAR Destination, PBYTE Source, DWORD Length) {
	return _sdByteArrayToCharArrayA(Destination, Source, Length, 0);
}

VOID sdByteArrayToCharArrayW(PWCHAR Destination, PBYTE Source, DWORD Length) {
	return _sdByteArrayToCharArrayW(Destination, Source, Length, 0);
}
