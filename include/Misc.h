#pragma once
#include "Common.h"

D_SEC( B ) ULONG sdFowlerA(LPCSTR String);

D_SEC( B ) ULONG sdFowlerW(LPCWSTR String);

D_SEC( B ) SIZE_T sdStringLengthA(LPCSTR String);

D_SEC( B ) SIZE_T sdStringLengthW(LPCWSTR String);

D_SEC( B ) VOID sdRtlInitAnsiString(PANSI_STRING DestinationString, PCSTR SourceString);

D_SEC( B ) VOID sdRtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString);

D_SEC( B ) PVOID sdFindText(PSIZE_T Size, PIMAGE_SECTION_HEADER section, PVOID pe_base);

D_SEC( B ) PCHAR sdStringCopyA(PCHAR String1, LPCSTR String2);

D_SEC( B ) PWCHAR sdStringCopyW(PWCHAR String1, LPCWSTR String2);

D_SEC( B ) PCHAR sdStringConcatA(PCHAR String1, LPCSTR String2);

D_SEC( B ) PWCHAR sdStringConcatW(PWCHAR String1, LPCWSTR String2);

D_SEC( B ) VOID sdByteArrayToCharArrayA(PCHAR Destination, PBYTE Source, DWORD Length);

D_SEC( B ) VOID sdByteArrayToCharArrayW(PWCHAR Destination, PBYTE Source, DWORD Length);
