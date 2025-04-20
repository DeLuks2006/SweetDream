#pragma once
#include "Native.h"
#include "Macros.h"

ULONG sdFowlerA(LPCSTR String);

ULONG sdFowlerW(LPCWSTR String);

SIZE_T sdStringLengthA(LPCSTR String);

SIZE_T sdStringLengthW(LPCWSTR String);

VOID sdRtlInitAnsiString(PANSI_STRING DestinationString, PCSTR SourceString);

VOID sdRtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString);

PVOID sdFindText(PSIZE_T Size, PIMAGE_SECTION_HEADER section, PVOID pe_base);

PCHAR sdStringCopyA(PCHAR String1, LPCSTR String2);

PWCHAR sdStringCopyW(PWCHAR String1, LPCWSTR String2);

PCHAR sdStringConcatA(PCHAR String1, LPCSTR String2);

PWCHAR sdStringConcatW(PWCHAR String1, LPCWSTR String2);