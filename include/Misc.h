#pragma once
#include "Native.h"
#include "Macros.h"

PVOID sdFindText(PSIZE_T Size, PIMAGE_SECTION_HEADER section, PVOID pe_base);

ULONG sdFowlerA(LPCSTR String);

ULONG sdFowlerW(LPCWSTR String);

SIZE_T sdStringLengthA(LPCSTR String);

SIZE_T sdStringLengthW(LPCWSTR String);

VOID sdRtlInitAnsiString(PANSI_STRING DestinationString, PCSTR SourceString);