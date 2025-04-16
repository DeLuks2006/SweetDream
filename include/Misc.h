#pragma once
#include "Native.h"
#include "Macros.h"

PVOID pdFindText(PSIZE_T Size, PIMAGE_SECTION_HEADER section, PVOID pe_base);

ULONG pdFowlerA(LPCSTR String);

ULONG pdFowlerW(LPCWSTR String);

SIZE_T pdStringLengthA(LPCSTR String);

SIZE_T pdStringLengthW(LPCWSTR String);

VOID pdRtlInitAnsiString(PANSI_STRING DestinationString, PCSTR SourceString);