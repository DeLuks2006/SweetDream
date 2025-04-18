#pragma once
#include "Native.h"
#include "Misc.h"

PVOID sdGetModuleHandle(ULONG Hash);

DWORD64 sdGetProcAddress(PVOID Module, ULONG Hash);