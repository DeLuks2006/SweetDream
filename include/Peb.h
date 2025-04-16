#pragma once
#include "Native.h"
#include "Misc.h"

PVOID pdGetModuleHandle(ULONG Hash);

DWORD64 pdGetProcAddress(PVOID Module, ULONG Hash);