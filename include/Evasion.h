#pragma once
#include "Native.h"
#include "Macros.h"
#include "Misc.h"
#include "Peb.h"

BOOL sdUnhookDll(ULONG Hash, PVOID ModuleBase);

BOOL sdPatchEtw(PVOID hNtdll);

BOOL sdPatchAmsi(PVOID hNtdll);