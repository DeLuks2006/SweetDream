#pragma once
#include "Common.h"
typedef int BOOL;

D_SEC( B ) BOOL sdUnhookDll(ULONG Hash, PVOID ModuleBase);

D_SEC( B ) BOOL sdPatchEtw(PVOID hNtdll);

D_SEC( B ) BOOL sdPatchAmsi(PVOID hNtdll);

D_SEC( B ) VOID Xor(PCHAR pBuffer, INT iLen);
