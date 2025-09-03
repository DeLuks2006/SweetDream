#pragma once
#include "Common.h"

D_SEC( B ) DWORD sdEnumerateThreads(SYSTEM_PROCESS_INFORMATION* ProcessInfo, PBYTE StartMod, PBYTE EndMod);

D_SEC( B ) SYSTEM_PROCESS_INFORMATION* EnumerateProcesses(SYSTEM_PROCESS_INFORMATION* ProcessInfo);

D_SEC( B ) DWORD GetLastTID(VOID);

D_SEC( B ) LRESULT CALLBACK WindowMessageReceiveRoutine(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
