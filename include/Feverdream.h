#pragma once
#include "Common.h"

DWORD sdEnumerateThreads(SYSTEM_PROCESS_INFORMATION* ProcessInfo, PBYTE StartMod, PBYTE EndMod);

SYSTEM_PROCESS_INFORMATION* EnumerateProcesses(SYSTEM_PROCESS_INFORMATION* ProcessInfo);

DWORD GetLastTID(VOID);

LRESULT CALLBACK WindowMessageReceiveRoutine(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
