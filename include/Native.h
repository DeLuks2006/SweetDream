#pragma once
#include <windows.h>
// include here all native definitions
typedef int BOOL;

#pragma region Types & Structures
#define STATUS_SUCCESS (NTSTATUS)0x00000000L
#define STATUS_IMAGE_ALREADY_LOADED	(NTSTATUS)0xC000010E

#define FILE_OPEN	0x00000001

#define OBJ_CASE_INSENSITIVE 0x00000040L
#define FILE_NON_DIRECTORY_FILE	0x00000040

#define NOTIFY_FOR_THIS_SESSION	0

#define CurrentTID	(DWORD)__readgsqword(0x48)
#define CurrentPID	(DWORD)__readgsqword(0x40)
#define GetPEB		(PPEB)__readgsqword(0x60)
#define LastError	(DWORD)__readgsdword(0x68)

#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
    (p)->RootDirectory = r; \
    (p)->Attributes = a; \
    (p)->ObjectName = n; \
    (p)->SecurityDescriptor = s; \
    (p)->SecurityQualityOfService = NULL; \
    }

#define SystemProcessInformation 5

typedef LONG KPRIORITY;

typedef BOOLEAN(WINAPI* DLLMAIN_T) (
	HMODULE ImageBase,
	DWORD Reason,
	LPVOID Parameter
);

typedef _Return_type_success_(return >= 0) long NTSTATUS;

typedef struct _STRING {
	USHORT Length;
	USHORT MaximumLength;
	_Field_size_bytes_part_opt_(MaximumLength, Length) PCHAR Buffer;
} STRING, * PSTRING, ANSI_STRING, * PANSI_STRING, OEM_STRING, * POEM_STRING;

typedef const ANSI_STRING* PCANSI_STRING;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	_Field_size_bytes_part_opt_(MaximumLength, Length) PWCH Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef const UNICODE_STRING* PCUNICODE_STRING;

typedef struct _LDR_DATA_TABLE_ENTRY {
	PVOID Reserved1[2];
	LIST_ENTRY InMemoryOrderLinks;
	PVOID Reserved2[2];
	PVOID DllBase;
	PVOID EntryPoint;
	PVOID Reserved3;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName; // previously Reserved4[8]
	PVOID Reserved5[3];
	union {
		ULONG CheckSum;
		PVOID Reserved6;
	};
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
	ULONG Length;
	BOOLEAN Initialized;
	HANDLE SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	BYTE           Reserved1[16];
	PVOID          Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef VOID(NTAPI* PPS_POST_PROCESS_INIT_ROUTINE)(
	VOID
	);

typedef struct _PEB {
	BYTE                          Reserved1[2];
	BYTE                          BeingDebugged;
	BYTE                          Reserved2[1];
	PVOID                         Reserved3[2];
	PPEB_LDR_DATA                 Ldr;
	PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
	PVOID                         Reserved4[3];
	PVOID                         AtlThunkSListPtr;
	PVOID                         Reserved5;
	ULONG                         Reserved6;
	PVOID                         Reserved7;
	ULONG                         Reserved8;
	ULONG                         AtlThunkSListPtr32;
	PVOID                         Reserved9[45];
	BYTE                          Reserved10[96];
	PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
	BYTE                          Reserved11[128];
	PVOID                         Reserved12[1];
	ULONG                         SessionId;
} PEB, * PPEB;


typedef struct _OBJECT_ATTRIBUTES
{
	ULONG Length;
	HANDLE RootDirectory;
	PCUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor; // PSECURITY_DESCRIPTOR;
	PVOID SecurityQualityOfService; // PSECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef const OBJECT_ATTRIBUTES* PCOBJECT_ATTRIBUTES;

typedef struct _IO_STATUS_BLOCK
{
	union
	{
		NTSTATUS Status;
		PVOID Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef enum _SECTION_INHERIT
{
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT;

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID;

typedef struct _SYSTEM_THREAD_INFORMATION {
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	LONG Priority;
	LONG BasePriority;
	ULONG ContextSwitches;
	ULONG ThreadState;
	ULONG WaitReason;
} SYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER WorkingSetPrivateSize;
	ULONG HardFaultCount;
	ULONG NumberOfThreadsHighWatermark;
	ULONGLONG CycleTime;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR UniqueProcessKey;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
	SYSTEM_THREAD_INFORMATION Threads[1];
} SYSTEM_PROCESS_INFORMATION;

//typedef struct _RTL_USER_PROCESS_PARAMETERS
//{
//	ULONG MaximumLength;
//	ULONG Length;
//} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef enum _THREADINFOCLASS
{
	ThreadBasicInformation, // q: THREAD_BASIC_INFORMATION
	ThreadTimes, // q: KERNEL_USER_TIMES
	ThreadPriority, // s: KPRIORITY (requires SeIncreaseBasePriorityPrivilege)
	ThreadBasePriority, // s: KPRIORITY
	ThreadAffinityMask, // s: KAFFINITY
	ThreadImpersonationToken, // s: HANDLE
	ThreadDescriptorTableEntry, // q: DESCRIPTOR_TABLE_ENTRY (or WOW64_DESCRIPTOR_TABLE_ENTRY)
	ThreadEnableAlignmentFaultFixup, // s: BOOLEAN
	ThreadEventPair, // Obsolete
	ThreadQuerySetWin32StartAddress, // q: ULONG_PTR
	ThreadZeroTlsCell, // s: ULONG // TlsIndex // 10
	ThreadPerformanceCount, // q: LARGE_INTEGER
	ThreadAmILastThread, // q: ULONG
	ThreadIdealProcessor, // s: ULONG
	ThreadPriorityBoost, // qs: ULONG
	ThreadSetTlsArrayAddress, // s: ULONG_PTR
	ThreadIsIoPending, // q: ULONG
	ThreadHideFromDebugger, // q: BOOLEAN; s: void
	ThreadBreakOnTermination, // qs: ULONG
	ThreadSwitchLegacyState, // s: void // NtCurrentThread // NPX/FPU
	ThreadIsTerminated, // q: ULONG // 20
	ThreadLastSystemCall, // q: THREAD_LAST_SYSCALL_INFORMATION
	ThreadIoPriority, // qs: IO_PRIORITY_HINT (requires SeIncreaseBasePriorityPrivilege)
	ThreadCycleTime, // q: THREAD_CYCLE_TIME_INFORMATION (requires THREAD_QUERY_LIMITED_INFORMATION)
	ThreadPagePriority, // qs: PAGE_PRIORITY_INFORMATION
	ThreadActualBasePriority, // s: LONG (requires SeIncreaseBasePriorityPrivilege)
	ThreadTebInformation, // q: THREAD_TEB_INFORMATION (requires THREAD_GET_CONTEXT + THREAD_SET_CONTEXT)
	ThreadCSwitchMon, // Obsolete
	ThreadCSwitchPmu, // Obsolete
	ThreadWow64Context, // qs: WOW64_CONTEXT, ARM_NT_CONTEXT since 20H1
	ThreadGroupInformation, // qs: GROUP_AFFINITY // 30
	ThreadUmsInformation, // q: THREAD_UMS_INFORMATION // Obsolete
	ThreadCounterProfiling, // q: BOOLEAN; s: THREAD_PROFILING_INFORMATION?
	ThreadIdealProcessorEx, // qs: PROCESSOR_NUMBER; s: previous PROCESSOR_NUMBER on return
	ThreadCpuAccountingInformation, // q: BOOLEAN; s: HANDLE (NtOpenSession) // NtCurrentThread // since WIN8
	ThreadSuspendCount, // q: ULONG // since WINBLUE
	ThreadHeterogeneousCpuPolicy, // q: KHETERO_CPU_POLICY // since THRESHOLD
	ThreadContainerId, // q: GUID
	ThreadNameInformation, // qs: THREAD_NAME_INFORMATION (requires THREAD_SET_LIMITED_INFORMATION)
	ThreadSelectedCpuSets, // q: ULONG[]
	ThreadSystemThreadInformation, // q: SYSTEM_THREAD_INFORMATION // 40
	ThreadActualGroupAffinity, // q: GROUP_AFFINITY // since THRESHOLD2
	ThreadDynamicCodePolicyInfo, // q: ULONG; s: ULONG (NtCurrentThread)
	ThreadExplicitCaseSensitivity, // qs: ULONG; s: 0 disables, otherwise enables // (requires SeDebugPrivilege and PsProtectedSignerAntimalware)
	ThreadWorkOnBehalfTicket, // ALPC_WORK_ON_BEHALF_TICKET // RTL_WORK_ON_BEHALF_TICKET_EX // NtCurrentThread
	ThreadSubsystemInformation, // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
	ThreadDbgkWerReportActive, // s: ULONG; s: 0 disables, otherwise enables
	ThreadAttachContainer, // s: HANDLE (job object) // NtCurrentThread
	ThreadManageWritesToExecutableMemory, // MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
	ThreadPowerThrottlingState, // qs: POWER_THROTTLING_THREAD_STATE // since REDSTONE3 (set), WIN11 22H2 (query)
	ThreadWorkloadClass, // THREAD_WORKLOAD_CLASS // since REDSTONE5 // 50
	ThreadCreateStateChange, // since WIN11
	ThreadApplyStateChange,
	ThreadStrongerBadHandleChecks, // s: ULONG // NtCurrentThread // since 22H1
	ThreadEffectiveIoPriority, // q: IO_PRIORITY_HINT
	ThreadEffectivePagePriority, // q: ULONG
	ThreadUpdateLockOwnership, // THREAD_LOCK_OWNERSHIP // since 24H2
	ThreadSchedulerSharedDataSlot, // SCHEDULER_SHARED_DATA_SLOT_INFORMATION
	ThreadTebInformationAtomic, // q: THREAD_TEB_INFORMATION (requires THREAD_GET_CONTEXT + THREAD_QUERY_INFORMATION)
	ThreadIndexInformation, // THREAD_INDEX_INFORMATION
	MaxThreadInfoClass
} THREADINFOCLASS;

typedef struct _INITIAL_TEB
{
	struct
	{
		PVOID OldStackBase;
		PVOID OldStackLimit;
	} OldInitialTeb;
	PVOID StackBase;
	PVOID StackLimit;
	PVOID StackAllocationBase;
} INITIAL_TEB, * PINITIAL_TEB;

typedef struct _TEB {
	PVOID Reserved1[12];
	PPEB  ProcessEnvironmentBlock;
	PVOID Reserved2[399];
	BYTE  Reserved3[1952];
	PVOID TlsSlots[64];
	BYTE  Reserved4[8];
	PVOID Reserved5[26];
	PVOID ReservedForOle;
	PVOID Reserved6[4];
	PVOID TlsExpansionSlots;
} TEB, * PTEB;

typedef _Function_class_(USER_THREAD_START_ROUTINE)
NTSTATUS NTAPI USER_THREAD_START_ROUTINE(
	_In_ PVOID ThreadParameter
);

typedef USER_THREAD_START_ROUTINE* PUSER_THREAD_START_ROUTINE;

typedef struct _PS_ATTRIBUTE
{
	ULONG_PTR Attribute;
	SIZE_T Size;
	union
	{
		ULONG_PTR Value;
		PVOID ValuePtr;
	};
	PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST
{
	SIZE_T TotalLength;
	PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

typedef struct _THREAD_BASIC_INFORMATION
{
	NTSTATUS ExitStatus;
	PTEB TebBaseAddress;
	CLIENT_ID ClientId;
	KAFFINITY AffinityMask;
	KPRIORITY Priority;
	KPRIORITY BasePriority;
} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;

#pragma endregion

#pragma region Functions
typedef NTSTATUS(NTAPI* NtAllocateVirtualMemory_t)(
	_In_ HANDLE ProcessHandle,
	_Inout_ PVOID* BaseAddress,
	_In_ ULONG ZeroBits,
	_Inout_ PSIZE_T RegionSize,
	_In_ ULONG AllocationType,
	_In_ ULONG PageProtection
	);

typedef NTSTATUS(NTAPI* NtReadVirtualMemory_t)(
	_In_ HANDLE ProcessHandle,
	_In_opt_ PVOID BaseAddress,
	_Out_writes_bytes_to_(NumberOfBytesToRead, *NumberOfBytesRead) PVOID Buffer,
	_In_ SIZE_T NumberOfBytesToRead,
	_Out_opt_ PSIZE_T NumberOfBytesRead
);

typedef NTSTATUS(NTAPI* NtProtectVirtualMemory_t)(
	_In_ HANDLE ProcessHandle,
	_Inout_ PVOID * BaseAddress,
	_Inout_ PSIZE_T RegionSize,
	_In_ ULONG NewProtection,
	_Out_ PULONG OldProtection
);

typedef NTSTATUS(NTAPI* LdrLoadDll_t)(
	_In_opt_ PCWSTR DllPath,
	_In_opt_ PULONG DllCharacteristics,
	_In_ PUNICODE_STRING DllName,
	_Out_ PVOID * DllHandle
);

typedef NTSTATUS(NTAPI* LdrGetProcedureAddress_t)(
	_In_ PVOID DllHandle,
	_In_opt_ PANSI_STRING ProcedureName,
	_In_opt_ ULONG ProcedureNumber,
	_Out_ PVOID * ProcedureAddress
);

typedef NTSTATUS(NTAPI* RtlAnsiStringToUnicodeString_t)(
	_Inout_ PUNICODE_STRING DestinationString,
	_In_ PCANSI_STRING SourceString,
	_In_ BOOLEAN AllocateDestinationString
);

typedef NTSTATUS (NTAPI* NtCreateSection_t)(
	_Out_ PHANDLE SectionHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ PCOBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PLARGE_INTEGER MaximumSize,
	_In_ ULONG SectionPageProtection,
	_In_ ULONG AllocationAttributes,
	_In_opt_ HANDLE FileHandle
);

typedef NTSTATUS (NTAPI* NtMapViewOfSection_t)(
	_In_ HANDLE SectionHandle,
	_In_ HANDLE ProcessHandle,
	_Inout_ _At_(*BaseAddress, _Readable_bytes_(*ViewSize) _Writable_bytes_(*ViewSize) _Post_readable_byte_size_(*ViewSize)) PVOID* BaseAddress,
	_In_ ULONG_PTR ZeroBits,
	_In_ SIZE_T CommitSize,
	_Inout_opt_ PLARGE_INTEGER SectionOffset,
	_Inout_ PSIZE_T ViewSize,
	_In_ SECTION_INHERIT InheritDisposition,
	_In_ ULONG AllocationType,
	_In_ ULONG PageProtection
);

typedef NTSTATUS (NTAPI* NtUnmapViewOfSection_t)(
	_In_ HANDLE ProcessHandle,
	_In_opt_ PVOID BaseAddress
);

typedef NTSTATUS (NTAPI* NtCreateFile_t)(
	_Out_ PHANDLE FileHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ PCOBJECT_ATTRIBUTES ObjectAttributes,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_In_opt_ PLARGE_INTEGER AllocationSize,
	_In_ ULONG FileAttributes,
	_In_ ULONG ShareAccess,
	_In_ ULONG CreateDisposition,
	_In_ ULONG CreateOptions,
	_In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
	_In_ ULONG EaLength
);

typedef NTSTATUS (NTAPI* NtClose_t)(
	_In_ HANDLE Handle
);

typedef NTSTATUS(WINAPI* NtQuerySystemInformation_t)(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);

typedef NTSTATUS(NTAPI* NtQueryInformationThread_t)(
	_In_ HANDLE ThreadHandle,
	_In_ THREADINFOCLASS ThreadInformationClass,
	_Out_writes_bytes_(ThreadInformationLength) PVOID ThreadInformation,
	_In_ ULONG ThreadInformationLength,
	_Out_opt_ PULONG ReturnLength
	);

typedef NTSTATUS (NTAPI* NtOpenThread_t)(
	_Out_ PHANDLE ThreadHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ PCOBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ CLIENT_ID* ClientId
);

typedef NTSTATUS (NTAPI* NtFreeVirtualMemory_t)(
	_In_ HANDLE ProcessHandle,
	_Inout_ __drv_freesMem(Mem) PVOID* BaseAddress,
	_Inout_ PSIZE_T RegionSize,
	_In_ ULONG FreeType
);

typedef NTSTATUS (NTAPI* NtResumeThread_t)(
	_In_ HANDLE ThreadHandle,
	_Out_opt_ PULONG PreviousSuspendCount
);

typedef NTSTATUS (NTAPI* NtCreateThreadEx_t)(
	_Out_ PHANDLE ThreadHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ PCOBJECT_ATTRIBUTES ObjectAttributes,
	_In_ HANDLE ProcessHandle,
	_In_ PUSER_THREAD_START_ROUTINE StartRoutine,
	_In_opt_ PVOID Argument,
	_In_ ULONG CreateFlags, // THREAD_CREATE_FLAGS_*
	_In_ SIZE_T ZeroBits,
	_In_ SIZE_T StackSize,
	_In_ SIZE_T MaximumStackSize,
	_In_opt_ PPS_ATTRIBUTE_LIST AttributeList
);

typedef NTSTATUS (NTAPI* NtSuspendThread_t)(
	_In_ HANDLE ThreadHandle,
	_Out_opt_ PULONG PreviousSuspendCount
);

typedef NTSTATUS (NTAPI* NtTerminateThread_t)(
	_In_opt_ HANDLE ThreadHandle,
	_In_ NTSTATUS ExitStatus
);

typedef NTSTATUS (NTAPI* NtDelayExecution_t)(
	_In_ BOOLEAN Alertable,
	_In_ PLARGE_INTEGER DelayInterval
);

typedef NTSTATUS(NTAPI* NtTerminateProcess_t)(
	_In_opt_ HANDLE ProcessHandle,
	_In_ NTSTATUS ExitStatus
	);

#pragma endregion

#pragma region Non-NTDLL Functions
typedef BOOL(__stdcall* WTSRegisterSessionNotification_t)(
	_In_ HWND  hWnd,
	_In_ DWORD dwFlags
	);

typedef BOOL(__stdcall* WTSUnRegisterSessionNotification_t)(
	_In_ HWND hWnd
	);

typedef BOOL(__stdcall* PostMessageW_t)(
	_In_opt_	HWND   hWnd,
	_In_        UINT   Msg,
	_In_        WPARAM wParam,
	_In_        LPARAM lParam
);

typedef LRESULT(__stdcall* DefWindowProcW_t)(
	_In_ HWND   hWnd,
	_In_ UINT   Msg,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam
);

typedef ATOM(__stdcall* RegisterClassExW_t)(
	_In_ const WNDCLASSEXW* unnamedParam1
);

typedef HWND(__stdcall* CreateWindowExW_t)(
	_In_			DWORD     dwExStyle,
	_In_opt_		LPCWSTR   lpClassName,
	_In_opt_		LPCWSTR   lpWindowName,
	_In_			DWORD     dwStyle,
	_In_			int       X,
	_In_			int       Y,
	_In_			int       nWidth,
	_In_			int       nHeight,
	_In_opt_		HWND      hWndParent,
	_In_opt_		HMENU     hMenu,
	_In_opt_		HINSTANCE hInstance,
	_In_opt_		LPVOID    lpParam
);

typedef BOOL(__stdcall* GetMessageW_t)(
	_Out_			LPMSG lpMsg,
	_In_opt_		HWND  hWnd,
	_In_			UINT  wMsgFilterMin,
	_In_			UINT  wMsgFilterMax
);

typedef BOOL(__stdcall* TranslateMessage_t)(
	_In_ const MSG* lpMsg
);

typedef LRESULT (__stdcall* DispatchMessageW_t)(
	_In_ const MSG* lpMsg
);

#pragma endregion
