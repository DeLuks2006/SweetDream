#pragma once
#include <windows.h>
// include here all native definitions

#pragma region Types & Structures
#define STATUS_SUCCESS (NTSTATUS)0x00000000L

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
	BYTE       Reserved1[8];
	PVOID      Reserved2[3];
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

#define OBJ_CASE_INSENSITIVE 0x00000040L
#define FILE_NON_DIRECTORY_FILE 0x00000040

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

#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
    (p)->RootDirectory = r; \
    (p)->Attributes = a; \
    (p)->ObjectName = n; \
    (p)->SecurityDescriptor = s; \
    (p)->SecurityQualityOfService = NULL; \
    }

#pragma endregion

#pragma region Functions
typedef NTSTATUS(NTAPI* fn_NtAllocateVirtualMemory)(
	_In_ HANDLE ProcessHandle,
	_Inout_ PVOID* BaseAddress,
	_In_ ULONG ZeroBits,
	_Inout_ PSIZE_T RegionSize,
	_In_ ULONG AllocationType,
	_In_ ULONG PageProtection
	);

typedef NTSTATUS(NTAPI* fn_NtReadVirtualMemory)(
	_In_ HANDLE ProcessHandle,
	_In_opt_ PVOID BaseAddress,
	_Out_writes_bytes_to_(NumberOfBytesToRead, *NumberOfBytesRead) PVOID Buffer,
	_In_ SIZE_T NumberOfBytesToRead,
	_Out_opt_ PSIZE_T NumberOfBytesRead
);

typedef NTSTATUS(NTAPI* fn_NtProtectVirtualMemory)(
	_In_ HANDLE ProcessHandle,
	_Inout_ PVOID * BaseAddress,
	_Inout_ PSIZE_T RegionSize,
	_In_ ULONG NewProtection,
	_Out_ PULONG OldProtection
);

typedef NTSTATUS(NTAPI * fn_LdrLoadDll)(
	_In_opt_ PCWSTR DllPath,
	_In_opt_ PULONG DllCharacteristics,
	_In_ PUNICODE_STRING DllName,
	_Out_ PVOID * DllHandle
);

typedef NTSTATUS(NTAPI* fn_LdrGetProcedureAddress)(
	_In_ PVOID DllHandle,
	_In_opt_ PANSI_STRING ProcedureName,
	_In_opt_ ULONG ProcedureNumber,
	_Out_ PVOID * ProcedureAddress
);

typedef NTSTATUS(NTAPI* fn_RtlAnsiStringToUnicodeString)(
	_Inout_ PUNICODE_STRING DestinationString,
	_In_ PCANSI_STRING SourceString,
	_In_ BOOLEAN AllocateDestinationString
);

typedef NTSTATUS (NTAPI* fn_NtCreateSection)(
	_Out_ PHANDLE SectionHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ PCOBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PLARGE_INTEGER MaximumSize,
	_In_ ULONG SectionPageProtection,
	_In_ ULONG AllocationAttributes,
	_In_opt_ HANDLE FileHandle
);

typedef NTSTATUS (NTAPI* fn_NtMapViewOfSection)(
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

typedef NTSTATUS (NTAPI* fn_NtUnmapViewOfSection)(
	_In_ HANDLE ProcessHandle,
	_In_opt_ PVOID BaseAddress
);

#define FILE_OPEN                           0x00000001
typedef NTSTATUS (NTAPI* fn_NtCreateFile)(
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

typedef NTSTATUS (NTAPI* fn_NtClose)(
	_In_ _Post_ptr_invalid_ HANDLE Handle
);

#pragma endregion