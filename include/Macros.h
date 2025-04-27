#pragma once

#define TEXT								0x88a82ec2

#define NTDLL								0xa62a3b3b
#define USER32								0x9d334019
#define WTSAPI32							0x0f7e276a

// ntdll
#define NT_VIRTUAL_ALLOC					0xca67b978
#define NT_VIRTUAL_PROTECT					0xbd799926
#define NT_VIRTUAL_READ						0x6e2a0391
#define NT_CREATE_SECTION					0x3c59f362
#define NT_MAP_SECTION_VIEW					0xcbc9e1ae
#define NT_UNMAP_SECTION_VIEW				0x53b808c5
#define LDR_GET_PROC_ADDR					0x1478f484
#define LDR_LOAD_DLL						0x7b566b5f
#define RTL_ANSI_TO_UNICODE					0x0322e544
#define NT_CREATE_FILE						0xa9c5b599
#define NT_CLOSE							0x6b372c05
#define NT_QUERY_INFO_THREAD				0x0c06e4e1
#define NT_QUERY_SYSTEM_INFO				0x7a43974a
#define NT_TRACE_EVENT						0x21419e94
#define NT_OPEN_THREAD						0x6c58330b
#define NT_FREE_VIRTUAL_MEM					0xb51cc567
#define NT_RESUME_THREAD					0xe06437fc
#define NT_CREATE_THREAD_EX					0xed0594da
#define NT_SUSPEND_THREAD					0x7d8ddcb1
#define NT_TERMINATE_THREAD					0x5d7da25e
#define NT_DELAY_EXECUTION					0xd856e554
#define NT_DEF_WINDOW_PROC					0x97d3f9d2
#define NT_TERMINATE_PROC					0x1f2f8e87

// amsi
#define AMSI_SCAN_BUFF						0xf76951a4

// user32 <- unhook me too
#define U_POST_MESSAGE_W					0xfd6577e3
#define U_REGISTER_CLASS_EX_W				0xfaa34a2e
#define U_CREATE_WINDOWS_EX_W				0x2d727b8d
#define U_GET_MESSAGE_W						0xc6953fd3
#define U_TRANSLATE_MESSAGE					0xe2f28554
#define U_DISPATCH_MESSAGE_W				0x0d39bb5f

// wtsapi32
#define WTS_REGISTER_SESSION_NOTIFICATION	0xe4de854d
#define WTS_UNREGISTER_SESSION_NOTIFICATION 0x2a7819f4

// REMOVE THIS - IS JUST BC MSVC FOR SOME REASON DOESNT SUPPORT __BUILTIN_MEMCPY
#define __builtin_memcpy memcpy
#define __builtin_memset memset

// all the below shamelessly stolen from titanldr :)

// get relative offset of string or pointer
#define G_SYM( x )	( ULONG_PTR )( GetIp( ) - ( ( ULONG_PTR ) &GetIp - ( ULONG_PTR ) x ) )

// place function in specific region of mem
#define D_SEC( x )	__attribute__((section( ".text$" #x ) ))

// cast as pointer with specified typedef
#define D_API( x )	__typeof__( x ) * x

// cast unsigned pointer-wide int type 
#define U_PTR( x )	( ( ULONG_PTR ) x )

// cast unsigned pointer-wide type
#define C_PTR( x )	( ( PVOID ) x )
