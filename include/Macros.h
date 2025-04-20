#pragma once

#define TEXT					0x88a82ec2

#define NTDLL					0xa62a3b3b
#define KRNL32					0x29cdd463

#define NT_VIRTUAL_ALLOC		0xca67b978
#define NT_VIRTUAL_PROTECT		0xbd799926
#define NT_VIRTUAL_READ			0x6e2a0391
#define NT_CREATE_SECTION		0x3c59f362
#define NT_MAP_SECTION_VIEW		0xcbc9e1ae
#define NT_UNMAP_SECTION_VIEW	0x53b808c5
#define LDR_GET_PROC_ADDR		0x1478f484
#define LDR_GET_DLL				0x7b566b5f
#define RTL_ANSI_TO_UNICODE		0x0322e544
#define NT_CLOSE				0x6b372c05
#define NT_CREATE_FILE			0xa9c5b599

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
