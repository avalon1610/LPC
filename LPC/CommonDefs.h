#pragma once

#ifndef _KERNEL_MODE
#include <windows.h>
#include "UserModeDefs.h"
//#include <map>
#include <stdio.h>
#include <tchar.h>
#else
#define RTL_USE_AVL_TABLES 0
#include <ntifs.h>
#include <Ntstrsafe.h>
//#include "KernelModeDefs.h"
#pragma comment(lib,"Ntstrsafe.lib")
#endif
/*
this header file defines all thing that could be used by ring0 and ring3
for example, simple convention of connection , user-defined struct ,  macros , and so on
*/
#ifdef __cplusplus
extern "C" {
#endif

//
// Define header for Port Message
//
typedef struct _PORT_MESSAGE
{
	union
	{
		struct
		{
			USHORT DataLength;          // Length of data following the header (bytes)
			USHORT TotalLength;         // Length of data + sizeof(PORT_MESSAGE)
		} s1;
		ULONG Length;
	} u1;

	union
	{
		struct
		{
			USHORT Type;
			USHORT DataInfoOffset;
		} s2;
		ULONG ZeroInit;
	} u2;

	union
	{
		CLIENT_ID ClientId;
		double   DoNotUseThisField;     // Force quadword alignment
	};

	SIZE_T MessageId;                   // Identifier of the particular message instance

	union
	{
		ULONG_PTR ClientViewSize;       // Size of section created by the sender (in bytes)
		ULONG  CallbackId;              // 
	};

} PORT_MESSAGE, *PPORT_MESSAGE;
//
// Define structure for initializing shared memory on the caller's side of the port
//

typedef struct _PORT_VIEW {

	SIZE_T Length;                      // Size of this structure
	HANDLE SectionHandle;               // Handle to section object with
	// SECTION_MAP_WRITE and SECTION_MAP_READ
	PVOID  SectionOffset;               // The offset in the section to map a view for

	// the port data area. The offset must be aligned 
	// with the allocation granularity of the system.
	SIZE_T ViewSize;                    // The size of the view (in bytes)
	PVOID  ViewBase;                    // The base address of the view in the creator
	// 
	PVOID  ViewRemoteBase;              // The base address of the view in the process
	// connected to the port.
} PORT_VIEW, *PPORT_VIEW;

//
// Define structure for shared memory coming from remote side of the port
//

typedef struct _REMOTE_PORT_VIEW {

	SIZE_T Length;                      // Size of this structure
	SIZE_T ViewSize;                    // The size of the view (bytes)
	PVOID  ViewBase;                    // Base address of the view

} REMOTE_PORT_VIEW, *PREMOTE_PORT_VIEW;


#ifdef __cplusplus
}
#endif // _cplusplus

#ifdef _KERNEL_MODE
#include "KernelModeDefs.h"
#endif // _KERNEL_MODE

