#pragma once

#define SERVERNAME_W L"\\MY_LPC_SERVER"
#define SERVERNAME_A  "\\MY_LPC_SERVER"

#define LARGE_MESSAGE_SIZE 0x9000

#include "CommonDefs.h"

#pragma pack(push,1)
#ifndef _KERNEL_MODE
#define PRINT(...) _tprintf(__VA_ARGS__)
#define STRLEN _tcslen
#define STRCOPY wcscpy_s
#else
#pragma comment(lib,"Ntstrsafe.lib")
#include "..\inc\uthash.h"
#define PRINT(...) KdPrint((__VA_ARGS__))
#define _T

FORCEINLINE size_t SafeStrlen(LPCTSTR str)
{
	size_t size;
	NTSTATUS status = RtlStringCchLengthW((STRSAFE_PCNZWCH)str,NTSTRSAFE_MAX_CCH,&size);
	if (NT_SUCCESS(status))
		return size;
	else
		return 0;
}
FORCEINLINE VOID SafeStrCopy(LPTSTR pszDest,size_t cchDest,LPCTSTR pszSrc)
{
	NTSTATUS status = RtlStringCchCopyW((NTSTRSAFE_PWSTR)pszDest,cchDest,(NTSTRSAFE_PCWSTR)pszSrc);
	if (!NT_SUCCESS(status))
		*pszDest = '\0';
}

#define STRLEN(x) SafeStrlen(x)
#define STRCOPY(a,b) SafeStrCopy((LPTSTR)a,SafeStrlen((LPCTSTR)b),(LPCTSTR)b)
		
#endif


#define OBJ_KERNEL_HANDLE       0x00000200L


#define LPC_COMMAND_REQUEST_NOREPLY  0x00000000
#define LPC_COMMAND_REQUEST_REPLY    0x00000001
#define LPC_COMMAND_STOP             0x00000002
#define LPC_COMMAND_RESERVE			 0x00000100

// user define command should be (LPC_COMMAND_RESERVE < x <= 0x7FFFFFFF)
#define IS_COMMAND_RESERVE(x)		 ((x) <= LPC_COMMAND_RESERVE) 
#define IS_COMMAND_ASYNC(x)			 ((x) & 0x80000000) //1 bit to decide async or sync
#define SET_COMMAND(x,y)			 x = (((x) & 0x7FFFFFFF) | ((y) << 31))
#define GET_COMMAND(x)				 x = ((x) & 0x7FFFFFFF)

// This is the data structure transferred through LPC.
// Every structure must begin with PORT_MESSAGE, and must NOT be
// greater that MAX_LPC_DATA

#ifdef _M_X64
#define MAX_LPC_DATA 0x120
#else
#define MAX_LPC_DATA 0x130
#endif // _M_IA64

//(MaxData <= 0x104) and (MaxTotal <= 0x148)
#define MAX_MESSAGE_SIZE 0xFE
typedef struct _TRANSFERRED_MESSAGE
{
	PORT_MESSAGE Header; // (0x18 -- x86)(0x28 -- x64)

	//ULONG	Reserve;			// this byte must be 0, or you get STATUS_INVALID_PARAMETER
	ULONG   Command;			// 4 byte
	BOOLEAN UseSection;			// 1 byte
	WCHAR   MessageText[127];	// 125*2 = 0xFE
	// 0x1 + 0x4 + 0xFE = 0x103 <= 0x104

} TRANSFERRED_MESSAGE, *PTRANSFERRED_MESSAGE;


typedef enum _LPC_TYPE { 
	LPC_NEW_MESSAGE,           // A new message 
	LPC_REQUEST,               // A request message 
	LPC_REPLY,                 // A reply to a request message 
	LPC_DATAGRAM,              // 
	LPC_LOST_REPLY,            // 
	LPC_PORT_CLOSED,           // Sent when port is deleted 
	LPC_CLIENT_DIED,           // Messages to thread termination ports 
	LPC_EXCEPTION,             // Messages to thread exception port 
	LPC_DEBUG_EVENT,           // Messages to thread debug port 
	LPC_ERROR_EVENT,           // Used by ZwRaiseHardError 
	LPC_CONNECTION_REQUEST     // Used by ZwConnectPort 
} LPC_TYPE;

enum ControlMethod
{
	SYNC = 0,
	ASYNC = 1
};

#ifndef InitializeMessageHeader
#define InitializeMessageHeader(ph, l, t)                              \
{                                                                      \
	(ph)->u1.s1.TotalLength      = (USHORT)(l);                        \
	(ph)->u1.s1.DataLength       = (USHORT)(l - sizeof(PORT_MESSAGE)); \
	(ph)->u2.s2.Type             = (USHORT)(t);                        \
	(ph)->u2.s2.DataInfoOffset   = 0;                                  \
	(ph)->ClientId.UniqueProcess = NULL;                               \
	(ph)->ClientId.UniqueThread  = NULL;                               \
	(ph)->MessageId              = 0;                                  \
	(ph)->ClientViewSize         = 0;                                  \
	}
#endif


//unexported functions declare

typedef NTSTATUS (NTAPI* _CreatePort)(
	OUT PHANDLE PortHandle,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG MaxConnectionInfoLength,
	IN ULONG MaxMessageLength,
	IN ULONG MaxPoolUsage
	);


typedef NTSTATUS (NTAPI* _ConnectPort)(
	OUT PHANDLE PortHandle,
	IN PUNICODE_STRING PortName,
	IN PSECURITY_QUALITY_OF_SERVICE SecurityQos,
	IN OUT PPORT_VIEW ClientView OPTIONAL,
	OUT PREMOTE_PORT_VIEW ServerView OPTIONAL,
	OUT PULONG MaxMessageLength OPTIONAL,
	IN OUT PVOID ConnectInformation OPTIONAL,
	IN OUT PULONG ConnectInformationLength OPTIONAL
	);


typedef NTSTATUS (NTAPI* _ListenPort)(
	IN HANDLE PortHandle,
	OUT PPORT_MESSAGE Message
	);


typedef NTSTATUS (NTAPI* _AcceptConnectPort)(
	OUT PHANDLE PortHandle,
	IN PVOID PortIdentifier,
	IN PPORT_MESSAGE Message,
	IN BOOLEAN Accept,
	IN OUT PPORT_VIEW ServerView OPTIONAL,
	OUT PREMOTE_PORT_VIEW ClientView OPTIONAL
	);


typedef NTSTATUS (NTAPI* _CompleteConnectPort)(
	IN HANDLE PortHandle
	);

typedef NTSTATUS (NTAPI* _ReplyPort)(
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE ReplyMessage
	);


typedef NTSTATUS (NTAPI* _ReplyWaitReceivePort)(
	IN HANDLE PortHandle,
	OUT PULONG PortIdentifier OPTIONAL,
	IN PPORT_MESSAGE ReplyMessage OPTIONAL,
	OUT PPORT_MESSAGE Message
	);


typedef NTSTATUS (NTAPI* _ReplyWaitReceivePortEx)(
	IN HANDLE PortHandle,
	OUT PVOID* PortIdentifier OPTIONAL,
	IN PPORT_MESSAGE ReplyMessage OPTIONAL,
	OUT PPORT_MESSAGE Message,
	IN PLARGE_INTEGER Timeout
	);

typedef NTSTATUS (NTAPI* _RequestPort)(
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE RequestMessage
	);


typedef NTSTATUS (NTAPI* _RequestWaitReplyPort)(
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE RequestMessage,
	OUT PPORT_MESSAGE ReplyMessage
	);

typedef NTSTATUS (NTAPI *_ZwCreateSection)(
	_Out_ PHANDLE SectionHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PLARGE_INTEGER MaximumSize,
	_In_ ULONG SectionPageProtection,
	_In_ ULONG AllocationAttributes,
	_In_opt_ HANDLE FileHandle
	);

typedef struct _CLIENT_ENTRY
{
	LIST_ENTRY List;
	HANDLE ClientHandle; // data port
	REMOTE_PORT_VIEW ClientView;
} CLIENT_ENTRY,*PCLIENT_ENTRY;

typedef struct _SERVER_INFO
{
	HANDLE LPCPortHandle;	// connection port
	HANDLE SectionHandle;
	HANDLE ServerThreadHandle;	// Server thread handle
	PORT_VIEW ServerView;
}SERVER_INFO,*PSERVER_INFO;

typedef struct _CLIENT_INFO
{
	HANDLE ServerHandle;	//data port
	PORT_VIEW ClientView;
	REMOTE_PORT_VIEW ServerView;
}CLIENT_INFO,*PCLIENT_INFO;

//data type
#define DATA_NOTIFY_SHUTDOWN 1
#define DATA_TRANSFER_CHATTING 2
#define DATA_TRANSFER_PROCESSS 3



#ifndef _KERNEL_MODE
#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))
#else
extern ULONG m_AllocTag;
#define MALLOC(x) ExAllocatePoolWithTag(PagedPool,x,m_AllocTag)
#define FREE(x)	ExFreePoolWithTag(x,m_AllocTag)
#endif

//http://troydhanson.github.io/uthash/userguide.html
#ifdef _KERNEL_MODE
typedef struct _KERNEL_MAP
{
	int command;		// key
	PVOID callback;		
	UT_hash_handle hh;	// make this structure hashable
} KERNEL_MAP,*PKERNEL_MAP;
#else
void Control( ULONG COMMAND,ULONG method, TCHAR *msg );
#endif

void InsertCallBack(ULONG command,PVOID callback);
void runServer(TCHAR *ServerName);
BOOL Connect(TCHAR *ServerName);
BOOL AsyncSend(TCHAR *msg);
BOOL SyncSend(TCHAR *msg);
BOOL Send(TCHAR *msg,ULONG command);
void StopServer(TCHAR *);

#pragma pack(pop)
