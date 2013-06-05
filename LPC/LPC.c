#include "LPC.h"

_CreatePort				NtCreatePort;
_ListenPort				NtListenPort;
_AcceptConnectPort		NtAcceptConnectPort;
_CompleteConnectPort	NtCompleteConnectPort;
_ReplyPort				NtReplyPort;
_ReplyWaitReceivePort	NtReplyWaitReceivePort;
_ReplyWaitReceivePortEx	NtReplyWaitReceivePortEx;
_RequestPort			NtRequestPort;
_RequestWaitReplyPort	NtRequestWaitReplyPort;
_ConnectPort			NtConnectPort; //exported
#ifndef _KERNEL_MODE
_InitUnicodeString		RtlInitUnicodeString;
_ZwCreateSection		ZwCreateSection;

MAP CallBackList; 
BOOL InitProcAddress();
BOOL CheckWOW64();
#else
KERNEL_MAP *CallBackList;
PVOID FindCallBack(ULONG command);
BOOL FindKernelFunction();
#endif

HANDLE hConnectPort;
HANDLE SectionHandle;
HANDLE hThread;
SERVER_INFO si;
CLIENT_INFO ci;
LIST_ENTRY head;
void ServerProc(SERVER_INFO *);
BOOL KeepRunning;

ULONG m_AllocTag = ' ZAR';
BOOL Debug = FALSE;

#ifdef _KERNEL_MODE
BOOL doKernelInit()
{
	CallBackList = NULL;//MALLOC(sizeof(CallBackList));
	return FindKernelFunction();
}
#endif

BOOL Initialize(void)
{
	BOOL bOK = FALSE;
	RtlZeroMemory(&ci,sizeof(CLIENT_INFO));
	RtlZeroMemory(&si,sizeof(SERVER_INFO));
#ifndef _KERNEL_MODE
	if (CheckWOW64())
	{
		return bOK;
	}
	bOK = InitProcAddress();
#else
	// in kernel mode, must do initialize explicitly
	bOK = doKernelInit();
#endif
	return bOK;
}

#ifdef _KERNEL_MODE
PVOID FindCallBack(ULONG command)
{
	KERNEL_MAP *k;
	HASH_FIND_INT(CallBackList,&command,k);
	if (k == NULL)
		return NULL;
	else
		return k->callback;
}
#endif // _KERNEL_MODE

void InsertCallBack(ULONG command,PVOID callback)
{
#ifdef _KERNEL_MODE
	KERNEL_MAP *k;
	if (!FindCallBack(command))
	{
		k = (KERNEL_MAP *)MALLOC(sizeof(KERNEL_MAP));
		k->command = command;
		k->callback = callback;
		HASH_ADD_INT(CallBackList,command,k);
	}
#else
	CallBackList[command] = callback;
#endif
}


void runServer(TCHAR *LpcPortName)
{
	UNICODE_STRING usPortName;
	OBJECT_ATTRIBUTES obj;
	LARGE_INTEGER SectionSize = {LARGE_MESSAGE_SIZE};

	if (LpcPortName == NULL)
		LpcPortName = (TCHAR *)SERVERNAME_W;

	if (!Initialize())
	{
		PRINT(_T("Initialize Failed!!!\n"));
		return;
	}

	InitializeListHead(&head);
	//HANDLE SectionHandle = NULL;
	__try
	{
		HANDLE ThreadHandle;
		NTSTATUS status = ZwCreateSection(&SectionHandle,
										  SECTION_MAP_READ | SECTION_MAP_WRITE,
										  NULL,	//backed by the pagefile
										  &SectionSize,
										  PAGE_READWRITE,
										  SEC_COMMIT,
										  NULL);
		
		if (!NT_SUCCESS(status))
		{
			PRINT(_T("ZwCreateSection error 0x%08lX\n"),status);
			__leave;
		}

		RtlInitUnicodeString(&usPortName,(PCWSTR)LpcPortName);
		InitializeObjectAttributes(&obj,&usPortName,0,NULL,NULL);

		//NtCreatePort checks whether (MaxConnectionInfoLength <= 0x104) and (MaxMessageLength <= 0x148).
		status = NtCreatePort(&hConnectPort,&obj,0x104,sizeof(PORT_MESSAGE) + MAX_LPC_DATA,0);
		
		if (!NT_SUCCESS(status))
		{
			PRINT(_T("NtCreatePort error 0x%08lX\n"),status);
			__leave;
		}

		si.LPCPortHandle = hConnectPort;
		si.SectionHandle = SectionHandle;
		KeepRunning = TRUE;

#ifndef _KERNEL_MODE
		ThreadHandle = CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)&ServerProc,(LPVOID)&si,0,NULL);
		if (ThreadHandle == NULL)
		{
			PRINT(_T("CreateThread ServerProc error:%d\n"),GetLastError());
			__leave;
		}	
#else
		status = PsCreateSystemThread(&ThreadHandle,0,NULL,NULL,NULL,(PKSTART_ROUTINE)&ServerProc,(PVOID)&si);
		if (!NT_SUCCESS(status))
		{
			PRINT("PsCreateSystemThread Error:0x%X\n",status);
			__leave;
		}
#endif
		si.ServerThreadHandle = ThreadHandle;
		PRINT(_T("Listening to Port \"%ws\",wait for connect...\n"),LpcPortName);
	}
	__finally
	{

	}
}

void ServerProc(SERVER_INFO *si)
{
	HANDLE ConnectionHandle = si->LPCPortHandle;
	//PORT_MESSAGE *MessageHeader = (PORT_MESSAGE *)MALLOC(sizeof(PORT_MESSAGE));
	PTRANSFERRED_MESSAGE LPCMessage = (PTRANSFERRED_MESSAGE)MALLOC(sizeof(TRANSFERRED_MESSAGE));
	PORT_MESSAGE *MessageHeader = &LPCMessage->Header;
	NTSTATUS status;
	ULONG count = 0;
	PORT_VIEW ServerView;
	HANDLE DataPortHandle = NULL;
	REMOTE_PORT_VIEW ClientView;
	BOOL isExist = TRUE;
	HANDLE ClientHandle = NULL;
	CLIENT_ENTRY *ConnectedClient = NULL;

	RtlZeroMemory(LPCMessage,sizeof(TRANSFERRED_MESSAGE));

	//
	// Fill local and remote memory views. When the LPC
	// message comes to the client, the section will be remapped
	// to be accessible to the listener, even if the client is in another
	// process or different processor mode (UserMode/KernelMode)
	//
	ServerView.Length = sizeof(PORT_VIEW);
	ServerView.SectionHandle = si->SectionHandle;
	ServerView.SectionOffset = 0;
	ServerView.ViewSize = LARGE_MESSAGE_SIZE;
	si->ServerView = ServerView;
	ClientView.Length = sizeof(REMOTE_PORT_VIEW);

	while (KeepRunning)
	{
		LIST_ENTRY *pEntry = (&head)->Flink;
		TCHAR *buffer;
		status = NtReplyWaitReceivePort(ConnectionHandle,(PULONG)&ClientHandle,NULL,MessageHeader);
		
		if (!NT_SUCCESS(status))
		{
			PRINT(_T("NtReplyWaitReceivePort error 0x%08lX\n"),status);
			break;
		}

		isExist = FALSE;
		while (pEntry != &head)
		{
			CLIENT_ENTRY *info = CONTAINING_RECORD(pEntry,CLIENT_ENTRY,List);
			if (info->ClientHandle == ClientHandle)
			{
				isExist = TRUE;
				ConnectedClient = info;
				break;
			}
			pEntry = pEntry->Flink;
		}

		if (MessageHeader->u2.s2.Type == LPC_CONNECTION_REQUEST)
		{
			CLIENT_ENTRY *ce;
			if (isExist)
			{
				PRINT(_T("client [%08lX] message type error!\n"),ClientHandle);
				continue;
			}
			
			status = NtAcceptConnectPort(&DataPortHandle,NULL,MessageHeader,TRUE,&ServerView,&ClientView);
		
			if (!NT_SUCCESS(status))
			{
				PRINT(_T("NtAcceptConnectPort error 0x%08lX\n"),status);
				break;
			}

			status = NtCompleteConnectPort(DataPortHandle);
			if (!NT_SUCCESS(status))
			{
				PRINT(_T("NtCompleteConnectPort error 0x%08lX\n"),status);
				break;
			}

			ce = (CLIENT_ENTRY *)MALLOC(sizeof(CLIENT_ENTRY));
			ce->ClientHandle = DataPortHandle;
			ce->ClientView = ClientView;
			InsertHeadList(&head,&ce->List);
			PRINT(_T("client [%08lX] connected,wait for message...\n"),DataPortHandle);
			
			continue;
		}
		else if (MessageHeader->u2.s2.Type == LPC_PORT_CLOSED)
		{
			RemoveEntryList(&ConnectedClient->List);
			PRINT(_T("client [%08lX] die...\n"),ClientHandle);
			continue;
		}
		
		//normal message handle
		if (!isExist)
		{
			PRINT(_T("Maybe Server Shutdown Request..\n"));
			continue;
		}
		
		LPCMessage = (PTRANSFERRED_MESSAGE)MessageHeader;
		if (IS_COMMAND_RESERVE(LPCMessage->Command))
		{
			TRANSFERRED_MESSAGE replayMsg;
			switch (LPCMessage->Command)
			{
			case LPC_COMMAND_REQUEST_NOREPLY:
				break;
			case LPC_COMMAND_REQUEST_REPLY:
				RtlCopyMemory(&replayMsg,LPCMessage,sizeof(TRANSFERRED_MESSAGE));
				STRCOPY(replayMsg.MessageText,_T("Server Answer!"));
				status = NtReplyPort(ClientHandle,&replayMsg.Header);
				if (!NT_SUCCESS(status))
					PRINT(_T("Reply Error: 0x%08lX\n"),status);
				break;
			case LPC_COMMAND_STOP:
				PRINT(_T("[%08lX] Shutdown the Server! We die ...\n"),ClientHandle);
				KeepRunning = FALSE;
				break;
			default:
				break;
			}
		}
		else
		{
#ifndef _KERNEL_MODE
			MAP::iterator iter;
			HANDLE hThread;
			iter = CallBackList.find(GET_COMMAND(LPCMessage->Command));
			if (iter == CallBackList.end())
				PRINT(_T("Can't find callback function using %d\n"),LPCMessage->Command);
			else
			{
				hThread = CreateThread(NULL,NULL,(LPTHREAD_START_ROUTINE)iter->second,LPCMessage->MessageText,0,0);
				if (hThread == INVALID_HANDLE_VALUE)
					PRINT(_T("call callback function failed %d\n"),GetLastError());
				if (!IS_COMMAND_ASYNC(LPCMessage->Command))
				{
					WaitForSingleObject(hThread,INFINITE);

					TRANSFERRED_MESSAGE replayMsg;
					RtlCopyMemory(&replayMsg,LPCMessage,sizeof(TRANSFERRED_MESSAGE));
					STRCOPY(replayMsg.MessageText,_T("Server Answer!"));
					status = NtReplyPort(ClientHandle,&replayMsg.Header);
					if (!NT_SUCCESS(status))
						PRINT(_T("Reply Error: 0x%08lX\n"),status);
				}
			}
#else
			// to do ..
			ULONG command = GET_COMMAND(LPCMessage->Command);
			PVOID callback = FindCallBack(command);
			if (callback)
			{
				HANDLE tHandle;
				status = PsCreateSystemThread(&tHandle,0,NULL,NULL,NULL,(PKSTART_ROUTINE)callback,LPCMessage->MessageText);
				if (!NT_SUCCESS(status))
					PRINT(_T("call callback function failed %d\n"),status);
				if (!IS_COMMAND_ASYNC(LPCMessage->Command))
				{
					TRANSFERRED_MESSAGE replayMsg;
					ZwWaitForSingleObject(tHandle,FALSE,NULL);

					RtlCopyMemory(&replayMsg,LPCMessage,sizeof(TRANSFERRED_MESSAGE));
					STRCOPY(replayMsg.MessageText,_T("Server Answer!"));
					status = NtReplyPort(ClientHandle,&replayMsg.Header);
					if (!NT_SUCCESS(status))
						PRINT(_T("Reply Error: 0x%08lX\n"),status);

				}

				ZwClose(tHandle);
			}
			else
				PRINT(_T("Can't find callback function using %d\n"),LPCMessage->Command);
#endif	
		}
		
		buffer = (TCHAR *)MALLOC(sizeof(TCHAR)*LARGE_MESSAGE_SIZE);
		if (LPCMessage->UseSection)
		{
			PRINT(_T("[Received Large Data]\n"));
			RtlCopyMemory(buffer,ConnectedClient->ClientView.ViewBase,ConnectedClient->ClientView.ViewSize);
			PRINT(_T("[%08lX]:%ws\n"),ClientHandle,buffer);
		}
		else
		{
			RtlCopyMemory(buffer,LPCMessage->MessageText,MAX_MESSAGE_SIZE);
			PRINT(_T("[%08lX]:%ws\n"),ClientHandle,buffer);
		}
		
		FREE(buffer);
	} //end of while

	FREE(LPCMessage);

#ifdef _KERNEL_MODE
	NtClose(ConnectionHandle);
	PsTerminateSystemThread(STATUS_SUCCESS);
#else
	CloseHandle(ConnectionHandle);
#endif
	
}

#ifdef _KERNEL_MODE
BOOL KillThread(PETHREAD Thread);

void StopServer(TCHAR *ServerName)
{
	/*NTSTATUS status;
	PETHREAD Thread;

	KeepRunning = FALSE;
	status = ObReferenceObjectByHandle(si.ServerThreadHandle,THREAD_ALL_ACCESS,*PsThreadType,KernelMode,&Thread,NULL);
	if (!NT_SUCCESS(status))
	{
		PRINT("ObReferenceObjectByHandle Error:%X\n",status);
		return;
	}
	
	if (!KillThread(Thread))
		return;
	*/
	NTSTATUS status;
	PORT_MESSAGE Request;
	PORT_MESSAGE IncomingReply;
	KeepRunning = FALSE;
	InitializeMessageHeader(&Request,sizeof(PORT_MESSAGE),LPC_NEW_MESSAGE);
	status = NtRequestWaitReplyPort(si.LPCPortHandle,&Request,&IncomingReply);
	if (!NT_SUCCESS(status) && status != STATUS_LPC_REPLY_LOST)
		return;
	status = ZwWaitForSingleObject(si.ServerThreadHandle,FALSE,NULL);
	if (!NT_SUCCESS(status))
		PRINT("ZwWaitForSingleObject Error:%X\n",status);
	ZwClose(si.ServerThreadHandle);
	
}
#endif // _KERNEL_MODE

BOOL Connect(TCHAR *LpcPortName)
{
	BOOL success = FALSE;
	UNICODE_STRING usPortName;

	SECURITY_QUALITY_OF_SERVICE SecurityQos;
	REMOTE_PORT_VIEW ServerView;
	LARGE_INTEGER SectionSize = {LARGE_MESSAGE_SIZE};
	PORT_VIEW ClientView;
	if (!Initialize())
	{
		PRINT(_T("Initialize Failed!!!\n"));
		return success;
	}
	
	RtlInitUnicodeString(&usPortName,(PCWSTR)LpcPortName);

	__try
	{
		HANDLE PortHandle = NULL;
		NTSTATUS status = ZwCreateSection(&SectionHandle,
										  SECTION_MAP_READ | SECTION_MAP_WRITE,
										  NULL,
										  &SectionSize,
										  PAGE_READWRITE,
										  SEC_COMMIT,
										  NULL);
		
		if (!NT_SUCCESS(status))
		{
			PRINT(_T("NtCreateSection result 0x%08lX\n"),status);
			__leave;
		}

		//
		// Initialize the parameters of LPC port
		SecurityQos.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
		SecurityQos.ImpersonationLevel = SecurityImpersonation;
		SecurityQos.EffectiveOnly = FALSE;
		SecurityQos.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;

		//
		// Fill local and remote memory view. When the LPC
		// message comes to the listener, the section will be remapped
		// to be accessible to the listener, even if the listener is in another
		// process or different processor mode (UserMode/KernelMode)
		//
	
		ClientView.Length = sizeof(PORT_VIEW);
		ClientView.SectionHandle = SectionHandle;
		ClientView.SectionOffset = 0;
		ClientView.ViewSize = LARGE_MESSAGE_SIZE;
		ServerView.Length = sizeof(REMOTE_PORT_VIEW);

		//
		// Connect to the port
		//
		
		PRINT(_T("Connecting to port \"%s\" (NtConnectPort)...\n"),LpcPortName);
		status = NtConnectPort(&PortHandle,
							   &usPortName,
							   &SecurityQos,
							   &ClientView,
							   &ServerView,
							   0,
							   NULL,
							   NULL);
		
		if (!NT_SUCCESS(status))
		{
			PRINT(_T("NtConnectPort error 0x%08lX\n"),status);
			__leave;
		}

		PRINT(_T("Connect success to %s\n"),LpcPortName);
		ci.ClientView = ClientView;
		ci.ServerView = ServerView;
		ci.ServerHandle = PortHandle;
		
		success = TRUE;
	}
	__finally
	{
		
	}
	
	return success;
}


BOOL AsyncSend(TCHAR *msg)
{
	return Send(msg,LPC_COMMAND_REQUEST_NOREPLY);
}

BOOL SyncSend(TCHAR *msg)
{
	return Send(msg,LPC_COMMAND_REQUEST_REPLY);
}

BOOL Send(TCHAR *msg,ULONG command)
{
	TRANSFERRED_MESSAGE Message;
	NTSTATUS status;
	ULONG MessageLength = sizeof(TRANSFERRED_MESSAGE);
	SIZE_T dataSize = (STRLEN(msg)+1)*sizeof(TCHAR);

	RtlZeroMemory(&Message,MessageLength);
	InitializeMessageHeader(&Message.Header,MessageLength,LPC_NEW_MESSAGE);
	Message.Command = command;
	
	if (dataSize > MAX_MESSAGE_SIZE)
	{
		if (dataSize > LARGE_MESSAGE_SIZE)
			return FALSE;
		//write to section
		Message.UseSection = TRUE;
		STRCOPY(Message.MessageText,_T("Real Message is in the Section!"));
		RtlCopyMemory(ci.ClientView.ViewBase,msg,dataSize);

	}
	else
	{
		//write to buffer of message
		Message.UseSection = FALSE;
		RtlCopyMemory(Message.MessageText,msg,dataSize);
	}

	if (IS_COMMAND_ASYNC(command))
	{
		//
		// Send the data request, do not wait for reply
		//

		/*
		 * Attention!
		 * LPC_REQUEST type will cause STATUS_INVALID_PARAMETER when use NtRequestPort
		 */
		status = NtRequestPort(ci.ServerHandle, &Message.Header);

		if (!NT_SUCCESS(status))
		{
			PRINT(_T("NtRequestPort error 0x%08lX\n"), status);
		}
	}
	else
	{
		//
		// Send the data request, and wait for reply
		//
		TRANSFERRED_MESSAGE ReplyMessage;
		TCHAR *buffer;
		RtlZeroMemory(&ReplyMessage,MessageLength);
		status = NtRequestWaitReplyPort(ci.ServerHandle, &Message.Header,&ReplyMessage.Header);

		if (!NT_SUCCESS(status))
		{
			PRINT(_T("NtRequestPort error 0x%08lX\n"), status);
		}
		else
		{
			buffer = (TCHAR *)MALLOC(sizeof(TCHAR)*LARGE_MESSAGE_SIZE);
			if (ReplyMessage.UseSection)
			{
				PRINT(_T("[Received Large Data]\n"));
				RtlCopyMemory(buffer,ci.ServerView.ViewBase,ci.ServerView.ViewSize);
				PRINT(_T("[%08lX]:%ws\n"),ci.ServerHandle,buffer);
			}
			else
			{
				RtlCopyMemory(buffer,ReplyMessage.MessageText,sizeof(ReplyMessage.MessageText));
				PRINT(_T("[%08lX]:%ws\n"),ci.ServerHandle,buffer);
			}

			FREE(buffer);
		}
	} 

	return NT_SUCCESS(status);
}

#ifndef _KERNEL_MODE
BOOL InitProcAddress()
{
	HMODULE hModule = GetModuleHandle(L"ntdll.dll");
	if (hModule != NULL)
	{
		NtCreatePort = (_CreatePort)GetProcAddress(hModule,"NtCreatePort");
		NtListenPort = (_ListenPort)GetProcAddress(hModule,"NtListenPort");
		NtAcceptConnectPort = (_AcceptConnectPort)GetProcAddress(hModule,"NtAcceptConnectPort");
		NtCompleteConnectPort = (_CompleteConnectPort)GetProcAddress (hModule,"NtCompleteConnectPort");
		NtReplyPort = (_ReplyPort )GetProcAddress(hModule,"NtReplyPort");
		NtReplyWaitReceivePort = (_ReplyWaitReceivePort)GetProcAddress (hModule,"NtReplyWaitReceivePort");
		NtReplyWaitReceivePortEx = (_ReplyWaitReceivePortEx)GetProcAddress(hModule,"NtReplyWaitReceivePortEx");
		RtlInitUnicodeString = (_InitUnicodeString)GetProcAddress(hModule,"RtlInitUnicodeString");
		NtConnectPort = (_ConnectPort)GetProcAddress(hModule,"NtConnectPort");
		ZwCreateSection = (_ZwCreateSection)GetProcAddress(hModule,"ZwCreateSection");
		NtRequestPort = (_RequestPort)GetProcAddress(hModule,"NtRequestPort");
		NtRequestWaitReplyPort = (_RequestWaitReplyPort)GetProcAddress(hModule,"NtRequestWaitReplyPort");

		if (NtCreatePort && NtListenPort && NtAcceptConnectPort && NtCompleteConnectPort && NtReplyPort && NtRequestWaitReplyPort &&
			NtReplyWaitReceivePort && NtReplyWaitReceivePortEx && RtlInitUnicodeString && NtConnectPort && ZwCreateSection && NtRequestPort)
			return TRUE;
	}

	return FALSE;
}

BOOL CheckWOW64()
{
	BOOL isUnderWOW64;
	if (IsWow64Process(GetCurrentProcess(),&isUnderWOW64))
	{
		if (isUnderWOW64)
		{
			PRINT(_T("WARNING: You are running 32-bit version of the application under 64-bit Windows.\n")
				_T("This is not supported and will not work.\n"));
			return TRUE;
		}
	}
	return FALSE;
};
#else
ULONG GetSystemRoutineAddress(int,PVOID);
DWORD GetFunctionAddressBySSDT(DWORD,WCHAR *);

BOOL FindKernelFunction()
{
	NtConnectPort = (_ConnectPort)GetSystemRoutineAddress(0,"NtConnectPort");
	NtCreatePort = (_CreatePort)GetFunctionAddressBySSDT(0,L"NtCreatePort");
	NtListenPort = (_ListenPort)GetFunctionAddressBySSDT(0,L"NtListenPort");
	NtAcceptConnectPort = (_AcceptConnectPort)GetFunctionAddressBySSDT(0,L"NtAcceptConnectPort");
	NtCompleteConnectPort = (_CompleteConnectPort)GetFunctionAddressBySSDT(0,L"NtCompleteConnectPort");
	NtReplyPort = (_ReplyPort)GetFunctionAddressBySSDT(0,L"NtReplyPort");
	NtReplyWaitReceivePort = (_ReplyWaitReceivePort)GetFunctionAddressBySSDT(0,L"NtReplyWaitReceivePort");
	NtReplyWaitReceivePortEx = (_ReplyWaitReceivePortEx)GetFunctionAddressBySSDT(0,L"NtReplyWaitReceivePortEx");
	NtRequestPort = (_RequestPort)GetFunctionAddressBySSDT(0,L"NtRequestPort");
	NtRequestWaitReplyPort = (_RequestWaitReplyPort)GetFunctionAddressBySSDT(0,L"NtRequestWaitReplyPort");

	if (NtCreatePort && NtListenPort && NtAcceptConnectPort && NtCompleteConnectPort && NtReplyPort && NtRequestWaitReplyPort &&
		NtReplyWaitReceivePort && NtReplyWaitReceivePortEx && NtRequestPort && NtRequestWaitReplyPort && NtConnectPort)
		return TRUE;

	return FALSE;
}
#endif

void Control( ULONG command,ULONG method, TCHAR *msg )
{
	SET_COMMAND(command,method);
	Send(msg,command);
}
