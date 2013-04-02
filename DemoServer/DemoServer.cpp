// DemoServer.cpp : Defines the entry point for the console application.
//

#include "../LPC/LPC.h"
#include <tchar.h>
#include <windows.h>

#pragma comment(lib,"LPC.lib")
#define COMMAND_DOSOMETHING LPC_COMMAND_RESERVE+0x1
void wait()
{
	MSG msg;
	while (GetMessage(&msg,NULL,0,0))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
}

void talk(LPVOID param)
{
	TCHAR *msg = (TCHAR *)param;
	MessageBox(NULL,msg,NULL,NULL);
}

int _tmain(int argc, _TCHAR* argv[])
{
	CLPC lpcServer;
	lpcServer.CallBackList[COMMAND_DOSOMETHING] = talk;
	lpcServer.runServer();
	wait();
	return 0;
}

