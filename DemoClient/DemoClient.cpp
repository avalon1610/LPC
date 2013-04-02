#include "../LPC/LPC.h"
#include <tchar.h>
#include <windows.h>
#include <iostream>

#pragma comment(lib,"LPC.lib")
using namespace std;

void wait()
{
	MSG msg;
	while (GetMessage(&msg,NULL,0,0))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
}

#define COMMAND_DOSOMETHING LPC_COMMAND_RESERVE+0x1
int _tmain(int argc, _TCHAR* argv[])
{

	CLPC lpcClient;
	lpcClient.Connect(SERVERNAME_W);
	TCHAR msg[LARGE_MESSAGE_SIZE] = {0};
	while(true)
	{
		wcin >> msg;
		//lpcClient.SyncSend(msg);
		lpcClient.Control(COMMAND_DOSOMETHING,SYNC,msg);
	}
	wait();
	return 0;
}
