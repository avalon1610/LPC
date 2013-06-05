#include "ntifs.h"
#include "..\LPC\LPC.h"


NTSTATUS DefaultDispatch(PDEVICE_OBJECT DeviceObject,PIRP Irp)
{
	NTSTATUS status = STATUS_SUCCESS;
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp,IO_NO_INCREMENT);
	return status;
}

#define COMMAND_DOSOMETHING LPC_COMMAND_RESERVE+0x1

void talk(PVOID param)
{
	TCHAR *msg;
	msg = (TCHAR *)param;
	KdPrint(("callback message:%ws\n",msg));
	PsTerminateSystemThread(STATUS_SUCCESS);
}


void DriverUnload(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	StopServer((TCHAR *)SERVERNAME_W);
	KdPrint(("LPCTest Unloaded!\n"));
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject,IN PUNICODE_STRING RegPath)
{
	ULONG i;
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegPath);

	for (i = 0;i < IRP_MJ_MAXIMUM_FUNCTION;i++)
		DriverObject->MajorFunction[i] = DefaultDispatch;
	DriverObject->DriverUnload = DriverUnload;  

	runServer((TCHAR *)SERVERNAME_W);
	InsertCallBack(COMMAND_DOSOMETHING,talk);

	return STATUS_SUCCESS;
}