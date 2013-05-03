#include "ntifs.h"
#include "..\LPC\LPC.h"


NTSTATUS DefaultDispatch(PDEVICE_OBJECT DeviceObject,PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	NTSTATUS status = STATUS_SUCCESS;
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
	KdPrint((msg));
}


void DriverUnload(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	CLPC::StopServer();
	KdPrint(("LPCTest Unloaded!\n"));
}

extern "C" 
NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject,IN PUNICODE_STRING RegPath)
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegPath);

	for (int i = 0;i < IRP_MJ_MAXIMUM_FUNCTION;i++)
		DriverObject->MajorFunction[i] = DefaultDispatch;
	DriverObject->DriverUnload = DriverUnload;  

	CLPC lpcServer;
	lpcServer.InsertCallBack(COMMAND_DOSOMETHING,talk);
	lpcServer.runServer();

	return STATUS_SUCCESS;
}