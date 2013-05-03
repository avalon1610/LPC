#ifdef _KERNEL_MODE
#include "KernelModeDefs.h"

__inline ULONG CR4()
{
	// mov eax,cr4
	__asm _emit 0x0F __asm _emit 0x20 __asm _emit 0xE0
}

VALIDITY_CHECK_STATUS MmIsAddressValidExPae(IN PVOID Pointer)
{
	VALIDITY_CHECK_STATUS Return = VCS_INVALID;
	MMPTE_PAE *Pde;
	MMPTE_PAE *Pte;
	MMPTE_PAE pte;

	Pde = MiGetPdeAddressPae(Pointer);
	if (Pde->u.Hard.Valid)
	{
		if (Pde->u.Hard.LargePage != 0)
		{
			Pte = Pde;
		}
		else
		{
			Pte = MiGetPteAddressPae(Pointer);
		}
		if (Pte->u.Hard.Valid)
		{
			Return = VCS_VALID;
		}
		else
		{
			//
			// PTE is not valid
			//
			pte = *Pte;
			if (pte.u.Long.LowPart == 0)
			{
				//PTE entry is completely invalid (page is not committed or is within VAD tree)
			}
			else
			{
				if (pte.u.Soft.Prototype == 1)
				{
					// more accurate check should be performed here for pointed prototype PTE!
					Return = VCS_PROTOTYPE;
				}
				else // not a prototype PTE
				{
					if (pte.u.Soft.Transition != 0)
					{
						//
						// This is a transition page.
						//
						Return = VCS_TRANSITION;
					}
					else if (pte.u.Soft.PageFileHigh == 0)
					{
						//
						// Demand zero page
						//
						Return = VCS_DEMANDZERO;
					}
					else
					{
						//
						// Pagefile PTE
						//
						if (pte.u.Soft.Transition == 0)
						{
							Return = VCS_PAGEDOUT;
						}
						else
						{
							// PTE entry is not valid, Refault
						}
					}
				}
			}
		}
	}
	else
	{
		// PDE entry is not valid
	}

	return Return;
}

VALIDITY_CHECK_STATUS MmIsAddressValidExNotPae(IN PVOID Pointer)
{
	VALIDITY_CHECK_STATUS Return = VCS_INVALID;
	MMPTE* Pde;
	MMPTE* Pte;
	MMPTE pte;

	Pde = MiGetPdeAddress(Pointer);

	if( Pde->u.Hard.Valid )
	{
		Pte = MiGetPteAddress(Pointer);

		if( Pte->u.Hard.Valid )
		{
			Return = VCS_VALID;
		}
		else
		{
			//
			// PTE is not valid
			//

			pte = *Pte;

			if( pte.u.Long )
			{
				if( pte.u.Soft.Prototype == 1 )
				{
					// PTE entry is not valid, points to prototype PTE.

					// more accurate check should be performed here for pointed prototype PTE!

					Return = VCS_PROTOTYPE;
				}
				else  // not a prototype PTE
				{
					if( pte.u.Soft.Transition != 0 )
					{
						//
						// This is a transition page. Consider it invalid.
						//

						// PTE entry is not valid, points to transition page

						Return = VCS_TRANSITION;
					}
					else if (pte.u.Soft.PageFileHigh == 0)
					{
						//
						// Demand zero page
						//

						Return = VCS_DEMANDZERO;
					}
					else
					{
						//
						// Pagefile PTE
						//

						if( pte.u.Soft.Transition == 0 )
						{
							Return = VCS_PAGEDOUT;
						}
						else
						{
							//PTE entry is not valid, Refault
						}
					}
				}
			}
			else
			{
				//PTE entry is completely invalid
			}
		}
	}
	else
	{
		// PDE entry is not valid
	}

	return Return;
}

VALIDITY_CHECK_STATUS MiIsAddressValidEx(IN PVOID Pointer)
{
	if (CR4() & PAE_ON)
	{
		return MmIsAddressValidExPae(Pointer);
	}
	else
	{
		return MmIsAddressValidExNotPae(Pointer);
	}
}

BOOL MmIsAddressValidEx(IN PVOID Pointer)
{
	VALIDITY_CHECK_STATUS MmRet;
	ULONG ulTry;

	if (ARGUMENT_PRESENT(Pointer) || !Pointer)
	{
		return FALSE;
	}

	MmRet = MiIsAddressValidEx(Pointer);
	if (MmRet != VCS_VALID)
	{
		return FALSE;
	}
	return TRUE;
}

ULONG GetSystemRoutineAddress(int IntType,PVOID lpwzFunction)
{
	ULONG ulFunction;
	UNICODE_STRING UnicodeFunctionString;
	ANSI_STRING AnsiFunctionString;
	int index;
	__try
	{
		if (IntType == 1)
		{
			RtlInitUnicodeString(&UnicodeFunctionString,(PCWSTR)lpwzFunction);
		}
		else if (IntType == 0)
		{
			RtlInitAnsiString(&AnsiFunctionString,(PCSZ)lpwzFunction);
			RtlAnsiStringToUnicodeString(&UnicodeFunctionString,&AnsiFunctionString,TRUE);
		}
		else
		{
			return FALSE;
		}
		ulFunction = (ULONG)MmGetSystemRoutineAddress(&UnicodeFunctionString);
		if (IntType == 0)
		{
			RtlFreeUnicodeString(&UnicodeFunctionString);
		}
		if (MmIsAddressValidEx((PVOID)ulFunction))
		{
			if (IntType == 0)
			{
				if (*((char *)lpwzFunction) == 'Z' && *((char *)lpwzFunction+1) == 'w')
				{
					index = *(DWORD *)(ulFunction+1);
					if (index <= (int)KeServiceDescriptorTable->TableSize)
					{
						ulFunction = KeServiceDescriptorTable->ServiceTable[index];
					}
				}
			}
			if (IntType == 1)
			{
				if (*((WCHAR *)lpwzFunction) == 'Z' && *((WCHAR *)lpwzFunction+1) == 'w')
				{
					index = *(DWORD *)(ulFunction+1);
					if (index <= (int)KeServiceDescriptorTable->TableSize)
					{
						ulFunction = KeServiceDescriptorTable->ServiceTable[index];
					}
				}
			}
			if (MmIsAddressValidEx((PVOID)ulFunction))
			{
				return ulFunction;
			}
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{

	}
	return ulFunction;
}

#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )  
#define ZwCurrentProcess() NtCurrentProcess()      

HANDLE MapFileAsSection(PUNICODE_STRING FileName,PVOID *ModuleBase)
{
	NTSTATUS status;
	HANDLE  hSection, hFile;
	DWORD dwKSDT;
	PVOID BaseAddress = NULL;
	SIZE_T size=0;
	IO_STATUS_BLOCK iosb;
	OBJECT_ATTRIBUTES oa = {sizeof oa, 0, FileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE};
	BOOL bInit = FALSE;

	*ModuleBase = NULL;
	status = ZwOpenFile(&hFile,
						FILE_EXECUTE | SYNCHRONIZE,
						&oa,
						&iosb,
						FILE_SHARE_READ,
						FILE_SYNCHRONOUS_IO_NONALERT);

	if (!NT_SUCCESS(status))
	{
		KdPrint(("ZwOpenFile failed\n"));
		return NULL;
	}

	oa.ObjectName = 0;
	status = ZwCreateSection(&hSection,
							 SECTION_ALL_ACCESS,
							 &oa,
							 0,
							 PAGE_EXECUTE,
							 SEC_IMAGE,
							 hFile);
	if (!NT_SUCCESS(status))
	{
		ZwClose(hFile);
		KdPrint(("ZwCreateSection failed:%d\n",RtlNtStatusToDosError(status)));
		return NULL;
	}

	status = ZwMapViewOfSection(hSection,
								NtCurrentProcess(),
								&BaseAddress,
								0,
								1000,
								0,
								&size,
								(SECTION_INHERIT)1,
								MEM_TOP_DOWN,
								PAGE_READWRITE);
	if (!NT_SUCCESS(status))
	{
		ZwClose(hFile);
		ZwClose(hSection);
		KdPrint(("ZwMapViewOfSection failed:%d\n",RtlNtStatusToDosError(status)));
		return NULL;
	}
	ZwClose(hFile);
	__try
	{
		*ModuleBase = BaseAddress;
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		return NULL;
	}
	return hSection;
}

BOOL GetFunctionIndexByName(CHAR *lpszFunctionName,int *Index)
{
	UNICODE_STRING wsNtDllString;

	HANDLE hNtSection;
	ULONG ulNtDllModuleBase;
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS NtDllHeader;

	IMAGE_OPTIONAL_HEADER opthdr;
	DWORD *arrayOfFunctionAddresses;
	DWORD *arrayOfFunctionNames;
	WORD *arrayOfFunctionOrdinals;
	DWORD functionOrdinal;
	DWORD Base, x, functionAddress,position;
	char* functionName;
	IMAGE_EXPORT_DIRECTORY *pExportTable;
	BOOL bRetOK = FALSE;
	BOOL bInit = FALSE;

	STRING lpszSearchFunction;
	STRING lpszFunction;

	__try
	{
		RtlInitUnicodeString(&wsNtDllString,L"\\SystemRoot\\System32\\ntdll.dll");
		hNtSection = MapFileAsSection(&wsNtDllString,(PVOID *)&ulNtDllModuleBase);
		if (!hNtSection)
			return bRetOK;
		ZwClose(hNtSection);

		pDosHeader = (PIMAGE_DOS_HEADER)ulNtDllModuleBase;
		if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		{
			KdPrint(("failed to find NtHeader\r\n"));
			return bRetOK;
		}

		NtDllHeader = (PIMAGE_NT_HEADERS)(ULONG)((ULONG)pDosHeader+pDosHeader->e_lfanew);
		if (NtDllHeader->Signature != IMAGE_NT_SIGNATURE)
		{
			KdPrint(("failed to find NtHeader\r\n"));
			return bRetOK;
		}

		opthdr = NtDllHeader->OptionalHeader;
		pExportTable = (IMAGE_EXPORT_DIRECTORY *)((BYTE*)ulNtDllModuleBase+opthdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
		arrayOfFunctionAddresses = (DWORD*)((BYTE*)ulNtDllModuleBase+pExportTable->AddressOfFunctions);
		arrayOfFunctionNames = (DWORD*)((BYTE*)ulNtDllModuleBase+pExportTable->AddressOfNames);
		arrayOfFunctionOrdinals = (WORD*)((BYTE*)ulNtDllModuleBase+pExportTable->AddressOfNameOrdinals);
	
		Base = pExportTable->Base;
		for (x = 0; x < pExportTable->NumberOfFunctions; x++)
		{
			functionName = (char *)((BYTE*)ulNtDllModuleBase + arrayOfFunctionNames[x]);
			functionOrdinal = arrayOfFunctionOrdinals[x] + Base - 1;
			functionAddress = (DWORD)((BYTE*)ulNtDllModuleBase + arrayOfFunctionAddresses[functionOrdinal]);
			position = *((WORD*)(functionAddress + 1));

			RtlInitString(&lpszSearchFunction,functionName);
			RtlInitString(&lpszFunction,lpszFunctionName);
			if (RtlCompareString(&lpszSearchFunction,&lpszFunction,TRUE) == 0)
			{
				KdPrint(("Find FunctionName:%s\r\nposition:%d\r\n",functionName,position));
				*Index = position;
				bRetOK = TRUE;
				break;
			}
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{

	}
	return bRetOK;
}

DWORD GetFunctionAddressBySSDT(DWORD index,WCHAR *zwFunctionName)
{
	UNICODE_STRING UnicodeFunctionName;
	ANSI_STRING AnsiFunction;
	char lpszFunction[128];

	RtlInitUnicodeString(&UnicodeFunctionName,zwFunctionName);
	RtlUnicodeStringToAnsiString(&AnsiFunction,&UnicodeFunctionName,TRUE);
	RtlZeroMemory(lpszFunction,sizeof(lpszFunction));

	strncpy(lpszFunction,AnsiFunction.Buffer,AnsiFunction.Length);
	KdPrint(("Get Function Index By Name:%s\n",lpszFunction));
	if (!GetFunctionIndexByName(lpszFunction,(int *)&index))
	{
		KdPrint(("Get Function Index By Name failed:%s\n",lpszFunction));
		RtlFreeAnsiString(&AnsiFunction);
		return NULL;
	}
	RtlFreeAnsiString(&AnsiFunction);
	if (index <= KeServiceDescriptorTable->TableSize)
	{
		KdPrint(("index:%x %x %ws\n",index,KeServiceDescriptorTable->TableSize,zwFunctionName));
		return KeServiceDescriptorTable->ServiceTable[index];
	}
	return NULL;
}
#endif