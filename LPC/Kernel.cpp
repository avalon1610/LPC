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
#endif