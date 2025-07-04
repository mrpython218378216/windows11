#include "syscalls.h"

/* SysWhispersU is a custom version made by Unam Sanctam https://github.com/UnamSanctam */

//Code below is adapted from @modexpblog. Read linked article for more details.
//https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams

SWU_SYSCALL_LIST SWU_SyscallList = { 0, NULL };

#ifdef RANDSYSCALL
uintptr_t ntdllBase = 0;
#endif

__declspec(noinline) uint32_t SWU_DecodeConstant(uint32_t constant) {
	return constant + SWU_SEED;
}

#define SWU_OBFCONST(x) SWU_DecodeConstant(x - SWU_SEED)

ULONGLONG SWU_GetPEB() {
	ULONGLONG pebAddress;
#ifdef _WIN64
    ULONGLONG pebOffset = SWU_OBFCONST(0x60);
    asm ("movq %%gs:(%1), %0"
         : "=r"(pebAddress)
         : "r"(pebOffset)
         : "memory"
    );
#else
	ULONGLONG pebOffset = SWU_OBFCONST(0x30);
    asm volatile (
        "movl %1, %%eax\n"
        "addl %%fs:(%%eax), %%eax\n"
        "movl %%eax, %0\n"
        : "=r"(pebAddress)
        : "r"(pebOffset)
        : "eax", "memory"
    );
#endif
    return pebAddress;
}


BOOL SWU_PopulateSyscallList(void)
{
    //Return early if the list is already populated.
    if (SWU_SyscallList.Count) return TRUE;

    PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
    PVOID DllBase = NULL;

    //Get the DllBase address of NTDLL.dll. NTDLL is not guaranteed to be the second
    //in the list, so it's safer to loop through the full list and find it.
	#define Peb ((PSWU_PEB)SWU_GetPEB())
    #define Ldr ((PSWU_PEB_LDR_DATA)Peb->Ldr)
    PSWU_LDR_DATA_TABLE_ENTRY LdrEntry;
    for (LdrEntry = (PSWU_LDR_DATA_TABLE_ENTRY)Ldr->Reserved2[1]; LdrEntry->DllBase != NULL; LdrEntry = (PSWU_LDR_DATA_TABLE_ENTRY)LdrEntry->Reserved1[0])
    {
        DllBase = LdrEntry->DllBase;
        #define DosHeader (PIMAGE_DOS_HEADER)DllBase
        #define NtHeaders ((PIMAGE_NT_HEADERS)((ULONG_PTR)DosHeader + *(PULONG)((ULONG_PTR)DosHeader + SWU_OBFCONST(0x3C))))
        #define DataDirectory ((PIMAGE_DATA_DIRECTORY)NtHeaders->OptionalHeader.DataDirectory)
        DWORD VirtualAddress = DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (VirtualAddress == 0) continue;

        ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)SWU_RVA2VA(ULONG_PTR, DllBase, VirtualAddress);

        //If this is NTDLL.dll, exit loop.
        #define DllName SWU_RVA2VA(PCHAR, DllBase, ExportDirectory->Name)
        if (*(uint32_t*)DllName == SWU_OBFCONST(0x6c64746e) && *(uint32_t*)(DllName + SWU_OBFCONST(4)) == SWU_OBFCONST(0x6c642e6c)) break;
    }

    if (!ExportDirectory) return FALSE;
    
#ifdef RANDSYSCALL
	ntdllBase = (uintptr_t)DllBase;
#endif

	#define EXPORT_FUNCTIONS (SWU_RVA2VA(PDWORD, DllBase, *(PULONG)((ULONG_PTR)ExportDirectory + SWU_OBFCONST(0x1C))))
	#define EXPORT_NAMES (SWU_RVA2VA(PDWORD, DllBase, *(PULONG)((ULONG_PTR)ExportDirectory + SWU_OBFCONST(0x20))))
	#define EXPORT_ORDINALS (SWU_RVA2VA(PWORD, DllBase, *(PULONG)((ULONG_PTR)ExportDirectory + SWU_OBFCONST(0x24))))
	#define ENTRIES SWU_SyscallList.Entries
	
	ENTRIES = (PSWU_SYSCALL_ENTRY)malloc(SWU_OBFCONST(SWU_MAX_ENTRIES) * sizeof(SWU_SYSCALL_ENTRY));
	
	DWORD j = 0;
	for (DWORD i = 0; i < ExportDirectory->NumberOfNames && j < SWU_OBFCONST(SWU_MAX_ENTRIES); i++) {
		//Check if it's a system call.
		PCHAR funcName = SWU_RVA2VA(PCHAR, DllBase, EXPORT_NAMES[i]);
		if (*(USHORT*)funcName != SWU_OBFCONST(0x775a)) continue;

		//Hash the function name
		DWORD Hash = SWU_SEED;
		for (DWORD i = 0; funcName[i]; i++)
		{
			Hash = (Hash + *(WORD*)((ULONG64)funcName + i) + SWU_ROR8(Hash)) & SWU_OBFCONST(0xFFFFFFFF);
		}
		
		ENTRIES[j].Hash = Hash;
		ENTRIES[j].Address = EXPORT_FUNCTIONS[EXPORT_ORDINALS[i]];

		//Sort the list by address in ascending order.
		for (DWORD k = j; k > 0 && ENTRIES[k].Address < ENTRIES[k-1].Address; k--) {
			SWU_SYSCALL_ENTRY TempEntry = ENTRIES[k];
			ENTRIES[k] = ENTRIES[k-1];
			ENTRIES[k-1] = TempEntry;
		}
		j++;
	}

	//Store the total amount of system calls found.
	SWU_SyscallList.Count = j;

    return TRUE;
}

EXTERN_C DWORD SWU_GetSyscallNumber(DWORD FunctionHash)
{
    //Ensure SWU_SyscallList is populated.
    if (!SWU_PopulateSyscallList()) return -1;

    for (DWORD i = 0; i < SWU_SyscallList.Count; i++)
    {
        if (FunctionHash == SWU_SyscallList.Entries[i].Hash)
        {
            return i;
        }
    }

    return -1;
}

#ifdef RANDSYSCALL
unsigned int callCount = 0;
int syscallOffset = -1;
#ifdef _WIN64
EXTERN_C uint64_t SWU_GetRandomSyscallAddress(void)
#else
EXTERN_C DWORD SWU_GetRandomSyscallAddress(int callType)
#endif
{
#ifdef _WIN64
    #define instructValue SWU_OBFCONST(0x0F)
	#define instructValue2 SWU_OBFCONST(0x05)
#else
	#define instructOffset SWU_OBFCONST(0x05)
	#define instructValue (callType == SWU_OBFCONST(1) ? SWU_OBFCONST(0x0BA) : SWU_OBFCONST(0x0E8))
#endif
    uint32_t seed = (uint32_t)SWU_SEED + (uintptr_t)&seed + (uint32_t)callCount++;
	
	if (syscallOffset == -1) {
		for(int i = 0; i < SWU_OBFCONST(64); i++) {
			if (*(unsigned char*)(ntdllBase + SWU_SyscallList.Entries[0].Address + i) == instructValue && *(unsigned char*)(ntdllBase + SWU_SyscallList.Entries[0].Address + i + SWU_OBFCONST(1)) == instructValue2) {
				syscallOffset = i;
				break;
			}
		}
	}
	
    do
	{
		int randNum = ((SWU_OBFCONST(1664525) * (seed++) + SWU_OBFCONST(1013904223)) % (SWU_SyscallList.Count - 1));
		if (*(unsigned char*)(ntdllBase + SWU_SyscallList.Entries[randNum].Address + syscallOffset) == instructValue && *(unsigned char*)(ntdllBase + SWU_SyscallList.Entries[randNum].Address + syscallOffset + SWU_OBFCONST(1)) == instructValue2)
			return (ntdllBase + SWU_SyscallList.Entries[randNum].Address + syscallOffset);
	} while(1);
}
#endif