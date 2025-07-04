.intel_syntax noprefix
.data
currentHash:    .long   0
returnAddress:  .quad   0
syscallNumber:  .long   0
syscallAddress: .quad   0

.text
.global UtSetInformationFile
.global UtSetInformationProcess
.global UtCreateFile
.global UtWriteFile
.global UtReadFile
.global UtDeleteFile
.global UtClose
.global UtOpenFile
.global UtResumeThread
.global UtGetContextThread
.global UtSetContextThread
.global UtAllocateVirtualMemory
.global UtWriteVirtualMemory
.global UtFreeVirtualMemory
.global UtDelayExecution
.global UtOpenProcess
.global UtCreateUserProcess
.global UtOpenProcessToken
.global UtWaitForSingleObject
.global UtQueryAttributesFile
.global UtQueryInformationFile
.global UtCreateMutant
.global UtAdjustPrivilegesToken
.global UtQuerySystemInformation
.global UtQueryInformationToken
.global UtOpenKey
.global UtCreateKey
.global UtEnumerateKey
.global UtQueryValueKey
.global UtRenameKey
.global UtTerminateProcess
.global UtProtectVirtualMemory
.global UtSetValueKey

.global WhisperMain
.extern SWU_GetSyscallNumber
.extern SWU_GetRandomSyscallAddress
    
WhisperMain:
    pop rax
    mov [rsp+ 8], rcx                           # Save registers.
    mov [rsp+16], rdx
    mov [rsp+24], r8
    mov [rsp+32], r9
    sub rsp, 0x28
    mov ecx, dword ptr [currentHash + RIP]
    call SWU_GetSyscallNumber
    mov dword ptr [syscallNumber + RIP], eax    # Save the syscall number
    xor rcx, rcx
    call SWU_GetRandomSyscallAddress            # Get a random syscall address
    mov qword ptr [syscallAddress + RIP], rax   # Save the random syscall address
    xor rax, rax
    mov eax, dword ptr [syscallNumber + RIP]    # Restore the syscall vallue
    add rsp, 0x28
    mov rcx, [rsp+ 8]                           # Restore registers.
    mov rdx, [rsp+16]
    mov r8, [rsp+24]
    mov r9, [rsp+32]
    mov r10, rcx
    pop qword ptr [returnAddress + RIP]         # Save the original return address
    call qword ptr [syscallAddress + RIP]       # Issue syscall
    push qword ptr [returnAddress + RIP]        # Restore the original return address
    ret

UtSetInformationFile:
    mov dword ptr [currentHash + RIP], 0x0800B320B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


UtSetInformationProcess:
    mov dword ptr [currentHash + RIP], 0x094E96583   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


UtCreateFile:
    mov dword ptr [currentHash + RIP], 0x079A9568A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


UtWriteFile:
    mov dword ptr [currentHash + RIP], 0x02374A3B6   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


UtReadFile:
    mov dword ptr [currentHash + RIP], 0x034A1FAF1   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


UtDeleteFile:
    mov dword ptr [currentHash + RIP], 0x08E6D73F9   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


UtClose:
    mov dword ptr [currentHash + RIP], 0x0BD896B03   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


UtOpenFile:
    mov dword ptr [currentHash + RIP], 0x0D9E7EF44   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


UtResumeThread:
    mov dword ptr [currentHash + RIP], 0x0C0825EFF   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


UtGetContextThread:
    mov dword ptr [currentHash + RIP], 0x0A7A60468   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


UtSetContextThread:
    mov dword ptr [currentHash + RIP], 0x00672CFC6   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


UtAllocateVirtualMemory:
    mov dword ptr [currentHash + RIP], 0x027E0DB9A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


UtWriteVirtualMemory:
    mov dword ptr [currentHash + RIP], 0x082069185   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


UtFreeVirtualMemory:
    mov dword ptr [currentHash + RIP], 0x0AB115B6D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


UtDelayExecution:
    mov dword ptr [currentHash + RIP], 0x07E1C4917   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


UtOpenProcess:
    mov dword ptr [currentHash + RIP], 0x0AC35F9E2   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


UtCreateUserProcess:
    mov dword ptr [currentHash + RIP], 0x04C09C67A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


UtOpenProcessToken:
    mov dword ptr [currentHash + RIP], 0x099068A8A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


UtWaitForSingleObject:
    mov dword ptr [currentHash + RIP], 0x04981D00A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


UtQueryAttributesFile:
    mov dword ptr [currentHash + RIP], 0x00BADD99B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


UtQueryInformationFile:
    mov dword ptr [currentHash + RIP], 0x02E2BF65C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


UtCreateMutant:
    mov dword ptr [currentHash + RIP], 0x03BEE4B0B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


UtAdjustPrivilegesToken:
    mov dword ptr [currentHash + RIP], 0x0EF5F7370   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


UtQuerySystemInformation:
    mov dword ptr [currentHash + RIP], 0x02633B413   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


UtQueryInformationToken:
    mov dword ptr [currentHash + RIP], 0x082652FB9   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


UtOpenKey:
    mov dword ptr [currentHash + RIP], 0x0FE049D0E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


UtCreateKey:
    mov dword ptr [currentHash + RIP], 0x0AD16F1FF   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


UtEnumerateKey:
    mov dword ptr [currentHash + RIP], 0x0161DA515   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


UtQueryValueKey:
    mov dword ptr [currentHash + RIP], 0x03AC7422D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


UtRenameKey:
    mov dword ptr [currentHash + RIP], 0x04C3D038B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


UtTerminateProcess:
    mov dword ptr [currentHash + RIP], 0x04DCE8273   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


UtProtectVirtualMemory:
    mov dword ptr [currentHash + RIP], 0x0C57512DB   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


UtSetValueKey:
    mov dword ptr [currentHash + RIP], 0x02828259E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


