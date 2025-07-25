#include <windows.h>
#include <iostream>
#include "peb_lookup.h"
#include "peloader.h"

#define RELOC_32BIT_FIELD 3
#define RELOC_64BIT_FIELD 0xA

#ifdef _WIN64
#define RELOC_FIELD RELOC_64BIT_FIELD
typedef ULONG_PTR FIELD_PTR;
#else
#define RELOC_FIELD RELOC_32BIT_FIELD
typedef  DWORD_PTR FIELD_PTR;
#endif

typedef struct _BASE_RELOCATION_ENTRY {
    WORD Offset: 12;
    WORD Type: 4;
} BASE_RELOCATION_ENTRY;

#define CRC_kernel32 0x6AE69F02
#define CRC_GetProcAddress 0xC97C1FFF
#define CRC_LoadLibraryA 0x3FC1BD8D

typedef struct {
    decltype(&LoadLibraryA) _LoadLibraryA;
    decltype(&GetProcAddress) _GetProcAddress;
} t_mini_iat;


bool init_iat(t_mini_iat &iat) {
    LPVOID base = get_module_by_checksum(CRC_kernel32);
    if (!base) {
        return false;
    }

    LPVOID load_lib = get_func_by_checksum((HMODULE) base, CRC_LoadLibraryA);
    if (!load_lib) {
        return false;
    }
    LPVOID get_proc = get_func_by_checksum((HMODULE) base, CRC_GetProcAddress);
    if (!get_proc) {
        return false;
    }

    iat._LoadLibraryA = reinterpret_cast<decltype(&LoadLibraryA)>(load_lib);
    iat._GetProcAddress = reinterpret_cast<decltype(&GetProcAddress)>(get_proc);
    return true;
}

bool relocate(IMAGE_DATA_DIRECTORY &relocationsDirectory, BYTE *image, FIELD_PTR oldBase) {
    PIMAGE_BASE_RELOCATION ProcessBReloc = (PIMAGE_BASE_RELOCATION) (relocationsDirectory.VirtualAddress +
                                                                     (FIELD_PTR) image);
    // apply relocations:
    while (ProcessBReloc->VirtualAddress != 0) {
        const DWORD page = ProcessBReloc->VirtualAddress;
        if (ProcessBReloc->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)) {
            continue;
        }
        size_t count = (ProcessBReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        BASE_RELOCATION_ENTRY *list = (BASE_RELOCATION_ENTRY *) (LPWORD) (ProcessBReloc + 1);
        for (size_t i = 0; i < count; i++) {
            if (list[i].Type == 0) break;
            if (list[i].Type != RELOC_FIELD) {
                return false;
            }
            DWORD rva = list[i].Offset + page;
            PULONG_PTR p = (PULONG_PTR) ((LPBYTE) image + rva);
            //relocate the address
            *p = ((*p) - oldBase) + (FIELD_PTR) image;
        }
        ProcessBReloc = (PIMAGE_BASE_RELOCATION) ((LPBYTE) ProcessBReloc + ProcessBReloc->SizeOfBlock);
    }
    return true;
}

bool load_imports(t_mini_iat iat, IMAGE_DATA_DIRECTORY importsDirectory, BYTE *image) {
    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR) (importsDirectory.VirtualAddress +
                                                                            (FIELD_PTR) image);

    while (importDescriptor->Name != NULL) {
        LPCSTR libraryName = (LPCSTR) ((ULONG_PTR) importDescriptor->Name + (ULONG_PTR) image);
        HMODULE library = iat._LoadLibraryA(libraryName);
        if (!library) return false;

        PIMAGE_THUNK_DATA thunk = NULL;
        thunk = (PIMAGE_THUNK_DATA) ((FIELD_PTR) image + importDescriptor->FirstThunk);

        while (thunk->u1.AddressOfData != NULL) {
            FIELD_PTR functionAddress = NULL;
            LPCSTR functionName = NULL;
            if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal)) {
                functionName = (LPCSTR) IMAGE_ORDINAL(thunk->u1.Ordinal);
            } else {
                PIMAGE_IMPORT_BY_NAME functionByName = (PIMAGE_IMPORT_BY_NAME) ((FIELD_PTR) image +
                                                                                thunk->u1.AddressOfData);
                functionName = functionByName->Name;
            }
            if (!functionName) return false;

            functionAddress = (FIELD_PTR) iat._GetProcAddress(library, functionName);
            if (!functionAddress) return false;

            thunk->u1.Function = functionAddress;
            ++thunk;
        }
        importDescriptor++;
    }
    return (importDescriptor != nullptr);
}

bool run_tls_callbacks(IMAGE_DATA_DIRECTORY &tlsDir, BYTE *image, void *tls_callbacks[]) {
    PIMAGE_TLS_DIRECTORY tls_dir = (PIMAGE_TLS_DIRECTORY) (tlsDir.VirtualAddress + (FIELD_PTR) image);
    std::cout << tls_dir->AddressOfIndex << std::endl;
    FIELD_PTR *callbacks_ptr = (FIELD_PTR *) tls_dir->AddressOfCallBacks; // this is VA...
    if (!callbacks_ptr) return true;
    int i = 0;
    while (callbacks_ptr != nullptr) {
        FIELD_PTR callback_va = *callbacks_ptr;
        if (!callback_va) break;

        void (NTAPI *callback_func)(PVOID DllHandle, DWORD dwReason, PVOID)
        = (void (NTAPI *)(PVOID, DWORD, PVOID)) callback_va;
        tls_callbacks[i] = reinterpret_cast<void *>(callback_va);
        callback_func(image, DLL_PROCESS_ATTACH, NULL);
        callback_func(image, DLL_THREAD_ATTACH, NULL);

        callbacks_ptr++;
        i++;
    }
    return true;
}

int __stdcall pe2shc_entry(void *module_base,void *tls_callbacks[]) {
    t_mini_iat iat;
    if (!init_iat(iat)) {
        return (-1);
    }
    IMAGE_DOS_HEADER *mz = (IMAGE_DOS_HEADER *) module_base;
    if (mz->e_magic != IMAGE_DOS_SIGNATURE) {
        return (-2);
    }
    IMAGE_NT_HEADERS *pe = (IMAGE_NT_HEADERS *) (mz->e_lfanew + (ULONG_PTR) module_base);
    if (pe->Signature != IMAGE_NT_SIGNATURE) {
        return (-2);
    }

    min_hdr_t *my_hdr = (min_hdr_t *) module_base;
    if (my_hdr->load_status == LDS_RUN) {
        // do not allow to run again:
        return ERROR_ALREADY_INITIALIZED;
    }
    if (my_hdr->load_status == LDS_ATTACHED) {
        if ((pe->FileHeader.Characteristics & IMAGE_FILE_DLL) == 0) {
            // not a DLL, this should not happed:
            return ERROR_ALREADY_INITIALIZED;
        }
        DWORD ep_rva = pe->OptionalHeader.AddressOfEntryPoint;
        ULONG_PTR ep_va = (ULONG_PTR) module_base + ep_rva;
        BOOL (WINAPI *my_DllMain)(HINSTANCE, DWORD, LPVOID)
        = (BOOL(WINAPI *)(HINSTANCE, DWORD, LPVOID)) ep_va;
        BOOL is_ok = my_DllMain((HINSTANCE) module_base, DLL_PROCESS_DETACH, 0);
        if (is_ok) {
            // no longer attached:
            my_hdr->load_status = LDS_RUN;
        }
        return is_ok;
    }
    if (my_hdr->load_status == LDS_CLEAN) {
        IMAGE_DATA_DIRECTORY &relocDir = pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (!relocDir.VirtualAddress) {
            return (-3);
        }
        const ULONG_PTR oldBase = pe->OptionalHeader.ImageBase;
        if (!relocate(relocDir, (BYTE *) module_base, oldBase)) {
            return (-4);
        }
        IMAGE_DATA_DIRECTORY &importDir = pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (importDir.VirtualAddress) {
            if (!load_imports(iat, importDir, (BYTE *) module_base)) {
                return (-5);
            }
        }
        IMAGE_DATA_DIRECTORY &tlsDir = pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
        if (tlsDir.VirtualAddress) {
            std::cout << "Starting call tls" << std::endl;
            run_tls_callbacks(tlsDir, (BYTE *) module_base,tls_callbacks);
            std::cout << "Finish tls" << std::endl;
        }
    }
    my_hdr->load_status = LDS_LOADED;

    DWORD ep_rva = pe->OptionalHeader.AddressOfEntryPoint;
    ULONG_PTR ep_va = (ULONG_PTR) module_base + ep_rva;
    BOOL is_ok = FALSE;

    my_hdr->load_status = LDS_RUN;
    if (pe->FileHeader.Characteristics & IMAGE_FILE_DLL) {
        BOOL (WINAPI *my_DllMain)(HINSTANCE, DWORD, LPVOID)
        = (BOOL(WINAPI *)(HINSTANCE, DWORD, LPVOID)) ep_va;
        std::cout << "Calling DllMain" << std::endl;
        is_ok = my_DllMain((HINSTANCE) module_base, DLL_PROCESS_ATTACH, 0);
        std::cout << "Called DllMain" << std::endl;
        if (is_ok) {
            my_hdr->load_status = LDS_ATTACHED;
        }
    } else {
        std::cout << "Calling EntryPoint" << std::endl;
        int (*my_main)() = (int (*)()) (ep_va);
        is_ok = my_main();
        std::cout << "Called EntryPoint" << std::endl;
    }
    return is_ok;
}
