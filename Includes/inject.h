#pragma once

#include <windows.h>

bool
inject_process(wchar_t *mutex, BYTE *payload, size_t payloadSize, LPWSTR programPath, LPWSTR cmdLine,
               LPWSTR startDir, LPWSTR runtimeData = nullptr);