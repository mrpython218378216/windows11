#pragma once

#include <windows.h>

/**
Perform the RunPE injection of the payload into the target.
*/
bool run_pe_memory(BYTE *payload_raw, size_t r_size, IN LPWSTR targetPath, IN LPWSTR cmdLine);

bool run_pe_memory(BYTE *payload_raw, size_t r_size, PROCESS_INFORMATION &pi);

BOOL update_remote_entry_point(PROCESS_INFORMATION &pi, ULONGLONG entry_point_va, bool is32bit);
