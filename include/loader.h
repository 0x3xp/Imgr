#ifndef LOADER_H
#define LOADER_H

#include <windows.h>    // PBYTE, PIMAGE_NT_HEADERS, PVOID
#include <stdint.h>     // uintptr_t, intptr_t
#include <stddef.h>     // size_t

typedef enum {
    LOADER_SUCCESS = 0,
    LOADER_INVALID_DOS_SIGNATURE,
    LOADER_INVALID_SECTION_TABLE,
    LOADER_ERR_INVALID_SECTION_TABLE,
    LOADER_INVALID_DOS_HEADER,
    LOADER_INVALID_NT_HEADER,
    LOADER_ERR_RELOCATION_FAILED,
    LOADER_ERR_INVALID_ARG,
    LOADER_ERR_ALLOCATION_FAILED,
    LOADER_ERR_REALLOC_FAILED,
    LOADER_ERR_IAT_FAILED
} LOADER_STATUS;

typedef struct {
    PBYTE            raw_buffer;
    size_t           raw_size;
    PBYTE            allocate_base;
    uintptr_t        preferred_base;
    intptr_t         delta;
    PIMAGE_NT_HEADERS nt_headers;
    PVOID            entry_point;
} LOADER_CTX;

#endif // LOADER_H