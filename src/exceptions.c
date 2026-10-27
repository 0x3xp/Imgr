#include <stdio.h>
#include <stdlib.h>
#include "..\include\loader.h"
#include "..\include\common.h"

typedef BOOLEAN (WINAPI *RTL_ADD_FUNCTION_TABLE)(
    PRUNTIME_FUNCTION FunctionTable,
    DWORD EntryCount,
    ULONG64 BaseAddress,
    PULONG64 FunctionTableBaseAddress,
    PVOID A,
    PVOID B
);

LOADER_STATUS REGISTER_SEH(LOADER_CTX* ctx) {
    if (ctx == NULL || ctx->allocate_base == NULL || ctx->nt_headers == NULL) {
        return LOADER_ERR_INVALID_ARG;
    }

    IMAGE_DATA_DIRECTORY* exc_dir =
        &ctx->nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

    if (exc_dir->VirtualAddress == 0 || exc_dir->Size == 0) {
        printf("[*] No exception directory (.pdata) - skipping SEH registration\n");
        return LOADER_SUCCESS;
    }

    size_t size_of_image = ctx->nt_headers->OptionalHeader.SizeOfImage;

    if ((size_t)exc_dir->VirtualAddress + exc_dir->Size > size_of_image) {
        fprintf(stderr, "[-] Exception directory out of image bounds\n");
        return LOADER_ERR_INVALID_ARG;
    }

    PRUNTIME_FUNCTION table = (PRUNTIME_FUNCTION)
        (ctx->allocate_base + exc_dir->VirtualAddress);
    DWORD count = exc_dir->Size / sizeof(RUNTIME_FUNCTION);

    if (count == 0) {
        printf("[*] Exception directory empty - skipping\n");
        return LOADER_SUCCESS;
    }

    if (RtlAddFunctionTable(table, count, (DWORD64)ctx->allocate_base)) {
        printf("[+] Registered SEH table: %lu entries at %p\n",
               (unsigned long)count, (void*)table);
        return LOADER_SUCCESS;
    }

    fprintf(stderr, "[-] RtlAddFunctionTable failed (error %lu)\n", GetLastError());
    return LOADER_ERR_INVALID_ARG;
}