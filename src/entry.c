#include <stdio.h>
#include <stdlib.h>
#include "..\include\loader.h"
#include "..\include\common.h"

typedef int (*ENTRY_FN)(void);

LOADER_STATUS CALL_ENTRY_POINT(LOADER_CTX* ctx) {
    if (ctx == NULL || ctx->allocate_base == NULL || ctx->nt_headers == NULL) {
        return LOADER_ERR_INVALID_ARG;
    }

    DWORD entry_rva = ctx->nt_headers->OptionalHeader.AddressOfEntryPoint;
    size_t size_of_image = ctx->nt_headers->OptionalHeader.SizeOfImage;

    if (entry_rva == 0 || (size_t)entry_rva >= size_of_image) {
        fprintf(stderr, "[-] Invalid entry point RVA: 0x%X\n", entry_rva);
        return LOADER_ERR_INVALID_ARG;
    }

    ctx->entry_point = ctx->allocate_base + entry_rva;

    printf("[*] Entry point: RVA: 0x%X, Absolute: %p\n", entry_rva, ctx->entry_point);

    ENTRY_FN entry = (ENTRY_FN)ctx->entry_point;

    printf("[*] Calling entry point...\n");

    int result = 0;
    __try {
        result = entry();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DWORD code = GetExceptionCode();
        fprintf(stderr, "[-] Entry point raised exception 0x%08lX\n", code);
        return LOADER_ERR_INVALID_ARG;
    }

    printf("[+] Entry point returned: %d\n", result);
    return LOADER_SUCCESS;
}