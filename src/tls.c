#include <stdio.h>
#include <stdlib.h>
#include "..\include\loader.h"
#include "..\include\common.h"

typedef void (NTAPI *PIMAGE_TLS_CALLBACK)(PVOID DllHandle, DWORD Reason, PVOID Reserved);

LOADER_STATUS CALL_TLS_CALLBACKS(LOADER_CTX* ctx) {
    if (ctx == NULL || ctx->allocate_base == NULL || ctx->nt_headers == NULL) {
        return LOADER_ERR_INVALID_ARG;
    }

    IMAGE_DATA_DIRECTORY* tls_dir =
        &ctx->nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];

    if (tls_dir->VirtualAddress == 0 || tls_dir->Size == 0) {
        printf("[*] No TLS directory - skipping TLS callbacks\n");
        return LOADER_SUCCESS;
    }

    size_t size_of_image = ctx->nt_headers->OptionalHeader.SizeOfImage;

    if ((size_t)tls_dir->VirtualAddress + sizeof(IMAGE_TLS_DIRECTORY) > size_of_image) {
        fprintf(stderr, "[-] TLS directory out of image bounds\n");
        return LOADER_ERR_INVALID_ARG;
    }

    PIMAGE_TLS_DIRECTORY tls = (PIMAGE_TLS_DIRECTORY)
        (ctx->allocate_base + tls_dir->VirtualAddress);

    if (tls->AddressOfCallBacks == 0) {
        printf("[*] TLS directory present but no callbacks\n");
        return LOADER_SUCCESS;
    }

    size_t cb_array_rva = (size_t)(tls->AddressOfCallBacks - (ULONG_PTR)ctx->nt_headers->OptionalHeader.ImageBase);
    if (cb_array_rva >= size_of_image) {
        fprintf(stderr, "[-] TLS callback array out of image bounds\n");
        return LOADER_ERR_INVALID_ARG;
    }

    PIMAGE_TLS_CALLBACK* callbacks = (PIMAGE_TLS_CALLBACK*)
        (ctx->allocate_base + cb_array_rva);

    int cb_count = 0;

    while (callbacks[cb_count] != NULL) {
        if ((size_t)((PBYTE)&callbacks[cb_count] - ctx->allocate_base) >= size_of_image) {
            fprintf(stderr, "[-] TLS callback array walked past image bounds\n");
            return LOADER_ERR_INVALID_ARG;
        }

        PIMAGE_TLS_CALLBACK cb = callbacks[cb_count];
        printf("[*] Calling TLS callback %d at %p (DLL_PROCESS_ATTACH)\n", cb_count, (void*)cb);

        __try {
            cb((PVOID)ctx->allocate_base, DLL_PROCESS_ATTACH, NULL);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            fprintf(stderr, "[-] TLS callback %d raised exception 0x%08lX\n",
                    cb_count, GetExceptionCode());
            return LOADER_ERR_INVALID_ARG;
        }

        cb_count++;
    }

    printf("[+] Called %d TLS callbacks\n", cb_count);
    return LOADER_SUCCESS;
}