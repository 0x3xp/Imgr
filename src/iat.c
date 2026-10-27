#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include "..\include\loader.h"
#include "..\include\common.h"

LOADER_STATUS RESOLVE_IMPORTS(LOADER_CTX* ctx) {
    if (ctx == NULL || ctx->allocate_base == NULL || ctx->nt_headers == NULL) {
        return LOADER_ERR_INVALID_ARG;
    }

    IMAGE_DATA_DIRECTORY* imp_dir =
        &ctx->nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    if (imp_dir->VirtualAddress == 0 || imp_dir->Size == 0) {
        printf("[+] No import directory (image has no imports)\n");
        return LOADER_SUCCESS;
    }

    size_t size_of_image = ctx->nt_headers->OptionalHeader.SizeOfImage;

    if ((size_t)imp_dir->VirtualAddress + imp_dir->Size > size_of_image) {
        fprintf(stderr, "[-] Import directory out of image bounds\n");
        return LOADER_ERR_IAT_FAILED;
    }

    printf("[+] Import directory: RVA: 0x%X, Size: 0x%X\n",
           imp_dir->VirtualAddress, imp_dir->Size);

    PIMAGE_IMPORT_DESCRIPTOR desc =
        (PIMAGE_IMPORT_DESCRIPTOR)(ctx->allocate_base + imp_dir->VirtualAddress);

    int dll_count = 0;
    int total_funcs = 0;

    while (desc->Name != 0) {
        if ((size_t)desc->Name >= size_of_image) {
            fprintf(stderr, "[-] Import descriptor Name RVA out of bounds (0x%X)\n", desc->Name);
            return LOADER_ERR_IAT_FAILED;
        }

        const char* dll_name = (const char*)(ctx->allocate_base + desc->Name);
        HMODULE hmod = LoadLibraryA(dll_name);
        if (hmod == NULL) {
            fprintf(stderr, "[-] LoadLibrary failed for '%s' (error %lu)\n",
                    dll_name, GetLastError());
            return LOADER_ERR_IAT_FAILED;
        }

        DWORD lookup_rva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;

        if ((size_t)lookup_rva >= size_of_image || (size_t)desc->FirstThunk >= size_of_image) {
            fprintf(stderr, "[-] Import thunk RVA out of bounds for '%s'\n", dll_name);
            return LOADER_ERR_IAT_FAILED;
        }

        PIMAGE_THUNK_DATA lookup = (PIMAGE_THUNK_DATA)(ctx->allocate_base + lookup_rva);
        PIMAGE_THUNK_DATA iat    = (PIMAGE_THUNK_DATA)(ctx->allocate_base + desc->FirstThunk);

        int func_count = 0;

        while (lookup->u1.AddressOfData != 0) {
            if ((size_t)lookup - (size_t)ctx->allocate_base >= size_of_image ||
                (size_t)iat    - (size_t)ctx->allocate_base >= size_of_image) {
                fprintf(stderr, "[-] Import thunk walked past image bounds for '%s'\n", dll_name);
                return LOADER_ERR_IAT_FAILED;
            }

            FARPROC func = NULL;

            if (lookup->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                WORD ordinal = (WORD)(lookup->u1.Ordinal & 0xFFFF);
                func = GetProcAddress(hmod, (LPCSTR)(ULONG_PTR)ordinal);
            } else {
                if ((size_t)lookup->u1.AddressOfData >= size_of_image) {
                    fprintf(stderr, "[-] Import name RVA out of bounds for '%s'\n", dll_name);
                    return LOADER_ERR_IAT_FAILED;
                }
                PIMAGE_IMPORT_BY_NAME name =
                    (PIMAGE_IMPORT_BY_NAME)(ctx->allocate_base + lookup->u1.AddressOfData);
                func = GetProcAddress(hmod, (LPCSTR)name->Name);
            }

            if (func == NULL) {
                fprintf(stderr, "[-] GetProcAddress failed for '%s' entry %d\n",
                        dll_name, func_count);
                return LOADER_ERR_IAT_FAILED;
            }

            iat->u1.Function = (ULONG_PTR)func;

            lookup++;
            iat++;
            func_count++;
        }

        printf("[+] Resolved %-16s : %d functions\n", dll_name, func_count);
        total_funcs += func_count;
        dll_count++;
        desc++;
    }

    printf("[+] Resolved %d imports across %d DLLs\n", total_funcs, dll_count);

    return LOADER_SUCCESS;
}