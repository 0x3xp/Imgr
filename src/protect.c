#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include "..\include\loader.h"
#include "..\include\common.h"

LOADER_STATUS SET_PROTECTIONS(LOADER_CTX* ctx) {
    if (ctx == NULL || ctx->allocate_base == NULL || ctx->nt_headers == NULL) {
        return LOADER_ERR_INVALID_ARG;
    }

    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(ctx->nt_headers);
    DWORD section_alignment = ctx->nt_headers->OptionalHeader.SectionAlignment;
    if (section_alignment == 0) section_alignment = 0x1000;

    int protected_count = 0;

    for (WORD i = 0; i < ctx->nt_headers->FileHeader.NumberOfSections; i++) {
        DWORD characteristics = sec[i].Characteristics;

        if (characteristics & IMAGE_SCN_MEM_DISCARDABLE) {
            continue;
        }

        DWORD size = sec[i].Misc.VirtualSize;
        if (size == 0) size = sec[i].SizeOfRawData;
        if (size == 0) continue;

        size_t aligned_size = ((size_t)size + section_alignment - 1) & ~((size_t)section_alignment - 1);

        size_t section_rva = (size_t)sec[i].VirtualAddress;
        if (section_rva + aligned_size > ctx->nt_headers->OptionalHeader.SizeOfImage) {
            fprintf(stderr, "[-] Section[%d] %.8s protection range out of image bounds\n",
                    i, sec[i].Name);
            return LOADER_ERR_INVALID_SECTION_TABLE;
        }

        DWORD new_protect;
        const char* prot_name;

        if (characteristics & IMAGE_SCN_MEM_EXECUTE) {
            if (characteristics & IMAGE_SCN_MEM_WRITE) {
                new_protect = PAGE_EXECUTE_READWRITE;
                prot_name = "PAGE_EXECUTE_READWRITE";
            } else if (characteristics & IMAGE_SCN_MEM_READ) {
                new_protect = PAGE_EXECUTE_READ;
                prot_name = "PAGE_EXECUTE_READ";
            } else {
                new_protect = PAGE_EXECUTE;
                prot_name = "PAGE_EXECUTE";
            }
        } else if (characteristics & IMAGE_SCN_MEM_WRITE) {
            if (characteristics & IMAGE_SCN_MEM_READ) {
                new_protect = PAGE_READWRITE;
                prot_name = "PAGE_READWRITE";
            } else {
                new_protect = PAGE_WRITECOPY;
                prot_name = "PAGE_WRITECOPY";
            }
        } else {
            if (characteristics & IMAGE_SCN_MEM_READ) {
                new_protect = PAGE_READONLY;
                prot_name = "PAGE_READONLY";
            } else {
                new_protect = PAGE_NOACCESS;
                prot_name = "PAGE_NOACCESS";
            }
        }

        DWORD old_protect = 0;
        if (!VirtualProtect(ctx->allocate_base + section_rva, aligned_size, new_protect, &old_protect)) {
            fprintf(stderr, "[-] VirtualProtect failed for %.8s (error %lu)\n",
                    sec[i].Name, GetLastError());
            return LOADER_ERR_INVALID_SECTION_TABLE;
        }

        printf("[+] Protected %-8.8s : %s\n", sec[i].Name, prot_name);
        protected_count++;
    }

    printf("[+] Applied protections to %d sections\n", protected_count);

    return LOADER_SUCCESS;
}