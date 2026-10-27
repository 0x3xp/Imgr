#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include "..\include\loader.h"
#include "..\include\common.h"

LOADER_STATUS APPLY_RELOCATIONS(LOADER_CTX* ctx) {
	 if (ctx == NULL || ctx->allocate_base == NULL || ctx->nt_headers == NULL) {
	 	return LOADER_ERR_INVALID_ARG;
	 }

	 uintptr_t preferred 	= ctx->nt_headers->OptionalHeader.ImageBase;
	 uintptr_t actual 		= (uintptr_t)ctx->allocate_base;
	 intptr_t delta			= (intptr_t)actual - (intptr_t)preferred;

	 ctx->delta = delta;

	if (delta == 0) {
	    printf("[+] Image loaded at preferred base, no relocations needed\n");
	    return LOADER_SUCCESS;
	}

		printf("[*] Relocating: preferred: 0x%zX, actual: 0x%zX, delta: 0x%zX\n", preferred, actual, (uintptr_t)delta);

	PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(ctx->nt_headers);
	PIMAGE_SECTION_HEADER reloc_sec = NULL;

	for (WORD i = 0; i < ctx->nt_headers->FileHeader.NumberOfSections; i++) {
	    if (strncmp(sec[i].Name, ".reloc", 8) == 0) {
	        reloc_sec = &sec[i];
	        break;
	    }
	}

	if (reloc_sec == NULL) {
	    fprintf(stderr, "[-] .reloc section not found (delta != 0)\n");
	    return LOADER_ERR_RELOCATION_FAILED;
	}

	if (reloc_sec->SizeOfRawData == 0 ||
	    (size_t)reloc_sec->VirtualAddress + reloc_sec->SizeOfRawData >
	        ctx->nt_headers->OptionalHeader.SizeOfImage) {
	    fprintf(stderr, "[-] .reloc section out of image bounds\n");
	    return LOADER_ERR_RELOCATION_FAILED;
	}

	printf("[+] Found .reloc at RVA 0x%X, size 0x%X\n",
	       reloc_sec->VirtualAddress, reloc_sec->SizeOfRawData);

	PIMAGE_BASE_RELOCATION block = (PIMAGE_BASE_RELOCATION)(ctx->allocate_base + reloc_sec->VirtualAddress);
	size_t remaining = reloc_sec->SizeOfRawData;
	size_t size_of_image = ctx->nt_headers->OptionalHeader.SizeOfImage;
	int block_count = 0;
	int total_entries = 0;

	while (remaining >= sizeof(IMAGE_BASE_RELOCATION)) {
	    if (block->SizeOfBlock == 0) {
	        printf("[+] End of relocation blocks (zero-size block, %zu bytes padding left)\n", remaining);
	        break;
	    }
	    if (block->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)) {
	        fprintf(stderr, "[-] Reloc block too small (SizeOfBlock: 0x%X)\n", block->SizeOfBlock);
	        return LOADER_ERR_RELOCATION_FAILED;
	    }
	    if (block->SizeOfBlock > remaining) {
	        fprintf(stderr, "[-] Reloc block exceeds section (SizeOfBlock: 0x%X, remaining=0x%zX)\n",
	                block->SizeOfBlock, remaining);
	        return LOADER_ERR_RELOCATION_FAILED;
	    }

	    DWORD entries_count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
	    PWORD entry = (PWORD)((PBYTE)block + sizeof(IMAGE_BASE_RELOCATION));

	    printf("[*] Block: VA: 0x%X, SizeOfBlock: 0x%X, entries: %u\n",
	           block->VirtualAddress, block->SizeOfBlock, entries_count);

	    for (DWORD j = 0; j < entries_count; j++) {
	        WORD type   = entry[j] >> 12;
	        WORD offset = entry[j] & 0xFFF;

	        if (type == IMAGE_REL_BASED_ABSOLUTE) {
	            continue;
	        }
	        if (type == IMAGE_REL_BASED_DIR64) {
	            size_t target_rva = (size_t)block->VirtualAddress + offset;
	            if (target_rva + sizeof(uint64_t) > size_of_image) {
	                fprintf(stderr, "[-] Reloc target out of image (RVA: 0x%zX)\n", target_rva);
	                return LOADER_ERR_RELOCATION_FAILED;
	            }
	            *(uint64_t*)(ctx->allocate_base + target_rva) += (uint64_t)delta;
	            total_entries++;
	        } else {
	            fprintf(stderr, "[!] Unknown reloc type %d at RVA 0x%X (skipping)\n",
	                    type, block->VirtualAddress + offset);
	        }
	    }

	    block_count++;
	    remaining -= block->SizeOfBlock;
	    block = (PIMAGE_BASE_RELOCATION)((PBYTE)block + block->SizeOfBlock);
	}

	printf("[+] Relocated %d entries across %d blocks (delta: 0x%zX)\n",
	       total_entries, block_count, (uintptr_t)delta);

	return LOADER_SUCCESS;
}