#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include "..\include\loader.h"
#include "..\include\common.h"

void getFileSize(const char* path, long* file_size) {
	struct stat st;

	if(stat(path, &st) == 0) {
		*file_size = st.st_size;
		printf("[+] File size: %ld bytes\n", st.st_size);
	} else {
		*file_size = -1;
	}
}

int allocateMemory(const char* path, unsigned char** buffer, long* file_size) {
	if(*file_size <= 0) {
		fprintf(stderr, "[-] Error invalid file size!\n");
		return 0;
	}

	*buffer = (unsigned char*)malloc((size_t)*file_size);
	if(*buffer == NULL) {
		fprintf(stderr, "[-] Error: memory allocation failed.\n");
		return 0;
	}

	FILE* file = fopen(path, "rb");
	if(!file) {
		free(*buffer);
		*buffer = NULL;
		return 0;
	}

	size_t read_bytes = fread(*buffer, 1, (size_t)*file_size, file);
	fclose(file);

	if(read_bytes != (size_t)*file_size) {
		fprintf(stderr, "[-] Error: failed to read entire file.\n");
        free(*buffer);
        *buffer = NULL;
        return 0;
	}
	return 1;
}

LOADER_STATUS parsePE(const unsigned char* raw, size_t raw_size, LOADER_CTX* ctx) {
	if(raw == NULL || ctx == NULL) {
		return LOADER_ERR_INVALID_ARG;
	}

	if(raw_size < sizeof(IMAGE_DOS_HEADER)) {
		return LOADER_INVALID_DOS_HEADER;
	}

	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)raw;
	if(dos->e_magic != IMAGE_DOS_SIGNATURE) {
		fprintf(stderr, "[-] DOS header FAILED (magic=0x%04X, expected 0x%04X)\n",
			dos->e_magic, IMAGE_DOS_SIGNATURE);

		return LOADER_INVALID_DOS_SIGNATURE;
	}

	printf("[+] DOS header OK (MZ - e_lfanew: 0x%X)\n", dos->e_lfanew);

	ctx->raw_buffer = (PBYTE)raw;
	ctx->raw_size = raw_size;

	if(dos->e_lfanew < 0 || (size_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > raw_size) {
		fprintf(stderr, "[-] NT header FAILED (e_lfanew: 0x%X out of bounds, raw_size: %zu)\n",
                dos->e_lfanew, raw_size);

		return LOADER_INVALID_NT_HEADER;
	}

	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(raw + dos->e_lfanew);
	if(nt->Signature != IMAGE_NT_SIGNATURE) {
		fprintf(stderr, "[-] NT header FAILED (signature: 0x%08X, expected 0x%08X)\n",
                nt->Signature, IMAGE_NT_SIGNATURE);

		return LOADER_INVALID_NT_HEADER;
	}

	printf("[+] NT header OK (PE, Machine: 0x%04X, Sections: %d, Magic: 0x%04X)\n",
           nt->FileHeader.Machine,
           nt->FileHeader.NumberOfSections,
           nt->OptionalHeader.Magic);

	ctx->nt_headers = nt;

	size_t sec_array_size = (size_t)nt->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
	size_t sec_array_offset = (size_t)((PBYTE)IMAGE_FIRST_SECTION(nt) - raw);

	if (sec_array_offset + sec_array_size > raw_size) {
    	fprintf(stderr, "[-] Section table FAILED (out of bounds)\n");
    	return LOADER_INVALID_NT_HEADER;
	}


	PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
	for(WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
		printf("[*] Section[%d]: name: %-8s  VA: 0x%06X  raw_size: 0x%06X  raw_ptr: 0x%06X\n",
       			i,
       			sec[i].Name,
       			sec[i].VirtualAddress,
       			sec[i].SizeOfRawData,
       			sec[i].PointerToRawData);
	}

	DWORD size_of_image = nt->OptionalHeader.SizeOfImage;
	DWORD size_of_headers = nt->OptionalHeader.SizeOfHeaders;

	LPVOID pImageBase = VirtualAlloc(NULL,
									 nt->OptionalHeader.SizeOfImage,
									 MEM_COMMIT | MEM_RESERVE,
									 PAGE_EXECUTE_READWRITE);
	if(pImageBase == NULL) {
		fprintf(stderr, "[-] Memory allocation failed for SizeOfImage (error %lu)\n", GetLastError());
		return LOADER_ERR_ALLOCATION_FAILED;
	}
		printf("[+] Image allocated: Base: %p, Size: 0x%X\n", pImageBase, size_of_image);

	ctx->allocate_base = (PBYTE)pImageBase;

	if (size_of_headers == 0 || size_of_headers > raw_size || size_of_headers > size_of_image) {
	    fprintf(stderr, "[-] Invalid SizeOfHeaders: 0x%X\n", size_of_headers);
	    VirtualFree(pImageBase, 0, MEM_RELEASE);
	    return LOADER_INVALID_NT_HEADER;
	}

	memcpy(pImageBase, raw, size_of_headers);

	PIMAGE_DOS_HEADER img_dos = (PIMAGE_DOS_HEADER)pImageBase;
	PIMAGE_NT_HEADERS img_nt  = (PIMAGE_NT_HEADERS)((PBYTE)pImageBase + img_dos->e_lfanew);

	printf("[+] Headers copied: %u bytes, MZ: %c%c, PE signature: 0x%08X\n",
	       size_of_headers,
	       ((char*)pImageBase)[0], ((char*)pImageBase)[1],
	       img_nt->Signature);


	for(WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
		if(sec[i].SizeOfRawData == 0) continue;

		if((size_t)sec[i].PointerToRawData +  sec[i].SizeOfRawData > raw_size) {
			fprintf(stderr, "[-] Section[%d] %.8s: raw data out of file bounds (ptr: 0x%X, size: 0x%X, raw_size: 0x%zX)\n",
            		i,
            		sec[i].Name,
            		sec[i].PointerToRawData,
            		sec[i].SizeOfRawData,
            		raw_size);
			VirtualFree(pImageBase, 0, MEM_RELEASE);
			return LOADER_INVALID_SECTION_TABLE;
		}

		if ((size_t)sec[i].VirtualAddress + sec[i].SizeOfRawData > size_of_image) {
    		fprintf(stderr, "[-] Section[%d] %.8s: virtual address out of image bounds (VA: 0x%X, Size: 0x%X, SizeOfImage: 0x%X)\n",
            		i,
            		sec[i].Name,
            		sec[i].VirtualAddress,
            		sec[i].SizeOfRawData,
            		size_of_image);
    		VirtualFree(pImageBase, 0, MEM_RELEASE);
    		return LOADER_INVALID_SECTION_TABLE;
		}

		memcpy((PBYTE)pImageBase + sec[i].VirtualAddress, raw + sec[i].PointerToRawData, sec[i].SizeOfRawData);
		printf("[+] Mapped %-8.8s : file 0x%06X -> RVA 0x%06X (0x%06X bytes)\n",
               sec[i].Name,
               sec[i].PointerToRawData,
               sec[i].VirtualAddress,
               sec[i].SizeOfRawData);
	}

	return LOADER_SUCCESS;
}