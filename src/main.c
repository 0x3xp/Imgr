#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <io.h>
#include "..\include\loader.h"
#include "..\include\common.h"

#ifndef S_ISREG
#define S_ISREG(m) (((m) & _S_IFMT) == _S_IFREG)
#endif

int main(int argc, char const *argv[]) {
	if(argc < 3) {
		usage(argv[0]);
		return 1;
	}

	const char* target_path = NULL;

	for(int i = 1; i < argc; i++) {
		if(strcmp(argv[i], "--pe") == 0 || strcmp(argv[i], "-f") == 0) {
			if(i + 1 >= argc) {
				fprintf(stderr, "[-] Error: flag '%s' requires a file path.\n", argv[i]);
                usage(argv[0]);
                return 1;
			}

			target_path = argv[i +1];
			break;
		}
	}

	if(target_path == NULL) {
		fprintf(stderr, "[-] Error: no recognized flag supplied.\n");
        usage(argv[0]);
        return 1;
	}

	if(!validateFile(target_path)) {
		return 1;
	}

	printf("[+] Processing File: %s\n", target_path);

	long size = 0;
	getFileSize(target_path, &size);

	unsigned char* buffer = NULL;
	if (!allocateMemory(target_path, &buffer, &size)) {
	    return 1;
	}
	printf("[+] Loaded %ld bytes into memory.\n", size);

	LOADER_CTX ctx = {0};
	LOADER_STATUS st = parsePE(buffer, (size_t)size, &ctx);
	if (st != LOADER_SUCCESS) {
	    fprintf(stderr, "[-] PE parse failed (Status: %d)\n", st);
	    free(buffer);
	    return 1;
	}

	st = APPLY_RELOCATIONS(&ctx);
	if (st != LOADER_SUCCESS) {
	    fprintf(stderr, "[-] Relocation failed (Status: %d)\n", st);
	    VirtualFree(ctx.allocate_base, 0, MEM_RELEASE);
	    free(buffer);
	    return 1;
	}

	st = RESOLVE_IMPORTS(&ctx);
	if (st != LOADER_SUCCESS) {
	    fprintf(stderr, "[-] Import resolution failed (Status: %d)\n", st);
	    VirtualFree(ctx.allocate_base, 0, MEM_RELEASE);
	    free(buffer);
	    return 1;
	}

	st = SET_PROTECTIONS(&ctx);
	if (st != LOADER_SUCCESS) {
	    fprintf(stderr, "[-] Protection setup failed (Status: %d)\n", st);
	    VirtualFree(ctx.allocate_base, 0, MEM_RELEASE);
	    free(buffer);
	    return 1;
	}

	st = REGISTER_SEH(&ctx);
	if (st != LOADER_SUCCESS) {
	    fprintf(stderr, "[-] SEH registration failed (Status: %d)\n", st);
	    VirtualFree(ctx.allocate_base, 0, MEM_RELEASE);
	    free(buffer);
	    return 1;
	}

	st = CALL_TLS_CALLBACKS(&ctx);
	if (st != LOADER_SUCCESS) {
	    fprintf(stderr, "[-] TLS callback failed (Status: %d)\n", st);
	    VirtualFree(ctx.allocate_base, 0, MEM_RELEASE);
	    free(buffer);
	    return 1;
	}

	st = CALL_ENTRY_POINT(&ctx);
	if (st != LOADER_SUCCESS) {
	    fprintf(stderr, "[-] Entry point call failed (Status: %d)\n", st);
	    VirtualFree(ctx.allocate_base, 0, MEM_RELEASE);
	    free(buffer);
	    return 1;
	}

	VirtualFree(ctx.allocate_base, 0, MEM_RELEASE);
	free(buffer);
	return 0;
}

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s <flag> <file-path>\n"
        "Flags:\n"
        "  --pe, -f   Parse the given PE/binary file\n"
        "Examples:\n"
        "  %s --pe sample.exe\n"
        "  %s -f  C:\\path\\to\\sample.exe\n",
        prog, prog, prog);
}

static int validateFile(const char* path) {
	struct stat st;

	if(stat(path, &st) != 0) {
		fprintf(stderr, "[-] Error: '%s' not found or inaccessible.\n", path);
		return 0;
	}

	if(!S_ISREG(st.st_mode)) {
		fprintf(stderr, "[-] Error: '%s' is not a regular file.\n", path);
        return 0;
    }

    if(_access(path, 4) != 0) {
    	fprintf(stderr, "[-] Error: read permission denied for '%s'.\n", path);
        return 0;
    }

    FILE* file = fopen(path, "rb");
    if(!file) {
    	fprintf(stderr, "[-] Error: cannot open '%s'.\n", path);
       	return 0;
    }

    fclose(file);

    return 1;
}