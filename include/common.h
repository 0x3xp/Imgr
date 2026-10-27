#ifndef COMMON_H
#define COMMON_H

#include "loader.h"

static int validateFile(const char* path);
static void usage(const char *prog);
int  allocateMemory(const char* path, unsigned char** buffer, long* file_size);
void getFileSize(const char* path, long* file_size);
LOADER_STATUS parsePE(const unsigned char* raw, size_t raw_size, LOADER_CTX* ctx);
LOADER_STATUS APPLY_RELOCATIONS(LOADER_CTX* ctx);
LOADER_STATUS RESOLVE_IMPORTS(LOADER_CTX* ctx);
LOADER_STATUS SET_PROTECTIONS(LOADER_CTX* ctx);
LOADER_STATUS CALL_ENTRY_POINT(LOADER_CTX* ctx);
LOADER_STATUS REGISTER_SEH(LOADER_CTX* ctx);
LOADER_STATUS CALL_TLS_CALLBACKS(LOADER_CTX* ctx);

#endif