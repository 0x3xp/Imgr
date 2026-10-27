#include <stdio.h>
#include <windows.h>

#pragma comment(lib, "user32.lib")

int main() {

	MessageBoxA(NULL,
		        "Target binary for in-memory PE loader",
		        "In-memory PE-Loader",
		        MB_OK | MB_ICONINFORMATION);

	return 0;
}