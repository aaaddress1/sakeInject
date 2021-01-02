#pragma once
#include <fstream>
#include <windows.h>
#pragma warning(disable:4996)
#define getNtHdr(buf) ((IMAGE_NT_HEADERS *)((size_t)buf + ((IMAGE_DOS_HEADER *)buf)->e_lfanew))
#define getSectionArr(buf) ((IMAGE_SECTION_HEADER *)((size_t)getNtHdr(buf) + sizeof(IMAGE_NT_HEADERS)))
#define P2ALIGNUP(size, align) ((((size) / (align)) + 1) * (align))

PIMAGE_SECTION_HEADER newSection(char* buf) {
	PIMAGE_SECTION_HEADER firstSecHdr = &getSectionArr(buf)[0];
	PIMAGE_SECTION_HEADER finalSecHdr = &getSectionArr(buf)[getNtHdr(buf)->FileHeader.NumberOfSections - 1];
	PIMAGE_SECTION_HEADER creatSecHdr = &getSectionArr(buf)[getNtHdr(buf)->FileHeader.NumberOfSections];
	memcpy(creatSecHdr->Name, ".sake", 8);
	creatSecHdr->Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
	creatSecHdr->VirtualAddress = P2ALIGNUP(
		finalSecHdr->VirtualAddress + finalSecHdr->Misc.VirtualSize,
		getNtHdr(buf)->OptionalHeader.SectionAlignment
	);
	getNtHdr(buf)->FileHeader.NumberOfSections += 1;
	return (size_t)creatSecHdr - (size_t)buf < firstSecHdr->PointerToRawData ? creatSecHdr : NULL; // bound check
}


void fixUp_SaveExeToFile(char* bufToSave, size_t currLen, char* pathToWrite) {
	for (size_t i = 1; i < getNtHdr(bufToSave)->FileHeader.NumberOfSections; i++)
		getSectionArr(bufToSave)[i - 1].Misc.VirtualSize =
		getSectionArr(bufToSave)[i].VirtualAddress - getSectionArr(bufToSave)[i - 1].VirtualAddress;

	getNtHdr(bufToSave)->OptionalHeader.SizeOfImage =
		getSectionArr(bufToSave)[getNtHdr(bufToSave)->FileHeader.NumberOfSections - 1].VirtualAddress +
		getSectionArr(bufToSave)[getNtHdr(bufToSave)->FileHeader.NumberOfSections - 1].Misc.VirtualSize;

	getNtHdr(bufToSave)->OptionalHeader.DllCharacteristics &= ~(IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE);
	FILE* fp = fopen(pathToWrite, "wb");
	fwrite(bufToSave, 1, currLen, fp);
	fclose(fp);
}

size_t rvaToOffset(char* exeData, size_t RVA) {
	for (size_t i = 0; i < getNtHdr(exeData)->FileHeader.NumberOfSections; i++)
		if (RVA >= getSectionArr(exeData)[i].VirtualAddress &&
			RVA <= getSectionArr(exeData)[i].VirtualAddress + getSectionArr(exeData)[i].Misc.VirtualSize)
			return getSectionArr(exeData)[i].PointerToRawData + (RVA - getSectionArr(exeData)[i].VirtualAddress);
	return 0;
}
bool tlsInject(char* exeData, char* ptrStubData, size_t appendStubSize, char* pathToWrite) {
	PIMAGE_NT_HEADERS ntHdr = (PIMAGE_NT_HEADERS)((size_t)exeData + PIMAGE_DOS_HEADER(exeData)->e_lfanew);
	PIMAGE_DATA_DIRECTORY tlsDataDir = &ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
	size_t sakeUsed = 0, fileSakeSize = 0, sectSakeSize = 0;
	char* sakeSecData = new char[0x100 + appendStubSize];
	size_t offset_newDataStart =
		getSectionArr(exeData)[getNtHdr(exeData)->FileHeader.NumberOfSections - 1].PointerToRawData +
		getSectionArr(exeData)[getNtHdr(exeData)->FileHeader.NumberOfSections - 1].SizeOfRawData;
	auto sakeSection = newSection(exeData);

	PIMAGE_TLS_DIRECTORY imgTlsDir;
	if (!tlsDataDir->VirtualAddress || !tlsDataDir->Size) {
		imgTlsDir = (PIMAGE_TLS_DIRECTORY)sakeSecData;
		memset(imgTlsDir, '\x00', sizeof(*imgTlsDir));
		sakeUsed += sizeof(*imgTlsDir);

		imgTlsDir->AddressOfIndex = getNtHdr(exeData)->OptionalHeader.ImageBase + sakeSection->VirtualAddress;
		imgTlsDir->AddressOfCallBacks = getNtHdr(exeData)->OptionalHeader.ImageBase + sakeSection->VirtualAddress + sakeUsed;
		auto addrOfCBackSaveAt = (decltype(imgTlsDir->AddressOfCallBacks)*)(sakeSecData + sakeUsed);
		sakeUsed += sizeof(decltype(imgTlsDir->AddressOfCallBacks)) * 2;
		addrOfCBackSaveAt[0] = getNtHdr(exeData)->OptionalHeader.ImageBase + sakeSection->VirtualAddress + sakeUsed;
		addrOfCBackSaveAt[1] = 0;
	
		tlsDataDir->VirtualAddress = sakeSection->VirtualAddress;
		tlsDataDir->Size = sakeUsed;
	}
	else {
		imgTlsDir = (PIMAGE_TLS_DIRECTORY)((size_t)exeData + rvaToOffset(exeData, tlsDataDir->VirtualAddress));
		auto k = rvaToOffset(exeData, imgTlsDir->AddressOfCallBacks - getNtHdr(exeData)->OptionalHeader.ImageBase);
		auto addrOfCBackSaveAt = (decltype(imgTlsDir->AddressOfCallBacks)*)((size_t)exeData + k);
		for (; *addrOfCBackSaveAt; addrOfCBackSaveAt++) if (!*addrOfCBackSaveAt) break;
		*addrOfCBackSaveAt++ = getNtHdr(exeData)->OptionalHeader.ImageBase + sakeSection->VirtualAddress + sakeUsed;
		*addrOfCBackSaveAt = 0;
	}

	fileSakeSize = P2ALIGNUP((sakeUsed + appendStubSize), ntHdr->OptionalHeader.FileAlignment);
	sectSakeSize = P2ALIGNUP((sakeUsed + appendStubSize), ntHdr->OptionalHeader.SectionAlignment);
	sakeSection->PointerToRawData = offset_newDataStart;
	sakeSection->SizeOfRawData = fileSakeSize;
	sakeSection->Misc.VirtualSize = sectSakeSize;

	char* outExeBuf = new char[offset_newDataStart + fileSakeSize];
	memcpy(outExeBuf, exeData, offset_newDataStart);
	memcpy(outExeBuf + offset_newDataStart, sakeSecData, sakeUsed);
	memcpy(outExeBuf + offset_newDataStart + sakeUsed, ptrStubData, appendStubSize);
	fixUp_SaveExeToFile(outExeBuf, offset_newDataStart + fileSakeSize, pathToWrite);
	return true;
}