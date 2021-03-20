#include<stdio.h>
#include<string.h>
#include"PEStruct.h"

IMAGE_DOS_HEADER idh;
IMAGE_NT_HEADERS64 inh;

// notepad.exe 경로
// C:\\Windows\\notepad.exe

void PrintPEView(FILE* fp, int FileSize, int Option); // 옵션에 따라 화면에 다르게 출력해주는 함수
void IMAGE_DOS_HEADER_PRINT(FILE* fp); // 분석한걸 옵션으로 받았을때 IMAGE_DOS_HEADER 구조체를 출력해주는 함수
void IMAGE_NT_HEADERS64_PRINT(FILE* fp);
void DOS_HEADER_PRINT(FILE* fp);
void ChangeEscapeSequence(CHAR* ch);
void IMAGE_SECTION_HEADER_PRINT(FILE* fp);
//void PrintText(int* p);

int main(int argc, int *argv[]) {
	int FileSize; // 파일 크기
	char* FileRoute = argv[1]; // 파일 경로
	int Option; // 들어온 옵션

	if (FileRoute == NULL) { // 파일 경로를 입력 안했을때
		printf("파일 경로를 입력해 주세요.\n");
		exit(0);
	}

	FILE* fp = fopen(FileRoute, "r");
	fseek(fp, 0, SEEK_END);
	FileSize = ftell(fp); // 파일 크기 받기
	fseek(fp, 0, SEEK_SET); // 파일의 커서를 처음으로 셋팅해두기


	if (argv[2] == NULL) { // 옵션을 입력 안했을때 
		printf("옵션을 입력해 주세요.\n");
		// 그리고 옵션 사용법 출력
		exit(0);
	}

	// 옵션값 저장
	if (strcmp(argv[2], "-B") == 0) {
		Option = VIEWBYTE;
	}
	else if (strcmp(argv[2], "-A") == 0) {
		Option = VIEWANALYSIS;
	}

	// PE를 화면에 출력
	PrintPEView(fp, FileSize, Option);

	fclose(fp);

	return 0;
}

void PrintPEView(FILE* fp, int FileSize, int Option) {
	// 바이트로만 출력
	if (Option == VIEWBYTE) {
		char Value[16] = { -1, }; // 바이트를 문자로 출력하기위한 임시저장변수
		char* buffer = (char*)malloc(sizeof(char) * FileSize); // 파일의 크기만큼 메모리 동적할당
		fread(buffer, FileSize, 1, fp); // 파일 크기만큼 읽기
		printf("%d\n", sizeof(IMAGE_NT_HEADERS32));
		printf("pFile\t\tRaw Data\t\t\t\t\t\tValue\n");
		printf("===============================================================\n");
		for (int i = 0; i < FileSize; i++) {
			if (i % 16 == 0) {
				printf("%08X\t", i); // 파일의 RVA 출력
			}
			printf("%02X ", (CHAR)buffer[i]); // 바이트 하나 출력
			Value[i%16] = (CHAR)buffer[i]; // 바이트 값을 하나씩 문자출력변수에 저장
			
			if (i % 16 == 15) { // 한줄이 다 채워지면
				printf("\t");
				for (int j = 0; j < 16; j++) { // 그 한줄의 문자들 출력
					ChangeEscapeSequence(&Value[j]);
				}
				printf("\n");
			}
			//if (i > 1006) { // 그냥 임시로 끊어 준것
			//	break;
			//}
		}
		free(buffer); // 메모리 해제
	}
	// 분석한 걸 출력
	if (Option == VIEWANALYSIS) {
		printf("%d\n", sizeof(inh));
		IMAGE_DOS_HEADER_PRINT(fp);
		DOS_HEADER_PRINT(fp);
		IMAGE_NT_HEADERS64_PRINT(fp);
		IMAGE_SECTION_HEADER_PRINT(fp);
	}

}

void IMAGE_DOS_HEADER_PRINT(FILE* fp) {
	fread(&idh, sizeof(idh), 1, fp); // 파일 읽기
	printf("+++IMAGE_DOS_HEADER+++\n");
	printf("e_magic : %04X\n", idh.e_magic);
	printf("e_cblp : %04X\n", idh.e_cblp);
	printf("e_cp : %04X\n", idh.e_cp);
	printf("e_crlc : %04X\n", idh.e_crlc);
	printf("e_cparhdr : %04X\n", idh.e_cparhdr);
	printf("e_minalloc : %04X\n", idh.e_minalloc);
	printf("e_maxalloc : %04X\n", idh.e_maxalloc);
	printf("e_ss : %04X\n", idh.e_ss);
	printf("e_sp : %04X\n", idh.e_sp);
	printf("e_csum : %04X\n", idh.e_csum);
	printf("e_ip : %04X\n", idh.e_ip);
	printf("e_cs : %04X\n", idh.e_cs);
	printf("e_lfarlc : %04X\n", idh.e_lfarlc);
	printf("e_ovno : %04X\n", idh.e_ovno);
	for (int i = 0; i < 4; i++) {
		printf("e_res[%d] : %04X\n", i, idh.e_res[i]);
	}
	printf("e_oeminfo : %04X\n", idh.e_oeminfo);
	for (int i = 0; i < 10; i++) {
		printf("e_res2[%X] : %04X\n", i, idh.e_res2[i]);
	}
	printf("e_lfanew : %08X\n", idh.e_lfanew);
}

void IMAGE_NT_HEADERS64_PRINT(FILE* fp) {
	fseek(fp, idh.e_lfanew, SEEK_SET); // 파일 포인터가 자꾸 이상해져서 아예 초기화 했음
	fread(&inh, sizeof(inh), 1, fp);
	printf("+++IMAGE_NT_HEADERS+++\n");
	printf("Signature : %08X\n", inh.Signature);
	printf("++++++IMAGE_FILE_HEADER+++++\n");
	printf("Machine : %04X\n", inh.FileHeader.Machine);
	printf("NumberOfSections : %04X\n", inh.FileHeader.NumberOfSections);
	printf("TimeDateStamp : %08X\n", inh.FileHeader.TimeDateStamp);
	printf("PointerToSymbolTable : %08X\n", inh.FileHeader.PointerToSymbolTable);
	printf("NumberOfSymbols : %08X\n", inh.FileHeader.NumberOfSymbols);
	printf("SizeOfOptionalHeader : %04X\n", inh.FileHeader.SizeOfOptionalHeader);
	printf("Characteristics : %04X\n", inh.FileHeader.Characteristics);
	printf("+++++IMAGE_OPTIONAL_HEADER32+++++\n");
	printf("Magic : %04X\n", inh.OptionalHeader.Magic);
	printf("MajorLinkerVersion : %02X\n", inh.OptionalHeader.MajorLinkerVersion);
	printf("MinorLinkerVersion : %02X\n", inh.OptionalHeader.MinorLinkerVersion);
	printf("SizeOfCode : %08X\n", inh.OptionalHeader.SizeOfCode);
	printf("SizeOfInitializedData : %08X\n", inh.OptionalHeader.SizeOfInitializedData);
	printf("SizeOfUninitializedData : %08X\n", inh.OptionalHeader.SizeOfUninitializedData);
	printf("AddressOfEntryPoint : %08X\n", inh.OptionalHeader.AddressOfEntryPoint);
	printf("BaseOfCode : %08X\n", inh.OptionalHeader.BaseOfCode);
	printf("ImageBase : %016X\n", inh.OptionalHeader.ImageBase);
	printf("SectionAlignment : %08X\n", inh.OptionalHeader.SectionAlignment);
	printf("FileAlignment : %08X\n", inh.OptionalHeader.FileAlignment);
	printf("MajorOperatingSystemVersion : %04X\n", inh.OptionalHeader.MajorOperatingSystemVersion);
	printf("MinorOperatingSystemVersion : %04X\n", inh.OptionalHeader.MinorOperatingSystemVersion);
	printf("MajorImageVersion : %04X\n", inh.OptionalHeader.MajorImageVersion);
	printf("MinorImageVersion : %04X\n", inh.OptionalHeader.MinorImageVersion);
	printf("MajorSubsystemVersion : %04X\n", inh.OptionalHeader.MajorSubsystemVersion);
	printf("MinorSubsystemVersion : %04X\n", inh.OptionalHeader.MinorSubsystemVersion);
	printf("Win32VersionValue : %08X\n", inh.OptionalHeader.Win32VersionValue);
	printf("SizeOfImage : %08X\n", inh.OptionalHeader.SizeOfImage);
	printf("SizeOfHeaders : %08X\n", inh.OptionalHeader.SizeOfHeaders);
	printf("CheckSum : %08X\n", inh.OptionalHeader.CheckSum);
	printf("Subsystem : %04X\n", inh.OptionalHeader.Subsystem);
	printf("DllCharacteristics : %04X\n", inh.OptionalHeader.DllCharacteristics);
	printf("SizeOfStackReserve : %016X\n", inh.OptionalHeader.SizeOfStackReserve);
	printf("SizeOfStackCommit : %016X\n", inh.OptionalHeader.SizeOfStackCommit);
	printf("SizeOfHeapReserve : %016X\n", inh.OptionalHeader.SizeOfHeapReserve);
	printf("SizeOfHeapCommit : %016X\n", inh.OptionalHeader.SizeOfHeapCommit);
	printf("LoaderFlags : %08X\n", inh.OptionalHeader.LoaderFlags);
	printf("NumberOfRvaAndSizes : %08X\n", inh.OptionalHeader.NumberOfRvaAndSizes);
	for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
		printf("DataDirectory[%X] - VirtualAddress : %08X\n", i, inh.OptionalHeader.DataDirectory[i].VirtualAddress);
		printf("DataDirectory[%X] - Size : %08X\n", i, inh.OptionalHeader.DataDirectory[i].Size);
	}
}

void IMAGE_SECTION_HEADER_PRINT(FILE* fp) {
	int IMAGE_SECTION_HEADER_START = idh.e_lfanew + sizeof(inh); // IMAGE_SECTION_HEADER의 시작 부분 저장
	int IMAGE_SECTION_HEADER_COUNT = inh.FileHeader.NumberOfSections; // IMAGE_SECTION_HEADER의 개수 저장
	IMAGE_SECTION_HEADER* ish = (IMAGE_SECTION_HEADER*)malloc(sizeof(IMAGE_SECTION_HEADER) * (IMAGE_SECTION_HEADER_COUNT)); // 개수만큼 배열 생성

	fseek(fp, IMAGE_SECTION_HEADER_START, SEEK_SET);
	for (int i = 0; i < IMAGE_SECTION_HEADER_COUNT; i++) {
		fread(&ish[i], sizeof(IMAGE_SECTION_HEADER), 1, fp);
		printf("+++IMAGE_SECTION_HEADER[%d]+++\n", i);
		printf("Name : %s\n", ish[i].name);
		printf("VirtualSize : %08X\n", ish[i].Misc.VirtualSize);
		printf("VirtualAddress : %08X\n", ish[i].VirtualAddress);
		printf("SizeofRawData : %08x\n", ish[i].SizeOfRawData);
		printf("PointerToRawData : %08X\n", ish[i].PointerToRawData);
		printf("PointerToRelocations : %08X\n", ish[i].PointerToRelocations);
		printf("PointerToLinenumber : %08X\n", ish[i].PointerToLinenumbers);
		printf("NumberOfRelocations : %04X\n", ish[i].NumberOfRelocations);
		printf("NumberOfLinenumbers : %04X\n", ish[i].NumberOfLinenumbers);
		printf("Characteristics : %08X\n", ish[i].Characteristics);
	}
	
	free(ish);
}

void DOS_HEADER_PRINT(FILE* fp) {
	fseek(fp, sizeof(idh), SEEK_SET); // 파일 위치 설정
	int DOS_HEADER_SIZE = idh.e_lfanew - sizeof(IMAGE_DOS_HEADER); // DOS_HEADER의 크기 저장
	char* DosHeaderBuffer = (char*)malloc(sizeof(char) * (DOS_HEADER_SIZE)); // DOS_HEADER의 값을 받을 공간 만듦
	fread(DosHeaderBuffer, DOS_HEADER_SIZE, 1, fp);
	printf("+++DOS_HEADER+++\n");
	for (int i = 0; i < DOS_HEADER_SIZE; i++) {
		if (i % 16 == 0) {
			printf("%08x\t", sizeof(IMAGE_DOS_HEADER) + i); // 파일 커서 위치 출력
		}
		ChangeEscapeSequence(&DosHeaderBuffer[i]); // 몇몇 특수문자 같은거 제거

		if (i % 16 == 15) {
			printf("\n");
		}
	}
	printf("\n");
	free(DosHeaderBuffer);
}

void ChangeEscapeSequence(CHAR *ch) { // 몇몇 글자들 대체하기
	if (*ch == 0x0A || *ch == 0x0D || // 개행, 공백, 백스페이스, 수평 탭, 수직 탭, 처음으로 가기, 경보, 등등
		*ch == 0x0 || *ch == 0x09 ||  // 그냥 .으로 바꿈
		*ch == 0x0B || *ch== 0x07 ||
		*ch == 0x08) {
		printf(".");
	}
	else {
		printf("%c", *ch);
	}
}

//void PrintText(int* p) {
//	int vsize = sizeof(*p);
//	char* pname = name(*p);
//	char* vname;
//
//	char* ptr = strtok(pname, ".");      
//
//	while (ptr != NULL)               
//	{
//		vname = ptr;		          
//		ptr = strtok(NULL, ".");      
//		if (ptr == NULL) {
//			break;
//		}
//	}
//
//	switch (vsize) {
//	case 1:
//		printf("%s : %02X", vname, *p);
//		break;
//	case 2:
//		printf("%s : %04X", vname, *p);
//		break;
//	case 4:
//		printf("%s : %08X", vname, *p);
//		break;
//	}
//}