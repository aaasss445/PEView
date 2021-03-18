#include<stdio.h>
#include<string.h>
#include"PEStruct.h"

IMAGE_DOS_HEADER idh;

// notepad.exe 경로
// C:\\Windows\\notepad.exe

void PrintPEView(FILE* fp, int FileSize, int Option); // 옵션에 따라 화면에 다르게 출력해주는 함수
void IMAGE_DOS_HEADER_PRINT(FILE* fp); // 분석한걸 옵션으로 받았을때 IMAGE_DOS_HEADER 구조체를 출력해주는 함수

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
		printf("test : %s", Value);
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
					printf("%c", Value[j]);
				}
				printf("\n");
			}
			if (i > 1006) { // 그냥 임시로 끊어 준것
				break;
			}
		}
		free(buffer); // 메모리 해제
	}
	// 분석한 걸 출력
	if (Option == VIEWANALYSIS) {
		IMAGE_DOS_HEADER_PRINT(fp);
	}

}

void IMAGE_DOS_HEADER_PRINT(FILE* fp) {
	fread(&idh, sizeof(idh), 1, fp);
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
		printf("e_res2[%d] : %04X\n", i, idh.e_res2[i]);
	}
	printf("e_lfanew : %08X\n", idh.e_lfanew);
}