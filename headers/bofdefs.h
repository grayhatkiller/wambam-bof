#pragma once
#pragma intrinsic(memcmp, memcpy,strcpy,strcmp,_stricmp,strlen)
#include <windows.h>
#include <stdarg.h>
#include <shlobj.h>
#include <stdio.h>
#include <wincrypt.h>

// #ifdef BOF

WINBASEAPI void *__cdecl MSVCRT$calloc(size_t _NumOfElements, size_t _SizeOfElements);
#define calloc MSVCRT$calloc

WINBASEAPI void * WINAPI KERNEL32$HeapAlloc (HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
#define HeapAlloc KERNEL32$HeapAlloc

WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
#define GetProcessHeap KERNEL32$GetProcessHeap

WINBASEAPI BOOL WINAPI KERNEL32$HeapFree (HANDLE, DWORD, PVOID);
#define HeapFree KERNEL32$HeapFree

WINBASEAPI int WINAPI SHELL32$SHGetFolderPathA (HWND, int, HANDLE, DWORD, LPSTR);
# define SHGetFolderPathA SHELL32$SHGetFolderPathA 

DECLSPEC_IMPORT char * __cdecl MSVCRT$strcat(char * __restrict__ _Dest,char * __restrict__ _Source);
# define strcat MSVCRT$strcat

WINBASEAPI size_t WINAPI MSVCRT$strlen(char* str);
# define strlen MSVCRT$strlen

WINBASEAPI char* WINAPI MSVCRT$strcpy(char* dest, const char* src);
// WINBASEAPI char* WINAPI MSVCRT$strcpy(char* dest, const char* src);
# define strcpy MSVCRT$strcpy

WINBASEAPI HANDLE WINAPI KERNEL32$FindFirstFileA(LPSTR, LPWIN32_FIND_DATAA);
# define FindFirstFileA KERNEL32$FindFirstFileA

WINBASEAPI BOOL WINAPI KERNEL32$FindNextFileA(HANDLE, LPWIN32_FIND_DATAA);
# define FindNextFileA KERNEL32$FindNextFileA

WINBASEAPI BOOL WINAPI KERNEL32$FindClose(HANDLE);
# define FindClose KERNEL32$FindClose

WINBASEAPI FILE* WINAPI MSVCRT$fopen(const char* filename, const char* mode);
# define fopen MSVCRT$fopen

WINBASEAPI size_t __cdecl MSVCRT$fread(void * _DstBuf, size_t _ElementSize, size_t _Count, FILE * _File);
# define fread MSVCRT$fread

WINBASEAPI int __cdecl MSVCRT$fclose(FILE *_File);
# define fclose MSVCRT$fclose

WINBASEAPI int __cdecl MSVCRT$fseek(FILE *_File, long _Offset, int _Origin);
# define fseek MSVCRT$fseek

WINBASEAPI long __cdecl MSVCRT$ftell(FILE *_File);
# define ftell MSVCRT$ftell

WINBASEAPI void *__cdecl MSVCRT$malloc(size_t _Size);
# define malloc MSVCRT$malloc

WINBASEAPI void __cdecl MSVCRT$free(void *_Memory);
# define free MSVCRT$free

WINBASEAPI int WINAPI MSVCRT$strcmp(const char* str1, const char* str2);
# define strcmp MSVCRT$strcmp

DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError(void);
# define GetLastError KERNEL32$GetLastError

WINBASEAPI int __cdecl MSVCRT$snprintf(char* buffer, size_t count, const char* format, ...);
# define snprintf MSVCRT$snprintf

WINBASEAPI int WINAPI MSVCRT$vsnprintf(char* buffer, size_t count, const char* format, va_list arg);
# define vsnprintf MSVCRT$vsnprintf

WINBASEAPI int __cdecl MSVCRT$_snprintf(char* buffer, size_t count, const char* format, ...);
# define _snprintf MSVCRT$_snprintf

WINBASEAPI int __cdecl MSVCRT$sprintf(char* buffer, const char* format, ...);
# define sprintf MSVCRT$sprintf

WINBASEAPI char* WINAPI MSVCRT$strstr(const char* haystack, const char* needle);
# define strstr MSVCRT$strstr

DECLSPEC_IMPORT PCHAR __cdecl MSVCRT$strchr(const char *haystack, int needle);
# define strchr MSVCRT$strchr

WINBASEAPI void __cdecl MSVCRT$memset(void *dest, int c, size_t count); 
# define memset MSVCRT$memset

WINBASEAPI char* WINAPI MSVCRT$strncpy(char* dest, const char* src, size_t count);
# define strncpy MSVCRT$strncpy

WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
# define CreateFileA KERNEL32$CreateFileA

WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
# define CloseHandle KERNEL32$CloseHandle

WINBASEAPI BOOL WINAPI KERNEL32$ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
# define ReadFile KERNEL32$ReadFile

WINBASEAPI DWORD WINAPI KERNEL32$GetFileSize(HANDLE, LPDWORD);
# define GetFileSize KERNEL32$GetFileSize

DECLSPEC_IMPORT BOOL WINAPI Crypt32$CryptUnprotectData(DATA_BLOB* pDataIn, LPWSTR* ppszDataDescr, DATA_BLOB* pOptionalEntropy, PVOID pvReserved, CRYPTPROTECT_PROMPTSTRUCT* pPromptStruct, DWORD dwFlags, DATA_BLOB* pDataOut);
# define CryptUnprotectData Crypt32$CryptUnprotectData

DECLSPEC_IMPORT HLOCAL WINAPI KERNEL32$LocalFree(HLOCAL);
# define LocalFree KERNEL32$LocalFree

WINBASEAPI int WINAPI Kernel32$WideCharToMultiByte(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL);
# define WideCharToMultiByte Kernel32$WideCharToMultiByte

// #else

#define intAlloc(size) KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define intFree(addr) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, addr)
// int WideCharToMultiByte(
//   [in]            UINT                               CodePage,
//   [in]            DWORD                              dwFlags,
//   [in]            _In_NLS_string_(cchWideChar)LPCWCH lpWideCharStr,
//   [in]            int                                cchWideChar,
//   [out, optional] LPSTR                              lpMultiByteStr,
//   [in]            int                                cbMultiByte,
//   [in, optional]  LPCCH                              lpDefaultChar,
//   [out, optional] LPBOOL                             lpUsedDefaultChar
// );

// WINBASEAPI HANDLE KERNEL32$GetProcessHeap(VOID);
// WINBASEAPI LPVOID KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
// WINBASEAPI BOOL KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
WINBASEAPI BOOL CRYPT32$CryptStringToBinaryA(LPCSTR, DWORD, DWORD, BYTE*, DWORD*, DWORD*, DWORD*);