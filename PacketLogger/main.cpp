
#include <windows.h>
#include <tlhelp32.h>
#include <shlwapi.h>
#include <conio.h>
#include <stdio.h>
#pragma comment(lib, "Shlwapi.lib")

#define WIN32_LEAN_AND_MEAN
#define CREATE_THREAD_ACCESS (PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ)

DWORD GetTargetThreadIDFromProcName(const char * ProcName)
{
  PROCESSENTRY32 pe;
  HANDLE thSnapShot;
  BOOL retval, ProcFound = false;

  thSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if(thSnapShot == INVALID_HANDLE_VALUE)
  {
     printf("Error: Unable to create toolhelp snapshot!");
     return false;
  }

  pe.dwSize = sizeof(PROCESSENTRY32);
   
  retval = Process32First(thSnapShot, &pe);
  while(retval)
  {
     if(StrStrI(pe.szExeFile, ProcName))
     {
        return pe.th32ProcessID;
     }
     retval = Process32Next(thSnapShot, &pe);
  }
  return 0;
}
BOOL Inject(DWORD pID, const char * DLL_NAME)
{
  HANDLE Proc;
  HMODULE hLib;
  char buf[50] = {0};
  LPVOID RemoteString, LoadLibAddy;

  if(!pID)
     return false;

  Proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pID);
  if(!Proc)
  {
     sprintf(buf, "OpenProcess() failed: %d", GetLastError());
     printf(buf);
     return false;
  }
   
  LoadLibAddy = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

  // Allocate space in the process for our DLL
  RemoteString = (LPVOID)VirtualAllocEx(Proc, NULL, strlen(DLL_NAME), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

  // Write the string name of our DLL in the memory allocated
  WriteProcessMemory(Proc, (LPVOID)RemoteString, DLL_NAME, strlen(DLL_NAME), NULL);

  // Load our DLL
  CreateRemoteThread(Proc, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibAddy, (LPVOID)RemoteString, NULL, NULL);

  CloseHandle(Proc);
  return true;
}


int main()
{
  // Retrieve process ID
  DWORD pID = GetTargetThreadIDFromProcName("WAR.exe");
   
  // Get the dll's full path name
  char buf[MAX_PATH] = {0};
  GetFullPathName("WarSniffer.dll", MAX_PATH, buf, NULL);
  printf(buf);
  printf("\n");
   
  // Inject our main dll
  if(!Inject(pID, buf))
  {

       printf("DLL Not Loaded!");
   }else{
       printf("DLL Loaded!");
   }


  return 0;
}

