#include <iostream>
#include "RemotePointer.h"
#include <TlHelp32.h>
DWORD ProcessName2Pid(std::wstring ProcessName)
{
	bool FoundPID = false;
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(pe32);
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	DWORD pid = -1;
	if (hProcessSnap == INVALID_HANDLE_VALUE) {
		std::cout << "CreateToolhelp32Snapshot Error!" << std::endl;;
		return false;
	}
	bool bResult = Process32First(hProcessSnap, &pe32);
	while (bResult)
	{
		if (_wcsicmp(pe32.szExeFile, ProcessName.c_str()) == 0)
		{
			FoundPID = true;
			//printf("ProcessName: %s \n", ProcessName.c_str());
			pid = pe32.th32ProcessID;
		}
		bResult = Process32Next(hProcessSnap, &pe32);
	}
	CloseHandle(hProcessSnap);
	return pid;
}


#define ASSERT(x) if(!(x)){__debugbreak();}

int main()
{
	DWORD pid = ProcessName2Pid(L"explorer.exe");
	remote_ptr<IMAGE_DOS_HEADER> p(pid);
	p = (intptr_t)GetModuleHandle(L"kernel32.dll");
	remote_ptr<IMAGE_DOS_HEADER> p1(pid, (intptr_t)GetModuleHandle(L"kernel32.dll"));
	std::shared_ptr<void> pHandle = std::shared_ptr<void>(NULL, CloseHandle);

	ASSERT(p == p1);
	sizeof(IMAGE_DOS_HEADER);
	char buffer[4] = { 0 };
	*(WORD*)buffer = p->e_magic;
	std::cout << buffer << std::endl;
	remote_ptr<IMAGE_NT_HEADERS> pNt = p + p->e_lfanew;


	*(WORD*)buffer = pNt->Signature;
	std::cout << buffer << std::endl;
	remote_ptr<void, 0x40>p3(pid);
	p3 = p;
	p3 = p3 + 1;
	remote_ptr<WORD>p4(pid);
	p4 = p;
	std::cout << std::hex << *p4 << std::endl;


	*p4 = 0x5b4d;
	p4.write_force();
	p4.update();
	std::cout << std::hex << *p4 << std::endl;

	p4 = p3;


	return 0;
}
