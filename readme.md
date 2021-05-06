# RemotePointer

a lib for reading/writing other process on Windows platform

example:

```cpp
#include "RemotePointer.h"

int main()
{
	DWORD pid = ProcessName2Pid(L"explorer.exe");
	remote_ptr<IMAGE_DOS_HEADER> p(pid);
	p = (intptr_t)GetModuleHandle(L"kernel32.dll");
	char buffer[4] = { 0 };
	*(WORD*)buffer = p->e_magic;
	std::cout << buffer << std::endl;

	return 0;
}
//output:MZ
```

