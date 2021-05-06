#pragma once
#include <exception>
#include <Windows.h>
inline HANDLE OpenProcessVm(DWORD pid)
{
	return OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, pid);
}
template <typename T, int num = 1>
class remote_ptr :public remote_ptr<void, sizeof(T)* num>
{
public:
	template<typename T2, int num2 = 1> remote_ptr(const remote_ptr<T2, num2>& rp)
		:remote_ptr<void, sizeof(T)* num>(rp) {}
	remote_ptr(HANDLE hProcess)
		:remote_ptr<void, sizeof(T)* num>(hProcess) {}
	remote_ptr(HANDLE hProcess, intptr_t addr)
		:remote_ptr<void, sizeof(T)* num>(hProcess, addr) {}
	remote_ptr(DWORD dwPid)
		:remote_ptr<void, sizeof(T)* num>(dwPid) {}
	remote_ptr(DWORD dwPid, intptr_t addr)
		:remote_ptr<void, sizeof(T)* num>(dwPid, addr) {}
	T& operator[](intptr_t);
	T& operator *();
	T* operator ->();
	T& operator =(intptr_t address);

	template<typename T2, int num2 = 1>T& operator =(const remote_ptr<T2, num2>& p);
	remote_ptr<T, num> operator +(intptr_t offset);
};

template<typename T, int num>
T& remote_ptr<T, num>::operator[](intptr_t offset)
{
	size_t size;
	if (!ReadProcessMemory(this->hProcess, (LPCVOID)(remote_ptr<void, sizeof(T) * num>::baseAddr + offset), remote_ptr<void, sizeof(T) * num>::pBufferOffset, sizeof(T) * num, &size))
	{
		throw std::exception("memory access failed");
	}
	return *(T*)remote_ptr<void, sizeof(T)* num>::pBufferOffset;
}

template<typename T, int num>
T& remote_ptr<T, num>::operator *()
{
	return *(T*)(remote_ptr<void, sizeof(T)* num>::pBuffer.get());
}

template<typename T, int num>
T* remote_ptr<T, num>::operator ->()
{
	return (T*)(remote_ptr<void, sizeof(T)* num>::pBuffer.get());
}

template<typename T, int num>
T& remote_ptr<T, num>::operator=(intptr_t address)
{
	remote_ptr<void, sizeof(T)* num>::baseAddr = address;
	size_t size;
	if (!ReadProcessMemory(remote_ptr<void, sizeof(T) * num>::hProcess.get(), (LPCVOID)remote_ptr<void, sizeof(T) * num>::baseAddr, remote_ptr<void, sizeof(T) * num>::pBuffer.get(), sizeof(T) * num, &size))
	{
		DWORD dwErrCode = GetLastError();
		throw std::exception("memory access failed");
	}
	return *(T*)(remote_ptr<void, sizeof(T)* num>::pBuffer.get());
}
template<typename T, int num>
template<typename T2, int num2>T& remote_ptr<T, num>::operator =(const remote_ptr<T2, num2>& rp)
{
	if (num <= num2 * sizeof(T2))
	{
		remote_ptr<void, sizeof(T)* num>::pBuffer = rp.pBuffer;
		remote_ptr<void, sizeof(T)* num>::pBufferOffset = rp.pBufferOffset;
		remote_ptr<void, sizeof(T)* num>::hProcess = rp.hProcess;
		remote_ptr<void, sizeof(T)* num>::baseAddr = rp.baseAddr;
		remote_ptr<void, sizeof(T)* num>::bufferSize = num;
	}
	else
	{
		remote_ptr<void, sizeof(T)* num>::hProcess = rp.hProcess;
		remote_ptr<void, sizeof(T)* num>::pBufferOffset.reset(operator new(num));
		remote_ptr<void, sizeof(T)* num>::pBuffer.reset(operator new(num));
		remote_ptr<void, sizeof(T)* num>::baseAddr = rp.baseAddr;
		remote_ptr<void, sizeof(T)* num>::bufferSize = num;
		size_t size;
		if (!ReadProcessMemory(this->hProcess.get(), (LPCVOID)remote_ptr<void, sizeof(T) * num>::baseAddr, remote_ptr<void, sizeof(T) * num>::pBuffer.get(), sizeof(T) * num, &size))
		{
			DWORD dwErrCode = GetLastError();
			throw std::exception("memory access failed");
		}
	}
	return *(T*)(remote_ptr<void, sizeof(T)* num>::pBuffer.get());

}
template<typename T, int num>
remote_ptr<T, num> remote_ptr<T, num>::operator +(intptr_t offset)
{
	return remote_ptr<T, num>(remote_ptr<void, sizeof(T)* num>::hProcess.get(), remote_ptr<void, sizeof(T)* num>::baseAddr + offset);
}

//void partial specialization 
template <int num>
class remote_ptr<void, num>
{
public:
	std::shared_ptr<void> pBuffer;
	std::shared_ptr<void> pBufferOffset;
	std::shared_ptr<void> hProcess;
	//HANDLE hProcess = NULL;
	size_t bufferSize = 0;
	intptr_t baseAddr = 0;

	template<typename T2, int num2> remote_ptr(const remote_ptr<T2, num2>& rp);
	remote_ptr(HANDLE hProcess);
	remote_ptr(HANDLE hProcess, intptr_t addr);
	remote_ptr(DWORD dwPid);
	remote_ptr(DWORD dwPid, intptr_t addr);
	~remote_ptr();
	void operator =(intptr_t address);
	template<typename T2, int num2>void operator =(const remote_ptr<T2, num2>& p);
	remote_ptr<void, num> operator +(intptr_t offset);
	template<typename T2, int num2> bool operator ==(const remote_ptr<T2, num2>& rp);
	BOOL update();
	BOOL write();
	BOOL write_force();
};
template<int num>
BOOL remote_ptr<void, num>::update()
{
	size_t readNum;
	return ReadProcessMemory(hProcess.get(), (LPCVOID)baseAddr, pBuffer.get(), bufferSize, &readNum);
}

template<int num>
BOOL remote_ptr<void, num>::write()
{
	size_t writeNum;
	return WriteProcessMemory(hProcess.get(), (LPVOID)baseAddr, pBuffer.get(), bufferSize, &writeNum);
}
template<int num>
BOOL remote_ptr<void, num>::write_force()
{
	BOOL ret = FALSE;
	DWORD dwOldProtect = 0;
	size_t writeNum;
	ret = VirtualProtect((LPVOID)baseAddr, bufferSize, PAGE_READWRITE, &dwOldProtect);
	if (!ret)
	{
		return ret;
	}
	ret = WriteProcessMemory(hProcess.get(), (LPVOID)baseAddr, pBuffer.get(), bufferSize, &writeNum);
	VirtualProtect((LPVOID)baseAddr, bufferSize, dwOldProtect, &dwOldProtect);
	return ret;
}

template <int num>
template<typename T2, int num2>
bool remote_ptr<void, num>::operator ==(const remote_ptr<T2, num2>& rp)
{
	return (this->baseAddr == rp.baseAddr) ? true : false;
	//return ((this->baseAddr == rp.baseAddr) && (this->hProcess == rp.hProcess)) ? true : false;

}
template <int num>
template<typename T2, int num2> remote_ptr<void, num>::remote_ptr(const remote_ptr<T2, num2>& rp)
{
	if (num <= num2 * sizeof(T2))
	{
		pBuffer = rp.pBuffer;
		pBufferOffset = rp.pBufferOffset;
		hProcess = rp.hProcess;
		baseAddr = rp.baseAddr;
		bufferSize = rp.bufferSize;
	}
	else
	{
		hProcess = rp.hProcess;
		pBufferOffset.reset(operator new(num));
		pBuffer.reset(operator new(num));
		baseAddr = rp.baseAddr;
		bufferSize = num;
		size_t size;
		if (!ReadProcessMemory(this->hProcess.get(), (LPCVOID)baseAddr, pBuffer.get(), num, &size))
		{
			DWORD dwErrCode = GetLastError();
			throw std::exception("memory access failed");
		}
	}
}
template<int num>
remote_ptr<void, num>::remote_ptr(HANDLE hProcess)
{
	this->hProcess = std::shared_ptr<void>(hProcess, CloseHandle);
	pBufferOffset.reset(operator new(num));
	pBuffer.reset(operator new(num));
	bufferSize = num;
}

template<int num>
remote_ptr<void, num>::remote_ptr(HANDLE hProcess, intptr_t addr)
{
	this->hProcess = std::shared_ptr<void>(hProcess, CloseHandle);
	pBufferOffset.reset(operator new(num));
	pBuffer.reset(operator new(num));
	baseAddr = addr;
	bufferSize = num;
	size_t size;
	if (!ReadProcessMemory(this->hProcess.get(), (LPCVOID)baseAddr, pBuffer.get(), num, &size))
	{
		DWORD dwErrCode = GetLastError();
		throw std::exception("memory access failed");
	}
}


template<int num>
remote_ptr<void, num>::remote_ptr(DWORD dwPid)
{
	hProcess = std::shared_ptr<void>(OpenProcessVm(dwPid), CloseHandle);
	//hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, dwPid);
	if (!hProcess)
	{
		throw std::exception("open process error");
	}
	pBufferOffset.reset(operator new(num));
	pBuffer.reset(operator new(num));
	bufferSize = num;
}

template<int num>
remote_ptr<void, num>::remote_ptr(DWORD dwPid, intptr_t addr)
{
	hProcess = std::shared_ptr<void>(OpenProcessVm(dwPid), CloseHandle);
	if (!hProcess)
	{
		throw std::exception("open process error");
	}
	pBufferOffset.reset(operator new(num));
	pBuffer.reset(operator new(num));
	bufferSize = num;
	baseAddr = addr;
	size_t size;
	if (!ReadProcessMemory(this->hProcess.get(), (LPCVOID)baseAddr, pBuffer.get(), num, &size))
	{
		DWORD dwErrCode = GetLastError();
		throw std::exception("memory access failed");
	}
}

template<int num>
remote_ptr<void, num>::~remote_ptr()
{
}


template<int num>
void remote_ptr<void, num>::operator=(intptr_t address)
{
	baseAddr = address;
	size_t size;
	if (!ReadProcessMemory(this->hProcess.get(), (LPCVOID)baseAddr, pBuffer.get(), num, &size))
	{
		DWORD dwErrCode = GetLastError();
		throw std::exception("memory access failed");
	}
	//return *(T*)pBuffer;
	return;
}
template<int num>
template<typename T2, int num2> void remote_ptr<void, num>::operator =(const remote_ptr<T2, num2>& rp)
{
	if (num <= num2 * sizeof(T2))
	{
		pBuffer = rp.pBuffer;
		pBufferOffset = rp.pBufferOffset;
		hProcess = rp.hProcess;
		baseAddr = rp.baseAddr;
		bufferSize = num;
	}
	else
	{
		hProcess = rp.hProcess;
		pBufferOffset.reset(operator new(num));
		pBuffer.reset(operator new(num));
		baseAddr = rp.baseAddr;
		bufferSize = num;
		size_t size;
		if (!ReadProcessMemory(this->hProcess.get(), (LPCVOID)baseAddr, pBuffer.get(), num, &size))
		{
			DWORD dwErrCode = GetLastError();
			throw std::exception("memory access failed");
		}
	}
	return;

}
template<int num>
remote_ptr<void, num> remote_ptr<void, num>::operator +(intptr_t offset)
{
	return remote_ptr<void, num>(hProcess.get(), baseAddr + offset);
}
