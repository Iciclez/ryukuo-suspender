#include "inject.hpp"

#include <TlHelp32.h>
#include <algorithm>
#include <cwctype>
#include <thread>

/*
dword external_loadlibraryexw_function(inject::loadlibraryexw_parameter *parameter)
{
	return parameter->address(parameter->filename, parameter->file, parameter->flags) == 0;
}

//doubling the real function size, safer as compiler optimization may produce different code
size_t external_loadlibraryexw_function_size = 26 * 2;

dword external_loadlibraryexa_function(inject::loadlibraryexa_parameter *parameter)
{
	return parameter->address(parameter->filename, parameter->file, parameter->flags) == 0;
}

//doubling the real function size, safer as compiler optimization may produce different code
size_t external_loadlibraryexa_function_size = 26 * 2;

dword external_ldrloaddll_function_(inject::ldrloaddll_parameter *parameter)
{
	parameter->rtlinitunicodestring(parameter->module_filename, parameter->filename);
	return parameter->address(parameter->pathtofile, parameter->flags, parameter->module_filename, parameter->module_handle) != STATUS_SUCCESS;
}

//doubling the real function size, safer as compiler optimization may produce different code
size_t external_ldrloaddll_function_size = 42 * 2;
*/

extern "C"
{
	//dword external_loadlibraryex_function(inject::loadlibraryexw_parameter *parameter)
	//dword external_loadlibraryex_function(inject::loadlibraryexa_parameter *parameter)
	dword external_loadlibraryex_function(void* parameter);
	dword external_ldrloaddll_function(inject::ldrloaddll_parameter* parameter);
}

#ifdef _WIN64
size_t external_loadlibraryex_function_size = 36;
size_t external_ldrloaddll_function_size = 52;
#elif _WIN32
size_t external_loadlibraryex_function_size = 26;
size_t external_ldrloaddll_function_size = 43;
#endif

std::vector<dword> inject::get_process_id(const std::string & process_name)
{
	std::string process = process_name;
	std::transform(process.begin(), process.end(), process.begin(), std::tolower);

	std::vector<dword> process_id;

	HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 p = { 0 };

	p.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(h, &p))
	{
		while (Process32Next(h, &p))
		{
			std::string process32_executablefile(p.szExeFile);
			std::transform(process32_executablefile.begin(), process32_executablefile.end(), process32_executablefile.begin(), std::tolower);

			if (!process.compare(process32_executablefile))
			{
				process_id.push_back(p.th32ProcessID);
			}
		}
	}

	if (h)
	{
		CloseHandle(h);
	}

	return process_id;
}

inject::inject(injection_routine routine, injection_thread_function thread, bool freeze_processes, std::function<void(injection_error)> error_handler)
{
	this->routine = routine;
	this->thread = thread;
	this->freeze_processes = freeze_processes;
	this->error_handler = error_handler;

	this->generic_injection = [&](std::function<void(handle h)> injection_procedure) -> bool
	{
		for (const std::pair<dword, handle> &p : processes)
		{
			if (!p.first)
			{
				this->error_handler(injection_error::ERROR_INVALID_PROCESS_ID);
				return false;
			}

			if (p.second == INVALID_HANDLE_VALUE || p.second == 0)
			{
				this->error_handler(injection_error::ERROR_INVALID_PROCESS_HANDLE);
				return false;
			}

			injection_procedure(p.second);
		}

		return true;
	};
}

bool inject::get_handles()
{
	for (dword id : this->process_id)
	{
		this->processes[id] = OpenProcess(PROCESS_ALL_ACCESS, FALSE, id);
	}
	return true;
}

bool inject::createandhandleremotethread(handle h, const std::string & module_name, const std::string & function_name, lpvoid argument)
{
	handle thread = createremotethread(h, module_name, function_name, argument);
	if (!thread)
	{
		return false;
	}

	WaitForSingleObject(thread, 4000);

	return true;
}

bool inject::createandhandleremotethread(handle h, dword address, lpvoid argument)
{
	handle thread = createremotethread(h, address, argument);
	if (!thread)
	{
		return false;
	}

	WaitForSingleObject(thread, 4000);


	return true;
}

lpvoid inject::virtualallocex(handle h, int32_t size)
{
	return VirtualAllocEx(h, NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
}

bool inject::virtualfree(handle h, lpvoid memory_region)
{
	return VirtualFreeEx(h, memory_region, 0, MEM_RELEASE) != FALSE;
}

bool inject::writeprocessmemory(handle h, const std::string & dll, int32_t dll_size, lpvoid memory_region)
{
	SIZE_T written = 0;
	return (WriteProcessMemory(h, memory_region, dll.c_str(), dll_size, &written) != FALSE) &&
		static_cast<dword>(dll_size) == written;
}

bool inject::writeprocessmemory(handle h, const std::wstring & dll, int32_t dll_size, lpvoid memory_region)
{
	SIZE_T written = 0;
	return (WriteProcessMemory(h, memory_region, dll.c_str(), dll_size, &written) != FALSE) &&
		static_cast<dword>(dll_size) == written;
}

bool inject::writeprocessmemory(handle h, lpvoid memory, int32_t memory_size, lpvoid memory_region)
{
	SIZE_T written = 0;
	return (WriteProcessMemory(h, memory_region, memory, memory_size, &written) != FALSE) &&
		static_cast<dword>(memory_size) == written;
}

handle inject::createremotethread(handle h, dword address, lpvoid argument)
{
	switch (this->thread)
	{
	case injection_thread_function::CREATEREMOTETHREAD:
		return CreateRemoteThread(h, 0, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(address), argument, 0, 0);

	case injection_thread_function::CREATEREMOTETHREADEX:
		return CreateRemoteThreadEx(h, 0, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(address), argument, 0, 0, 0);

	case injection_thread_function::NTCREATETHREADEX:
	{
		typedef NTSTATUS(NTAPI * NtCreateThreadEx)(
			PHANDLE                 ThreadHandle,
			ACCESS_MASK             DesiredAccess,
			LPVOID                  ObjectAttributes,
			HANDLE                  ProcessHandle,
			LPTHREAD_START_ROUTINE  lpStartAddress,
			LPVOID                  lpParameter,
			BOOL                    CreateSuspended,
			DWORD                   dwStackSize,
			DWORD                   Unknown1,
			DWORD                   Unknown2,
			LPVOID                  Unknown3
			);

		handle remote_thread = 0;

		reinterpret_cast<NtCreateThreadEx>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateThreadEx"))
			(&remote_thread, GENERIC_ALL, NULL, h, reinterpret_cast<LPTHREAD_START_ROUTINE>(address), argument, 
				FALSE, NULL, NULL, NULL, NULL);

		return remote_thread;
	}
	case injection_thread_function::RTLCREATEUSERTHREAD:
	{
		typedef NTSTATUS(NTAPI * RtlCreateUserThread)(
			IN HANDLE               ProcessHandle,
			IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
			IN BOOLEAN              CreateSuspended,
			IN ULONG                StackZeroBits,
			IN OUT PULONG           StackReserved,
			IN OUT PULONG           StackCommit,
			IN PVOID                StartAddress,
			IN PVOID                StartParameter OPTIONAL,
			OUT PHANDLE             ThreadHandle,
			OUT CLIENT_ID *         ClientID
			);

		handle remote_thread = 0;
		CLIENT_ID client_id = { 0 };

		reinterpret_cast<RtlCreateUserThread>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlCreateUserThread"))
			(h, 0, FALSE, 0, 0, 0, reinterpret_cast<lpvoid>(address), argument,
				&remote_thread, &client_id);

		return remote_thread;
	}
	}

	return 0;
}

handle inject::createremotethread(handle h, const std::string &module_name, const std::string &function_name, lpvoid argument)
{
	return createremotethread(h, reinterpret_cast<dword>(GetProcAddress(GetModuleHandle(module_name.c_str()), function_name.c_str())), argument);
}

bool inject::waitforsingleobject(handle h)
{
	std::thread([h]()
	{
		WaitForSingleObject(h, INFINITE);

		if (h)
		{
			CloseHandle(h);
		}

	}).detach();
}


handle inject::createfile(const std::string & file)
{
	return CreateFileA(file.c_str(), GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
}

bool inject::closehandle(handle h)
{
	if (h)
	{
		return CloseHandle(h) != FALSE;
	}
	return true;
}

dword inject::getfilesize(handle h)
{
	return GetFileSize(h, 0);
}

lpvoid inject::heapalloc(dword size)
{
	return HeapAlloc(GetProcessHeap(), 0, size);
}

bool inject::heapfree(lpvoid memory)
{
	if (memory)
	{
		return HeapFree(GetProcessHeap(), 0, memory) != FALSE;
	}

	return true;
}

bool inject::readfile(handle h, lpvoid memory, dword filesize)
{
	dword read = 0;
	return ReadFile(h, memory, filesize, &read, 0) != FALSE;
}

dword inject::getdllmain(lpvoid memory, platform platform_type)
{
	uint32_t address = reinterpret_cast<uint32_t>(memory);
	uint32_t export_dir = address + reinterpret_cast<PIMAGE_DOS_HEADER>(address)->e_lfanew;

	switch ((reinterpret_cast<PIMAGE_NT_HEADERS>(export_dir))->OptionalHeader.Magic) 
	{
		//PE32
	case 0x010B:
		if (platform_type != platform::x86)
			return 0;
		break;

		//PE64
	case 0x020B:
		if (platform_type != platform::x64)
			return 0;
		break;

		//NEITHER
	default:
		return 0;

	}

	std::function<dword(dword, uint32_t)> rva_to_offset = [](dword rva, uint32_t base_address) -> dword 
	{
		PIMAGE_NT_HEADERS nt_header = reinterpret_cast<PIMAGE_NT_HEADERS>(base_address + ((PIMAGE_DOS_HEADER)base_address)->e_lfanew);
		PIMAGE_SECTION_HEADER section_header = reinterpret_cast<PIMAGE_SECTION_HEADER>(reinterpret_cast<uint32_t>(&nt_header->OptionalHeader) + nt_header->FileHeader.SizeOfOptionalHeader);


		if (rva < section_header[0].PointerToRawData) 
		{
			return rva;
		}

		for (uint16_t i = 0; i < nt_header->FileHeader.NumberOfSections; i++) 
		{
			if (rva >= section_header[i].VirtualAddress &&
				rva < (section_header[i].VirtualAddress + section_header[i].SizeOfRawData)) 
			{
				return (rva - section_header[i].VirtualAddress + section_header[i].PointerToRawData);
			}
		}

		return static_cast<dword>(0);

	};

	export_dir = address + rva_to_offset((reinterpret_cast<PIMAGE_DATA_DIRECTORY>(reinterpret_cast<dword>(&(reinterpret_cast<PIMAGE_NT_HEADERS>(export_dir))->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT])))->VirtualAddress, address);

	dword name_array = address + rva_to_offset(reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(export_dir)->AddressOfNames, address);;
	dword name_ordinals = address + rva_to_offset(reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(export_dir)->AddressOfNameOrdinals, address);
	dword i = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(export_dir)->NumberOfNames;

	while (i--) 
	{
		if (strstr(reinterpret_cast<char*>(address + rva_to_offset(*reinterpret_cast<dword*>(name_array), address)), "DllMain") != NULL) 
		{
			return rva_to_offset(*reinterpret_cast<dword*>(address + rva_to_offset(reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(export_dir)->AddressOfFunctions, address) + (*reinterpret_cast<word*>(name_ordinals) * sizeof(DWORD))), address);
		}
		name_array += sizeof(dword);
		name_ordinals += sizeof(word);
	}

	return 0;
}

inject::inject(const std::string & process_name, injection_routine routine, injection_thread_function thread, bool freeze, std::function<void(injection_error)> error_handler)
	: inject(routine, thread, freeze, error_handler)
{
	this->process_id = get_process_id(process_name);
	this->get_handles();
}

inject::inject(hwnd window, injection_routine routine, injection_thread_function thread, bool freeze, std::function<void(injection_error)> error_handler)
	: inject(routine, thread, freeze, error_handler)
{
	dword id = 0;
	GetWindowThreadProcessId(window, &id);
	this->process_id.push_back(id);
	this->get_handles();
}

inject::inject(dword process_id, injection_routine routine, injection_thread_function thread, bool freeze, std::function<void(injection_error)> error_handler)
	: inject(routine, thread, freeze, error_handler)
{
	this->process_id.push_back(process_id);
	this->get_handles();
}

inject::~inject()
{
	for (const std::pair<const dword, handle> &process : processes)
	{
		if (process.second)
		{
			CloseHandle(process.second);
		}
	}
}

bool inject::inject_dll(const std::vector<std::string>& dll_list)
{
	if (dll_list.empty())
	{
		return true;
	}

	this->suspend();

	bool result = this->generic_injection([&](handle h)
	{
		if (this->routine == injection_routine::LOADLIBRARYA || this->routine == injection_routine::LOADLIBRARYEXA)
		{
			for (const std::string & dll : dll_list)
			{
				int32_t dll_size = dll.size() + 1;

				lpvoid allocated_memory_region = virtualallocex(h, dll_size);
				if (!allocated_memory_region)
				{
					continue;
				}

				//start

				do
				{
					if (!writeprocessmemory(h, dll, dll_size, allocated_memory_region))
					{
						break;
					}

					if (this->routine == injection_routine::LOADLIBRARYA)
					{
						if (!createandhandleremotethread(h, "kernelbase.dll", "LoadLibraryA", allocated_memory_region))
						{
							break;
						}
					}
					else if (this->routine == injection_routine::LOADLIBRARYEXA)
					{
						loadlibraryexa_parameter parameter;
						parameter.address = reinterpret_cast<loadlibraryexa_t>(GetProcAddress(GetModuleHandleW(L"kernelbase.dll"), "LoadLibraryExA"));
						parameter.filename = reinterpret_cast<char*>(allocated_memory_region);
						parameter.file = 0;
						parameter.flags = 0;

						lpvoid function_allocated_memory_region = virtualallocex(h, external_loadlibraryex_function_size);
						lpvoid parameter_allocated_memory_region = virtualallocex(h, sizeof(loadlibraryexa_parameter));
						do
						{
							if (!writeprocessmemory(h, external_loadlibraryex_function, external_loadlibraryex_function_size, function_allocated_memory_region) ||
								!writeprocessmemory(h, &parameter, sizeof(loadlibraryexa_parameter), parameter_allocated_memory_region))
							{
								break;
							}

							if (!createandhandleremotethread(h, reinterpret_cast<dword>(function_allocated_memory_region), parameter_allocated_memory_region))
							{
								break;
							}

						} while (false);


						if (function_allocated_memory_region)
						{
							virtualfree(h, function_allocated_memory_region);
						}

						if (parameter_allocated_memory_region)
						{
							virtualfree(h, parameter_allocated_memory_region);
						}

						break;
					}

				} while (false);



				//end

				if (allocated_memory_region)
				{
					virtualfree(h, allocated_memory_region);
				}
			}
		}
		else if (this->routine == injection_routine::LOADLIBRARYW || this->routine == injection_routine::LOADLIBRARYEXW || this->routine == injection_routine::LDRLOADDLL)
		{
			for (const std::string & _dll : dll_list)
			{
				std::wstring dll(_dll.begin(), _dll.end());
				int32_t dll_size = dll.size() * 2 + 1;

				lpvoid allocated_memory_region = virtualallocex(h, dll_size);
				if (!allocated_memory_region)
				{
					continue;
				}

				//start

				do
				{
					if (!writeprocessmemory(h, dll, dll_size, allocated_memory_region))
					{
						break;
					}

					if (this->routine == injection_routine::LOADLIBRARYW)
					{
						if (!createandhandleremotethread(h, "kernelbase.dll", "LoadLibraryW", allocated_memory_region))
						{
							break;
						}
					}
					else if (this->routine == injection_routine::LOADLIBRARYEXW)
					{
						loadlibraryexw_parameter parameter;
						parameter.address = reinterpret_cast<loadlibraryexw_t>(GetProcAddress(GetModuleHandleW(L"kernelbase.dll"), "LoadLibraryExW"));
						parameter.filename = reinterpret_cast<wchar_t*>(allocated_memory_region);
						parameter.file = 0;
						parameter.flags = 0;

						lpvoid function_allocated_memory_region = virtualallocex(h, external_loadlibraryex_function_size);
						lpvoid parameter_allocated_memory_region = virtualallocex(h, sizeof(loadlibraryexw_parameter));
						do
						{
							if (!writeprocessmemory(h, external_loadlibraryex_function, external_loadlibraryex_function_size, function_allocated_memory_region) ||
								!writeprocessmemory(h, &parameter, sizeof(loadlibraryexw_parameter), parameter_allocated_memory_region))
							{
								break;
							}

							if (!createandhandleremotethread(h, reinterpret_cast<dword>(function_allocated_memory_region), parameter_allocated_memory_region))
							{
								break;
							}

						} while (false);


						if (function_allocated_memory_region)
						{
							virtualfree(h, function_allocated_memory_region);
						}

						if (parameter_allocated_memory_region)
						{
							virtualfree(h, parameter_allocated_memory_region);
						}

						break;
					}
					else if (this->routine == injection_routine::LDRLOADDLL)
					{
						lpvoid handle_allocated_memory_region = virtualallocex(h, sizeof(handle));
						lpvoid unicode_string_allocated_memory_region = virtualallocex(h, sizeof(UNICODE_STRING));

						ldrloaddll_parameter parameter;
						parameter.address = reinterpret_cast<ldrloaddll_t>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "LdrLoadDll"));
						parameter.rtlinitunicodestring = reinterpret_cast<rtlinitunicodestring_t>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlInitUnicodeString"));
						parameter.filename = reinterpret_cast<wchar_t*>(allocated_memory_region);

						parameter.pathtofile = 0;
						parameter.flags = 0;
						parameter.module_filename = reinterpret_cast<UNICODE_STRING*>(unicode_string_allocated_memory_region);
						parameter.module_handle = reinterpret_cast<handle*>(handle_allocated_memory_region);

						lpvoid function_allocated_memory_region = virtualallocex(h, external_ldrloaddll_function_size);
						lpvoid parameter_allocated_memory_region = virtualallocex(h, sizeof(ldrloaddll_parameter));
						do
						{

							if (!writeprocessmemory(h, external_ldrloaddll_function, external_ldrloaddll_function_size, function_allocated_memory_region) ||
								!writeprocessmemory(h, &parameter, sizeof(ldrloaddll_parameter), parameter_allocated_memory_region))
							{
								break;
							}

							if (!createandhandleremotethread(h, reinterpret_cast<dword>(function_allocated_memory_region), parameter_allocated_memory_region))
							{
								break;
							}

						} while (false);


						if (function_allocated_memory_region)
						{
							virtualfree(h, function_allocated_memory_region);
						}

						if (parameter_allocated_memory_region)
						{
							virtualfree(h, parameter_allocated_memory_region);
						}

						if (unicode_string_allocated_memory_region)
						{
							virtualfree(h, unicode_string_allocated_memory_region);
						}

						if (handle_allocated_memory_region)
						{
							virtualfree(h, handle_allocated_memory_region);
						}

						break;
					}

				} while (false);

				//end

				if (allocated_memory_region)
				{
					virtualfree(h, allocated_memory_region);
				}
			}
		}
	});

	this->resume();

	return result;
}

bool inject::map_dll(const std::vector<std::string>& dll_list)
{
	if (dll_list.empty())
	{
		return true;
	}

	this->suspend();

	bool result = this->generic_injection([&](handle h)
	{
		for (const std::string &dll : dll_list)
		{
			handle hdll = createfile(dll);
			if (hdll)
			{
				continue;
			}

			dword filesize = getfilesize(hdll);
			lpvoid memory = heapalloc(filesize);


			//start
			do
			{
				//fill memory with the bytes from the file
				if (!readfile(hdll, memory, filesize))
				{
					break;
				}

				dword dllmain = getdllmain(memory);
				if (!dllmain)
				{
					this->error_handler(injection_error::ERROR_DLL_MAPPING_UNSUPPORTED);
					break;
				}

				lpvoid allocated_memory_region = virtualallocex(h, filesize);
				if (!allocated_memory_region)
				{
					break;
				}

				//start
				do
				{
					//write heapmemory to external memory
					if (!writeprocessmemory(h, memory, filesize, allocated_memory_region))
					{
						break;
					}

					if (!createandhandleremotethread(h, reinterpret_cast<dword>(memory) + dllmain, allocated_memory_region))
					{
						break;
					}
				} while (false);

				//end
				if (allocated_memory_region)
				{
					virtualfree(h, allocated_memory_region);
				}

			} while (false);

			//end
			heapfree(memory);
			closehandle(hdll);
		}
	});

	this->resume();

	return result;
}

bool inject::suspend()
{
	if (!this->freeze_processes)
	{
		return false;
	}

	bool result = true;

	for (const std::pair<dword, handle> &p : processes)
	{
		result &= inject::suspend(p.second);
	}

	return result;
}

bool inject::resume()
{
	if (!this->freeze_processes)
	{
		return false;
	}

	bool result = true;

	for (const std::pair<dword, handle> &p : processes)
	{
		result &= inject::resume(p.second);
	}
	
	return result;
}

bool inject::suspend(handle process_handle)
{
	typedef NTSTATUS(NTAPI *ntsuspendprocess_t)(IN HANDLE);
	
	return reinterpret_cast<ntsuspendprocess_t>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSuspendProcess"))
		(process_handle) == STATUS_SUCCESS;
}

bool inject::resume(handle process_handle)
{
	typedef NTSTATUS(NTAPI *ntresumeprocess_t)(IN HANDLE);

	return reinterpret_cast<ntresumeprocess_t>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtResumeProcess"))
		(process_handle) == STATUS_SUCCESS;
}
