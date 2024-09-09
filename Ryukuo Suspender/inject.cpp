#include "inject.hpp"

#include <TlHelp32.h>
#include <algorithm>
#include <cwctype>
#include <fstream>
#include <thread>


/*
DWORD external_loadlibraryexw_function(inject::loadlibraryexw_parameter *parameter)
{
	return parameter->address(parameter->filename, parameter->file, parameter->flags) == 0;
}

//doubling the real function size, safer as compiler optimization may produce different code
size_t external_loadlibraryexw_function_size = 26 * 2;

DWORD external_loadlibraryexa_function(inject::loadlibraryexa_parameter *parameter)
{
	return parameter->address(parameter->filename, parameter->file, parameter->flags) == 0;
}

//doubling the real function size, safer as compiler optimization may produce different code
size_t external_loadlibraryexa_function_size = 26 * 2;

DWORD external_ldrloaddll_function_(inject::ldrloaddll_parameter *parameter)
{
	parameter->rtlinitunicodestring(parameter->module_filename, parameter->filename);
	return parameter->address(parameter->pathtofile, parameter->flags, parameter->module_filename, parameter->module_handle) != STATUS_SUCCESS;
}

//doubling the real function size, safer as compiler optimization may produce different code
size_t external_ldrloaddll_function_size = 42 * 2;
*/

extern "C"
{
	//DWORD external_loadlibraryex_function(inject::loadlibraryexw_parameter *parameter)
	//DWORD external_loadlibraryex_function(inject::loadlibraryexa_parameter *parameter)
	DWORD external_loadlibraryex_function(void* parameter);
	DWORD external_ldrloaddll_function(inject::ldrloaddll_parameter* parameter);
}

#ifdef _WIN64
size_t external_loadlibraryex_function_size = 36;
size_t external_ldrloaddll_function_size = 52;
#elif _WIN32
size_t external_loadlibraryex_function_size = 26;
size_t external_ldrloaddll_function_size = 43;
#endif

std::vector<DWORD> inject::get_process_id(const std::string& process_name)
{
	std::string process = process_name;
	std::transform(process.begin(), process.end(), process.begin(), std::tolower);

	std::vector<DWORD> process_id;

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

	this->generic_injection = [&](std::function<void(HANDLE h)> injection_procedure) -> bool
		{
			for (const std::pair<DWORD, HANDLE>& p : processes)
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

void inject::get_handles()
{
	for (DWORD id : this->process_id)
	{
		this->processes[id] = OpenProcess(PROCESS_ALL_ACCESS, FALSE, id);
	}
}

void inject::with_remote_virtual_memory(HANDLE handle, uintptr_t size, const std::function<void(void*)>& function, const void* value_at_remote_memory)
{
	void* remote_address = VirtualAllocEx(handle, NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (remote_address)
	{
		if (value_at_remote_memory != nullptr)
		{
			DWORD bytes_written = 0;
			WriteProcessMemory(handle, remote_address, value_at_remote_memory, size, &bytes_written);
		}
		function(remote_address);
		VirtualFreeEx(handle, remote_address, 0, MEM_RELEASE);
	}
}

bool inject::remote_call(HANDLE h, const std::string& module_name, const std::string& function_name, void* argument)
{
	HANDLE thread = remote_thread(h, reinterpret_cast<DWORD>(GetProcAddress(GetModuleHandle(module_name.c_str()), function_name.c_str())), argument);
	if (!thread)
	{
		return false;
	}

	WaitForSingleObject(thread, 4000);
	return true;
}

bool inject::remote_call(HANDLE h, DWORD address, void* argument)
{
	HANDLE thread = remote_thread(h, address, argument);
	if (!thread)
	{
		return false;
	}

	WaitForSingleObject(thread, 4000);
	return true;
}

HANDLE inject::remote_thread(HANDLE h, DWORD address, void* argument)
{
	switch (this->thread)
	{
	case injection_thread_function::CREATEREMOTETHREAD:
		return CreateRemoteThread(h, 0, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(address), argument, 0, 0);

	case injection_thread_function::CREATEREMOTETHREADEX:
		return CreateRemoteThreadEx(h, 0, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(address), argument, 0, 0, 0);

	case injection_thread_function::NTCREATETHREADEX:
	{
		typedef NTSTATUS(NTAPI* NtCreateThreadEx)(
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

		HANDLE remote_thread = 0;

		reinterpret_cast<NtCreateThreadEx>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateThreadEx"))
			(&remote_thread, GENERIC_ALL, NULL, h, reinterpret_cast<LPTHREAD_START_ROUTINE>(address), argument,
				FALSE, NULL, NULL, NULL, NULL);

		return remote_thread;
	}
	case injection_thread_function::RTLCREATEUSERTHREAD:
	{
		typedef NTSTATUS(NTAPI* RtlCreateUserThread)(
			IN HANDLE               ProcessHandle,
			IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
			IN BOOLEAN              CreateSuspended,
			IN ULONG                StackZeroBits,
			IN OUT PULONG           StackReserved,
			IN OUT PULONG           StackCommit,
			IN PVOID                StartAddress,
			IN PVOID                StartParameter OPTIONAL,
			OUT PHANDLE             ThreadHandle,
			OUT CLIENT_ID* ClientID
			);

		HANDLE remote_thread = 0;
		CLIENT_ID client_id = { 0 };

		reinterpret_cast<RtlCreateUserThread>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlCreateUserThread"))
			(h, 0, FALSE, 0, 0, 0, reinterpret_cast<void*>(address), argument,
				&remote_thread, &client_id);

		return remote_thread;
	}
	}

	return 0;
}

std::vector<uint8_t> inject::read_binary_file(const std::string& file_path)
{
	std::ifstream fs(file_path, std::ios::binary);
	fs.unsetf(std::ios::skipws);

	fs.seekg(0, std::ios::end);
	std::streampos file_size = fs.tellg();
	fs.seekg(0, std::ios::beg);

	std::vector<uint8_t> bytes;
	bytes.reserve(static_cast<size_t>(file_size));
	bytes.insert(bytes.begin(), std::istream_iterator<uint8_t>(fs), std::istream_iterator<uint8_t>());

	return bytes;
}

DWORD inject::get_dll_main(void* memory, platform platform_type)
{
	uintptr_t address = reinterpret_cast<uintptr_t>(memory);
	uintptr_t export_dir = address + reinterpret_cast<PIMAGE_DOS_HEADER>(address)->e_lfanew;

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

	std::function<DWORD(DWORD, uintptr_t)> rva_to_offset = [](DWORD rva, uintptr_t base_address) -> DWORD
		{
			PIMAGE_NT_HEADERS nt_header = reinterpret_cast<PIMAGE_NT_HEADERS>(base_address + ((PIMAGE_DOS_HEADER)base_address)->e_lfanew);
			PIMAGE_SECTION_HEADER section_header = reinterpret_cast<PIMAGE_SECTION_HEADER>(reinterpret_cast<uintptr_t>(&nt_header->OptionalHeader) + nt_header->FileHeader.SizeOfOptionalHeader);


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

			return static_cast<DWORD>(0);

		};

	export_dir = address + rva_to_offset((reinterpret_cast<PIMAGE_DATA_DIRECTORY>(reinterpret_cast<DWORD>(&(reinterpret_cast<PIMAGE_NT_HEADERS>(export_dir))->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT])))->VirtualAddress, address);

	DWORD name_array = address + rva_to_offset(reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(export_dir)->AddressOfNames, address);;
	DWORD name_ordinals = address + rva_to_offset(reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(export_dir)->AddressOfNameOrdinals, address);
	DWORD i = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(export_dir)->NumberOfNames;

	while (i--)
	{
		if (strstr(reinterpret_cast<char*>(address + rva_to_offset(*reinterpret_cast<DWORD*>(name_array), address)), "dll_main") != NULL)
		{
			return rva_to_offset(*reinterpret_cast<DWORD*>(address + rva_to_offset(reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(export_dir)->AddressOfFunctions, address) + (*reinterpret_cast<WORD*>(name_ordinals) * sizeof(DWORD))), address);
		}
		name_array += sizeof(DWORD);
		name_ordinals += sizeof(WORD);
	}

	return 0;
}

inject::inject(const std::string& process_name, injection_routine routine, injection_thread_function thread, bool freeze, std::function<void(injection_error)> error_handler)
	: inject(routine, thread, freeze, error_handler)
{
	this->process_id = get_process_id(process_name);
	this->get_handles();
}

inject::inject(HWND window, injection_routine routine, injection_thread_function thread, bool freeze, std::function<void(injection_error)> error_handler)
	: inject(routine, thread, freeze, error_handler)
{
	DWORD id = 0;
	GetWindowThreadProcessId(window, &id);
	this->process_id.push_back(id);
	this->get_handles();
}

inject::inject(DWORD process_id, injection_routine routine, injection_thread_function thread, bool freeze, std::function<void(injection_error)> error_handler)
	: inject(routine, thread, freeze, error_handler)
{
	this->process_id.push_back(process_id);
	this->get_handles();
}

inject::~inject()
{
	for (const std::pair<DWORD, HANDLE>& process : processes)
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

	bool result = this->generic_injection([&](HANDLE h)
		{
			if (this->routine == injection_routine::LOADLIBRARYA || this->routine == injection_routine::LOADLIBRARYEXA)
			{
				for (const std::string& dll : dll_list)
				{
					size_t dll_size = dll.size() + 1;

					this->with_remote_virtual_memory(h, dll_size, [this, h](void* remote_address) {
						if (this->routine == injection_routine::LOADLIBRARYA)
						{
							remote_call(h, "kernelbase.dll", "LoadLibraryA", remote_address);
						}
						else if (this->routine == injection_routine::LOADLIBRARYEXA)
						{
							loadlibraryexa_parameter parameter;
							parameter.address = reinterpret_cast<LoadLibraryExA_t>(GetProcAddress(GetModuleHandleW(L"kernelbase.dll"), "LoadLibraryExA"));
							parameter.file_name = reinterpret_cast<char*>(remote_address);
							parameter.file = 0;
							parameter.flags = 0;

							this->with_remote_virtual_memory(h, external_loadlibraryex_function_size, [&](void* function_allocated_memory_region)
								{
									this->with_remote_virtual_memory(h, sizeof(loadlibraryexa_parameter), [&](void* parameter_allocated_memory_region)
										{
											remote_call(h, reinterpret_cast<DWORD>(function_allocated_memory_region), parameter_allocated_memory_region);
										}, &parameter);
								}, external_loadlibraryex_function);
						}
						}, dll.c_str());
				}
			}
			else if (this->routine == injection_routine::LOADLIBRARYW || this->routine == injection_routine::LOADLIBRARYEXW || this->routine == injection_routine::LDRLOADDLL)
			{
				for (const std::string& _ : dll_list)
				{
					std::wstring dll(_.begin(), _.end());
					size_t dll_size = dll.size() * 2 + 1;


					this->with_remote_virtual_memory(h, dll_size, [this, h](void* remote_address)
						{
							if (this->routine == injection_routine::LOADLIBRARYW)
							{
								remote_call(h, "kernelbase.dll", "LoadLibraryW", remote_address);
							}
							else if (this->routine == injection_routine::LOADLIBRARYEXW)
							{
								loadlibraryexw_parameter parameter;
								parameter.address = reinterpret_cast<LoadLibraryExW_t>(GetProcAddress(GetModuleHandleW(L"kernelbase.dll"), "LoadLibraryExW"));
								parameter.file_name = reinterpret_cast<wchar_t*>(remote_address);
								parameter.file = 0;
								parameter.flags = 0;

								this->with_remote_virtual_memory(h, external_loadlibraryex_function_size, [&](void* function_allocated_memory_region)
									{
										this->with_remote_virtual_memory(h, sizeof(loadlibraryexw_parameter), [&](void* parameter_allocated_memory_region)
											{
												remote_call(h, reinterpret_cast<DWORD>(function_allocated_memory_region), parameter_allocated_memory_region);
											}, &parameter);
									}, external_loadlibraryex_function);
							}
							else if (this->routine == injection_routine::LDRLOADDLL)
							{
								this->with_remote_virtual_memory(h, sizeof(HANDLE), [&](void* handle_allocated_memory_region)
									{
										this->with_remote_virtual_memory(h, sizeof(UNICODE_STRING), [&](void* unicode_string_allocated_memory_region)
											{
												ldrloaddll_parameter parameter;
												parameter.address = reinterpret_cast<LdrLoadDll_t>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "LdrLoadDll"));
												parameter.rtl_init_unicode_string = reinterpret_cast<RtlInitUnicodeString_t>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlInitUnicodeString"));
												parameter.file_name = reinterpret_cast<wchar_t*>(remote_address);

												parameter.file_path = 0;
												parameter.flags = 0;
												parameter.module_file_name = reinterpret_cast<UNICODE_STRING*>(unicode_string_allocated_memory_region);
												parameter.module_handle = reinterpret_cast<HANDLE*>(handle_allocated_memory_region);

												this->with_remote_virtual_memory(h, external_ldrloaddll_function_size, [&](void* function_allocated_memory_region)
													{
														this->with_remote_virtual_memory(h, sizeof(ldrloaddll_parameter), [&](void* parameter_allocated_memory_region)
															{
																remote_call(h, reinterpret_cast<DWORD>(function_allocated_memory_region), parameter_allocated_memory_region);
															}, &parameter);
													}, external_ldrloaddll_function);
											});
									});
							}
						}, dll.c_str());
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

	bool result = this->generic_injection([&](HANDLE h)
		{
			for (const std::string& dll : dll_list)
			{
				std::vector<uint8_t> dll_binary = this->read_binary_file(dll);

				DWORD dll_main = get_dll_main(dll_binary.data());

				if (dll_main)
				{
					this->with_remote_virtual_memory(h, dll_binary.size(), [&](void* remote_address) {
						// TODO: recalculate base addresses and get win32 api from iat
						remote_call(h, reinterpret_cast<DWORD>(remote_address) + dll_main, 0);
						}, dll_binary.data());
				}
				else
				{
					this->error_handler(injection_error::ERROR_DLL_MAPPING_UNSUPPORTED);
				}
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

	for (const std::pair<DWORD, HANDLE>& p : processes)
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

	for (const std::pair<DWORD, HANDLE>& p : processes)
	{
		result &= inject::resume(p.second);
	}

	return result;
}

bool inject::suspend(HANDLE process_handle)
{
	typedef NTSTATUS(NTAPI* ntsuspendprocess_t)(IN HANDLE);

	return reinterpret_cast<ntsuspendprocess_t>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSuspendProcess"))
		(process_handle) == STATUS_SUCCESS;
}

bool inject::resume(HANDLE process_handle)
{
	typedef NTSTATUS(NTAPI* ntresumeprocess_t)(IN HANDLE);

	return reinterpret_cast<ntresumeprocess_t>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtResumeProcess"))
		(process_handle) == STATUS_SUCCESS;
}
