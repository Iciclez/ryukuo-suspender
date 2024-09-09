#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <functional>
#include <windows.h>
#include <winternl.h>


#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS 0x00000000
#endif

class inject
{
public:
	typedef HMODULE(WINAPI* LoadLibraryExA_t)(LPCSTR, HANDLE, DWORD);
	typedef HMODULE(WINAPI* LoadLibraryExW_t)(LPCWSTR, HANDLE, DWORD);
	typedef NTSTATUS(NTAPI* LdrLoadDll_t)(IN PWCHAR OPTIONAL, IN ULONG OPTIONAL, IN PUNICODE_STRING, OUT PHANDLE);
	typedef VOID(NTAPI* RtlInitUnicodeString_t)(PUNICODE_STRING, __drv_aliasesMem PCWSTR);

	enum class injection_routine
	{
		LOADLIBRARYA = 1,
		LOADLIBRARYW,
		LOADLIBRARYEXA,
		LOADLIBRARYEXW,
		LDRLOADDLL,
	};

	enum class injection_thread_function
	{
		CREATEREMOTETHREAD = 1,
		CREATEREMOTETHREADEX,
		NTCREATETHREADEX,
		RTLCREATEUSERTHREAD
	};

	enum class injection_error
	{
		ERROR_INVALID_PROCESS_ID = 1,
		ERROR_INVALID_PROCESS_HANDLE,
		ERROR_DLL_MAPPING_UNSUPPORTED
	};

	struct loadlibraryexw_parameter
	{
		LoadLibraryExW_t address;
		wchar_t* file_name;
		HANDLE file;
		DWORD flags;
	};

	struct loadlibraryexa_parameter
	{
		LoadLibraryExA_t address;
		char* file_name;
		HANDLE file;
		DWORD flags;
	};

	struct ldrloaddll_parameter
	{
		LdrLoadDll_t address;
		RtlInitUnicodeString_t rtl_init_unicode_string;
		wchar_t* file_name;

		wchar_t* file_path;
		DWORD flags;
		UNICODE_STRING* module_file_name;
		HANDLE* module_handle;
	};

	inject(const std::string& process_name, injection_routine routine = injection_routine::LOADLIBRARYA, injection_thread_function thread = injection_thread_function::CREATEREMOTETHREAD, bool freeze = true, std::function<void(injection_error)> error_handler = [](injection_error) {});
	inject(HWND window, injection_routine routine = injection_routine::LOADLIBRARYA, injection_thread_function thread = injection_thread_function::CREATEREMOTETHREAD, bool freeze = true, std::function<void(injection_error)> error_handler = [](injection_error) {});
	inject(DWORD process_id, injection_routine routine = injection_routine::LOADLIBRARYA, injection_thread_function thread = injection_thread_function::CREATEREMOTETHREAD, bool freeze = true, std::function<void(injection_error)> error_handler = [](injection_error) {});
	~inject();

	bool inject_dll(const std::vector<std::string>& dll_list);
	bool map_dll(const std::vector<std::string>& dll_list);

	bool suspend();
	bool resume();

	static bool suspend(HANDLE process_handle);
	static bool resume(HANDLE process_handle);

	static std::vector<DWORD> get_process_id(const std::string& process_name);

private:
	std::vector<DWORD> process_id;
	std::unordered_map<DWORD, HANDLE> processes;
	bool freeze_processes;
	injection_routine routine;
	injection_thread_function thread;
	std::function<bool(std::function<void(HANDLE h)>)> generic_injection;
	std::function<void(injection_error)> error_handler;

private:
	inject(injection_routine routine = injection_routine::LOADLIBRARYA, injection_thread_function thread = injection_thread_function::CREATEREMOTETHREAD, bool freeze_processes = true, std::function<void(injection_error)> error_handler = [](injection_error) {});
	void get_handles();

	void with_remote_virtual_memory(HANDLE handle, uintptr_t size, const std::function<void(void*)>& function, const void* value_at_remote_memory = nullptr);

	bool remote_call(HANDLE handle, const std::string& module_name, const std::string& function_name, void* argument);
	bool remote_call(HANDLE handle, DWORD address, void* argument);

	HANDLE remote_thread(HANDLE h, DWORD address, void* argument);

	std::vector<uint8_t> read_binary_file(const std::string& file_path);

	enum class platform : uint8_t
	{
		x86 = 1,
		x64 = 2
	};

	DWORD get_dll_main(void* memory, platform platform_type = platform::x86);
};
