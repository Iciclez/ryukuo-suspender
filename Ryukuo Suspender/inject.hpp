#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <functional>
#include <windows.h>
#include <winternl.h>

typedef HANDLE handle;
typedef DWORD dword;
typedef WORD word;
typedef HWND hwnd;
typedef LPVOID lpvoid;
typedef _UNICODE_STRING unicode_string;

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS 0x00000000
#endif

class inject
{
public:
	typedef HMODULE(WINAPI *loadlibraryexa_t)(LPCSTR, HANDLE, DWORD);
	typedef HMODULE(WINAPI *loadlibraryexw_t)(LPCWSTR, HANDLE, DWORD);
	typedef NTSTATUS(NTAPI *ldrloaddll_t)(IN PWCHAR OPTIONAL, IN ULONG OPTIONAL, IN PUNICODE_STRING, OUT PHANDLE);
	typedef VOID(NTAPI *rtlinitunicodestring_t)(PUNICODE_STRING, __drv_aliasesMem PCWSTR);

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
		loadlibraryexw_t address;
		wchar_t *filename;
		handle file;
		dword flags;
	};

	struct loadlibraryexa_parameter
	{
		loadlibraryexa_t address;
		char *filename;
		handle file;
		dword flags;
	};

	struct ldrloaddll_parameter
	{
		ldrloaddll_t address;
		rtlinitunicodestring_t rtlinitunicodestring;
		wchar_t *filename;

		wchar_t *pathtofile;
		dword flags;
		UNICODE_STRING *module_filename;
		handle *module_handle;
	};

	inject(const std::string& process_name, injection_routine routine = injection_routine::LOADLIBRARYA, injection_thread_function thread = injection_thread_function::CREATEREMOTETHREAD, bool freeze = true, std::function<void(injection_error)> error_handler = [](injection_error) {});
	inject(hwnd window, injection_routine routine = injection_routine::LOADLIBRARYA, injection_thread_function thread = injection_thread_function::CREATEREMOTETHREAD, bool freeze = true, std::function<void(injection_error)> error_handler = [](injection_error) {});
	inject(dword process_id, injection_routine routine = injection_routine::LOADLIBRARYA, injection_thread_function thread = injection_thread_function::CREATEREMOTETHREAD, bool freeze = true, std::function<void(injection_error)> error_handler = [](injection_error) {});
	~inject();

	bool inject_dll(const std::vector<std::string> &dll_list);
	bool map_dll(const std::vector<std::string> &dll_list);

	bool suspend();
	bool resume();

	static bool suspend(handle process_handle);
	static bool resume(handle process_handle);

	static std::vector<dword> get_process_id(const std::string &process_name);

private:
	std::vector<dword> process_id;
	std::unordered_map<dword, handle> processes;
	bool freeze_processes;
	injection_routine routine;
	injection_thread_function thread;
	std::function<bool(std::function<void(handle h)>)> generic_injection;
	std::function<void(injection_error)> error_handler;

private:
	inject(injection_routine routine = injection_routine::LOADLIBRARYA, injection_thread_function thread = injection_thread_function::CREATEREMOTETHREAD, bool freeze_processes = true, std::function<void(injection_error)> error_handler = [](injection_error) {});
	bool get_handles();
	bool createandhandleremotethread(handle h, const std::string &module_name, const std::string &function_name, lpvoid argument);
	bool createandhandleremotethread(handle h, dword address, lpvoid argument);

	lpvoid virtualallocex(handle h, int32_t dll_size);
	bool virtualfree(handle h, lpvoid memory_region);
	bool writeprocessmemory(handle h, const std::string &dll, int32_t dll_size, lpvoid memory_region);
	bool writeprocessmemory(handle h, const std::wstring &dll, int32_t dll_size, lpvoid memory_region);
	bool writeprocessmemory(handle h, lpvoid memory, int32_t dll_size, lpvoid memory_region);
	handle createremotethread(handle h, dword address, lpvoid argument);
	handle createremotethread(handle h, const std::string &module_name, const std::string &function_name, lpvoid argument);
	bool waitforsingleobject(handle h);

	handle createfile(const std::string &file);
	bool closehandle(handle h);
	dword getfilesize(handle h);
	lpvoid heapalloc(dword size);
	bool heapfree(lpvoid memory);
	bool readfile(handle h, lpvoid memory, dword filesize);
	
	enum class platform : byte
	{
		x86 = 1,
		x64 = 2
	};

	dword getdllmain(lpvoid memory, platform platform_type = platform::x86);
};

