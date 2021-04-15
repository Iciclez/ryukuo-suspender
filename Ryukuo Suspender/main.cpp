#include <windows.h>
#include <cstdint>
#include "mainwindow.hpp"

#pragma comment(linker,"\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

#pragma comment (lib, "Icy.lib")
#pragma comment (lib, "ntdll")

typedef HINSTANCE hinstance;
typedef LPSTR lpstr;
typedef HANDLE handle;

int32_t _stdcall WinMain(hinstance inst, hinstance, lpstr, int32_t)
{
	[]()
	{
		handle process = GetCurrentProcess();
		handle token = 0;
		if (OpenProcessToken(process, TOKEN_ADJUST_PRIVILEGES, &token))
		{
			CloseHandle(token);
			CloseHandle(process);
			return false;
		}

		LUID luid = { 0 };
		if (!LookupPrivilegeValue(0, "SeDebugPrivilege", &luid))
		{
			CloseHandle(token);
			CloseHandle(process);
			return false;
		}

		TOKEN_PRIVILEGES privileges = { 0 };
		privileges.PrivilegeCount = 1;
		privileges.Privileges[0].Luid = luid;
		privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		AdjustTokenPrivileges(token, false, &privileges, 0, 0, 0);

		CloseHandle(token);
		CloseHandle(process);

		return true;
	}();

	return mainwindow(inst).message_loop();
}