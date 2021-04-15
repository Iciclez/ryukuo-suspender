#include "process.hpp"
#include <functional>
#include <TlHelp32.h>
#include <memory>
#include "inject.hpp"

process::process(uint32_t process_id, uint32_t access)
	: statuses({ "Exception", "Suspended", "Normal", "Terminated" })
{
	this->process_id = process_id;
	this->process_handle = OpenProcess(access, FALSE, process_id);
}

process::~process()
{
	if (this->process_handle)
	{
		CloseHandle(process_handle);
	}
}

bool process::suspend()
{
	return inject::suspend(process_handle);
}

bool process::resume()
{
	return inject::resume(process_handle);
}

bool process::terminate()
{
	return TerminateProcess(process_handle, 0) != FALSE;
}

HANDLE process::get_handle()
{
	return this->process_handle;
}

process::status process::get_status()
{
	typedef LONG KPRIORITY;

	enum KWAIT_REASON
	{
		Executive,
		FreePage,
		PageIn,
		PoolAllocation,
		DelayExecution,
		Suspended,
		UserRequest,
		WrExecutive,
		WrFreePage,
		WrPageIn,
		WrPoolAllocation,
		WrDelayExecution,
		WrSuspended,
		WrUserRequest,
		WrEventPair,
		WrQueue,
		WrLpcReceive,
		WrLpcReply,
		WrVirtualMemory,
		WrPageOut,
		WrRendezvous,
		Spare2,
		Spare3,
		Spare4,
		Spare5,
		Spare6,
		WrKernel,
		MaximumWaitReason
	};

	enum THREAD_STATE
	{
		Running = 2,
		Waiting = 5,
	};
#pragma pack(push,4)

	struct CLIENT_ID
	{
		HANDLE UniqueProcess; // Process ID
		HANDLE UniqueThread;  // Thread ID
	};

	struct SYSTEM_THREAD
	{
		FILETIME     ftKernelTime;
		FILETIME     ftUserTime;
		FILETIME     ftCreateTime;
		DWORD        dWaitTime;
		PVOID        pStartAddress;
		CLIENT_ID    Cid;
		DWORD        dPriority;
		DWORD        dBasePriority;
		DWORD        dContextSwitches;
		THREAD_STATE dThreadState;
		KWAIT_REASON WaitReason;
		DWORD        dReserved01;
	};

	struct VM_COUNTERS // virtual memory of process
	{
		DWORD PeakVirtualSize;
		DWORD VirtualSize;
		DWORD PageFaultCount;
		DWORD PeakWorkingSetSize;
		DWORD WorkingSetSize;
		DWORD QuotaPeakPagedPoolUsage;
		DWORD QuotaPagedPoolUsage;
		DWORD QuotaPeakNonPagedPoolUsage;
		DWORD QuotaNonPagedPoolUsage;
		DWORD PagefileUsage;
		DWORD PeakPagefileUsage;
	};

	struct SYSTEM_PROCESS
	{
		DWORD          dNext;         // relative offset
		DWORD          dThreadCount;
		DWORD          dReserved01;
		DWORD          dReserved02;
		DWORD          dReserved03;
		DWORD          dReserved04;
		DWORD          dReserved05;
		DWORD          dReserved06;
		FILETIME       ftCreateTime;
		FILETIME       ftUserTime;
		FILETIME       ftKernelTime;
		UNICODE_STRING usName;        // process name (unicode)
		KPRIORITY      BasePriority;
		DWORD          dUniqueProcessId;
		DWORD          dInheritedFromUniqueProcessId;
		DWORD          dHandleCount;
		DWORD          dReserved07;
		DWORD          dReserved08;
		VM_COUNTERS    VmCounters;    // see ntddk.h
		DWORD          dCommitCharge; // bytes
		IO_COUNTERS    IoCounters;    // see ntddk.h
		SYSTEM_THREAD  aThreads;      // thread array
	};

#pragma pack(pop)

	//NTSTATUS STATUS_SUCCESS = 0x00000000
	//SystemProcessAndThreadInformation = 5
	
	dword system_process_info_size = 1024;
	std::unique_ptr<byte[]> system_process_info = std::make_unique<byte[]>(system_process_info_size);

	dword needed = 0;
	NTSTATUS nt = NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS::SystemProcessInformation, system_process_info.get(), system_process_info_size, &needed);
	while (nt == 0xC0000004)
	{
		system_process_info_size = needed + 4076;
		system_process_info.reset();
		system_process_info = std::move(std::make_unique<byte[]>(system_process_info_size));
		nt = NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS::SystemProcessInformation, system_process_info.get(), system_process_info_size, &needed);
	}
	
	if (nt == 0x00000000 && system_process_info.get() != nullptr)
	{
		std::function<dword(dword)> getmainthreadid = [](dword process_id) -> dword
		{
			HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
			if (h == 0 || h == INVALID_HANDLE_VALUE)
			{
				return 0;
			}

			THREADENTRY32 threadentry = { 0 };
			threadentry.dwSize = sizeof(THREADENTRY32);

			if (Thread32First(h, &threadentry))
			{
				do
				{
					if (threadentry.th32OwnerProcessID == process_id)
					{
						CloseHandle(h);
						return threadentry.th32ThreadID;
					}

				} while (Thread32Next(h, &threadentry));
			}

			CloseHandle(h);
			return 0;
		};

		SYSTEM_PROCESS *psystemprocess = reinterpret_cast<SYSTEM_PROCESS*>(system_process_info.get());

		for (; psystemprocess->dUniqueProcessId != process_id; psystemprocess = reinterpret_cast<SYSTEM_PROCESS*>(reinterpret_cast<byte*>(psystemprocess) + psystemprocess->dNext))
		{
			if (!psystemprocess->dNext)
			{
				return exception;
			}
		};

		if (psystemprocess->dUniqueProcessId == process_id)
		{
			SYSTEM_THREAD *psystemthread = &psystemprocess->aThreads;
			dword threadid = getmainthreadid(process_id);
			if (threadid == 0)
			{
				return exception;
			}
			for (dword dw = 0; dw < psystemprocess->dThreadCount; ++dw, ++psystemthread)
			{
				if (reinterpret_cast<dword>(psystemthread->Cid.UniqueThread) == threadid)
				{
					if (psystemthread->dThreadState == Waiting && psystemthread->WaitReason == Suspended)
					{
						return suspended;
					}
					else
					{
						return normal;
					}

					break;
				}
			}

		}
	}
	return exception;
}

std::string &process::get_status_string()
{
	return statuses.at(this->get_status());
}
