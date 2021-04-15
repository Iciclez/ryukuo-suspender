#pragma once
#include <windows.h>

#include <string>
#include <array>

class process
{
public:
	enum status
	{
		exception = 0, 

		suspended,
		normal,
		terminated
	};

public:
	process(uint32_t process_id, uint32_t access = PROCESS_ALL_ACCESS);
	~process();

	bool suspend();
	bool resume();
	bool terminate();

	HANDLE get_handle();

	status get_status();
	std::string &get_status_string();

private:
	std::array<std::string, 4> statuses;

	HANDLE process_handle;
	uint32_t process_id;
};

