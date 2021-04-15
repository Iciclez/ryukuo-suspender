#pragma once
#include <string>

class messagebox
{
public:
	enum messageboxresult : int32_t
	{
		yes = 1,
		no,
		cancel,
	};

	messagebox();
	~messagebox() noexcept;

	static void show(const std::string& caption = "", const std::string &title = "");
	static void showerror(const std::string& caption = "", const std::string &title = "");
	static void showinfo(const std::string& caption = "", const std::string &title = "");

	static messageboxresult show_yesno(const std::string& caption = "", const std::string &title = "");
	static messageboxresult show_yesnocancel(const std::string& caption = "", const std::string &title = "");
};

