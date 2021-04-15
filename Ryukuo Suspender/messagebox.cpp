#include "messagebox.hpp"
#include <windows.h>


messagebox::messagebox()
{
}


messagebox::~messagebox()
{
}

void messagebox::show(const std::string & caption, const std::string & title)
{
	MessageBox(0, caption.c_str(), title.c_str(), MB_OK | MB_TASKMODAL);
}

void messagebox::showerror(const std::string & caption, const std::string & title)
{
	MessageBox(0, caption.c_str(), title.c_str(), MB_OK | MB_ICONERROR | MB_TASKMODAL);
}

void messagebox::showinfo(const std::string & caption, const std::string & title)
{
	MessageBox(0, caption.c_str(), title.c_str(), MB_OK | MB_ICONINFORMATION | MB_TASKMODAL);
}

messagebox::messageboxresult messagebox::show_yesno(const std::string & caption, const std::string & title)
{
	return MessageBox(0, caption.c_str(), title.c_str(), MB_YESNO | MB_ICONQUESTION | MB_TASKMODAL) == IDYES ? yes : no;
}

messagebox::messageboxresult messagebox::show_yesnocancel(const std::string & caption, const std::string & title)
{
	switch (MessageBox(0, caption.c_str(), title.c_str(), MB_YESNOCANCEL | MB_ICONQUESTION | MB_TASKMODAL))
	{
	case IDYES:
		return yes;
	case IDNO:
		return no;
	case IDCANCEL:
		return cancel;
	default:
		return cancel;
	}
}
