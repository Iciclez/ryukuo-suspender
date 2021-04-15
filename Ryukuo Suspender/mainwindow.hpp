#pragma once
#include <string>
#include <memory>
#include <map>

#include "window.hpp"
#include "checklistview.hpp"
#include "groupbox.hpp"
#include "tabcontrolex.hpp"

#include "progresswindow.hpp"
#include "automaticsuspenderview.hpp"

#include "logger.hpp"

class automaticsuspenderview;

extern logger l;

class mainwindow
{
private:
	std::string windowname();

	void set_message_handler();

public:
	enum id : int32_t
	{
		menu_exit = 1,
		menu_taskmanager,
		menu_about,

		menu_refresh,

		groupbox_processlist,
		checklistview_processlist,

		groupbox_automaticsuspender,
		tabcontrolex_automaticsuspender,

		button_suspend,
		button_resume,
		menu_terminate,
		
		menu_inject

		// 8000 and above are reserved for automaticsuspenderid
	};

private:
	HIMAGELIST processlist_imagelist;
private:
	hinstance inst;
	std::unique_ptr<window> w;

	std::unique_ptr<groupbox> m_groupbox_processlist;
	std::unique_ptr<checklistview> m_checklistview_processlist;

	std::unique_ptr<groupbox> m_groupbox_automaticsuspender;
	std::unique_ptr<tabcontrolex> m_tabcontrolex_automaticsuspender;

	std::unique_ptr<button> m_button_suspend;
	std::unique_ptr<button> m_button_resume;

	std::shared_ptr<progresswindow> m_progresswindow;

	uint32_t automaticsuspenderid;
	std::map<uint32_t, std::shared_ptr<automaticsuspenderview>> m_automaticsuspender;

public:
	mainwindow(hinstance inst);
	~mainwindow();

	int32_t message_loop();
};

