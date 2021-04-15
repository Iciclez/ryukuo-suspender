#include "mainwindow.hpp"
#include "process.hpp"
#include "messagebox.hpp"
#include "inject.hpp"
#include <sstream>
#include <iomanip>
#include <thread>
#include <string>
#include <algorithm>

#include <TlHelp32.h>
#include <Psapi.h>
#include <Shlobj.h>
#include <Shlwapi.h>

#include "resource.h"


logger l("ryukuo_suspender.log");

#pragma comment (lib, "Comctl32.lib")
#pragma comment (lib, "Shlwapi.lib")

std::string mainwindow::windowname()
{
	std::stringstream ss;
	ss << "Ryukuo Suspender | Process Id: "
		<< std::hex << std::uppercase << std::setw(8) << std::setfill('0') << GetCurrentProcessId()
		<< " (" << std::dec << GetCurrentProcessId() << ")";

	return ss.str();
}

void mainwindow::set_message_handler()
{
	this->w->add_message_handler(std::make_pair(menu_refresh, [this](hwnd, wparam, lparam) -> lresult
	{
		this->m_checklistview_processlist->clear();

		HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		PROCESSENTRY32 p = { 0 };

		p.dwSize = sizeof(PROCESSENTRY32);

		SHFILEINFO sfi = { 0 };

		if (Process32First(h, &p))
		{
			if (!SUCCEEDED(SHGetFileInfo(".exe", FILE_ATTRIBUTE_NORMAL, &sfi, sizeof(sfi), SHGFI_ICON | SHGFI_SMALLICON | SHGFI_USEFILEATTRIBUTES)))
			{
				CloseHandle(h);
				return 0;
			}
		}

		int32_t default_icon = ImageList_AddIcon(processlist_imagelist, sfi.hIcon);
		DestroyIcon(sfi.hIcon);

		this->m_progresswindow->show();

		LVITEM lvI;
		char executable_path[MAX_PATH];

		do
		{
			std::memset(&lvI, 0, sizeof(LVITEM));

			lvI.mask = LVIF_TEXT | LVIF_IMAGE;
			lvI.iItem = this->m_checklistview_processlist->size();
			lvI.iImage = -1;

			lvI.iSubItem = 0;
			ListView_InsertItem(this->m_checklistview_processlist->get_handle(), &lvI);

			//PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
			process current_process(p.th32ProcessID);

			for (lvI.iSubItem = lvI.iSubItem + 1; lvI.iSubItem < 4; ++lvI.iSubItem)
			{
				lvI.iImage = -1;
				switch (lvI.iSubItem)
				{
				case 1:
				{
					lvI.iImage = default_icon;
					lvI.pszText = p.szExeFile;

					if (current_process.get_handle() != INVALID_HANDLE_VALUE)
					{
						//GetModuleFileNameEx
						DWORD max_path = MAX_PATH;
						if (QueryFullProcessImageName(current_process.get_handle(), 0, executable_path, &max_path))
						{
							if (SUCCEEDED(SHGetFileInfo(executable_path, static_cast<DWORD>(-1), &sfi, sizeof(sfi), SHGFI_ICON | SHGFI_LARGEICON)))
							{
								int32_t app_icon = ImageList_AddIcon(processlist_imagelist, sfi.hIcon);
								if (app_icon != -1)
								{
									lvI.iImage = app_icon;
									DestroyIcon(sfi.hIcon);
								}
							}
						}
					}
					break;
				}
				case 2:
					snprintf(lvI.pszText, 16, "%d", p.th32ProcessID);
					break;
				case 3:
					lvI.pszText = const_cast<char*>(current_process.get_status_string().c_str());
					break;
				}

				ListView_SetItem(this->m_checklistview_processlist->get_handle(), &lvI);
			}

		} while (Process32Next(h, &p));

		ListView_EnsureVisible(this->m_checklistview_processlist->get_handle(), this->m_checklistview_processlist->size(), TRUE);

		this->m_progresswindow->hide();

		ListView_RedrawItems(this->m_checklistview_processlist->get_handle(), this->m_checklistview_processlist->size(), this->m_checklistview_processlist->size());

		if (h)
		{
			CloseHandle(h);
		}


		return 0;
	}));


	this->w->add_message_handler(std::make_pair(button_suspend, [this](hwnd, wparam, lparam) -> lresult
	{
		std::vector<uint32_t> checkedlist = this->m_checklistview_processlist->get_checked_list();
		for (uint32_t n : checkedlist)
		{
			uint32_t process_id = std::stoi(this->m_checklistview_processlist->text(n, 2));
			handle process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
			if (!process)
			{
				l.log("[-] manual: openprocess error on process id: %d (%.08X)", process_id, process_id);
				continue;
			}

			if (inject::suspend(process))
			{
				l.log("[+] manual: succesfully suspended process id: %d (%.08X) ", process_id, process_id);
			}
			else
			{
				l.log("[-] manual: unable to suspend process id: %d (%.08X) ", process_id, process_id);
			}

			CloseHandle(process);
		}

		return 0;
	}));

	this->w->add_message_handler(std::make_pair(button_resume, [this](hwnd, wparam, lparam) -> lresult
	{
		std::vector<uint32_t> checkedlist = this->m_checklistview_processlist->get_checked_list();
		for (const uint32_t n : checkedlist)
		{
			uint32_t process_id = std::stoi(this->m_checklistview_processlist->text(n, 2));
			handle process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
			if (!process)
			{
				l.log("[-] manual: openprocess error on process id: %d (%.08X)", process_id, process_id);
				continue;
			}

			if (inject::resume(process))
			{
				l.log("[+] manual: succesfully resumed process id: %d (%.08X) ", process_id, process_id);
			}
			else
			{
				l.log("[-] manual: unable to resume process id: %d (%.08X) ", process_id, process_id);
			}

			CloseHandle(process);
		}
		return 0;

	}));

	this->w->add_message_handler(std::make_pair(menu_terminate, [this](hwnd, wparam, lparam) -> lresult
	{
		std::vector<uint32_t> checkedlist = this->m_checklistview_processlist->get_checked_list();
		for (const uint32_t n : checkedlist)
		{
			uint32_t process_id = std::stoi(this->m_checklistview_processlist->text(n, 2));
			handle process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
			if (!process)
			{
				l.log("[-] manual: openprocess error on process id: %d (%.08X)", process_id, process_id);
				continue;
			}

			if (TerminateProcess(process, 0))
			{
				l.log("[+] manual: succesfully terminated process id: %d (%.08X) ", process_id, process_id);
			}
			else
			{
				l.log("[-] manual: unable to terminate process id: %d (%.08X) ", process_id, process_id);
			}

			CloseHandle(process);
		}
		return 0;

	}));

	this->w->add_message_handler(std::make_pair(menu_exit, [this](hwnd, wparam, lparam) -> lresult
	{
		this->w->send_message(WM_CLOSE);
		return 0;
	}));


	this->w->add_message_handler(std::make_pair(menu_taskmanager, [this](hwnd, wparam, lparam) -> lresult
	{
		std::unique_ptr<char[]> systemdirectory = std::make_unique<char[]>(MAX_PATH);
		std::unique_ptr<char[]> taskmanager = std::make_unique<char[]>(MAX_PATH);
		if (SHGetSpecialFolderPath(0, systemdirectory.get(), CSIDL_SYSTEM, FALSE) && PathFileExists(PathCombine(taskmanager.get(), systemdirectory.get(), "taskmgr.exe")))
		{
			ShellExecute(NULL, "OPEN", taskmanager.get(), NULL, NULL, SW_SHOWNORMAL);
		}

		return 0;
	}));

	this->w->add_message_handler(std::make_pair(menu_about, [this](hwnd wnd, wparam, lparam) -> lresult
	{
		messagebox::showinfo("Ryukuo Suspender					2.0.0.0\n\nCreated by Iciclez", "About Ryukuo Suspender");
		return 0;
	}));

	this->w->add_message_handler(std::make_pair(menu_inject, [this](hwnd wnd, wparam, lparam) -> lresult 
	{
		int32_t n = this->m_checklistview_processlist->get_next_selected_item();
		std::string process_name = this->m_checklistview_processlist->text(n, 1);
		dword processid = std::stoi(this->m_checklistview_processlist->text(n, 2));
		if (processid)
		{
			OPENFILENAMEA ofn = { 0 };
			char file[MAX_PATH] = { 0 };

			ofn.lStructSize = sizeof(ofn);
			ofn.hwndOwner = wnd;
			ofn.lpstrFile = file;
			ofn.nMaxFile = sizeof(file);
			ofn.lpstrFilter = "Dynamic-link Library (*.dll)\0*.dll\0\0"; // "Dynamic-link Library (*.dll)", "*.dll";
			ofn.nFilterIndex = 1;
			ofn.lpstrFileTitle = 0;
			ofn.nMaxFileTitle = 0;
			ofn.lpstrInitialDir = NULL;
			ofn.lpstrTitle = "Ryukuo Suspender: Select a Dll";
			ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_EXPLORER;

			if (GetOpenFileName(&ofn))
			{

				switch (messagebox::show_yesno("Are you sure you would like to inject '" + std::string(PathFindFileName(file)) + "' to the following module: \r\n\r\nTarget: " + std::string(process_name.begin(), process_name.end()) + "\r\nProcess Id: " + std::to_string(processid), "Ryukuo Suspender: Dll Injector"))
				{
				case messagebox::messageboxresult::yes:
					break;

				case messagebox::messageboxresult::no:
					return 0;
				}

				//inject

				std::string file_string(file);

				inject(processid, inject::injection_routine::LOADLIBRARYA, inject::injection_thread_function::CREATEREMOTETHREAD, true)
					.inject_dll(std::vector<std::string>({ file_string }));

				std::transform(file_string.begin(), file_string.end(), file_string.begin(), tolower);
				std::transform(process_name.begin(), process_name.end(), process_name.begin(), towlower);

				std::stringstream ss;
				
				ss << "injected '" << PathFindFileName(file_string.c_str()) << "' "
					<< " into module '" << std::string(process_name.begin(), process_name.end()) << "' "
					<< ", process id: " << std::dec << processid
					<< " (" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << processid
					<< ")";

				l.log("[+] %s", ss.str().c_str());
				messagebox::show(ss.str(), "Ryukuo Suspender: Succesfully Injected");
			}
		}

		return 0;
	}));
}

mainwindow::mainwindow(hinstance inst)
{
	this->inst = inst;
	this->automaticsuspenderid = 8000;

	this->w = std::move(std::make_unique<window>(inst, this->windowname(), "Ryukuo Suspender", static_cast<window::window_event_t>([this](hwnd wnd, wparam, lparam)
	{
		hfont bold_font = widget::make_font("Segoe UI", 14, 0, true);

		menu mainmenu;
		menu filemenu;
		menu toolsmenu;
		menu helpmenu;

		mainmenu.append_menu(filemenu, "File");
		mainmenu.append_menu(toolsmenu, "Tools");
		mainmenu.append_menu(helpmenu, "Help");

		filemenu.append_menu(menu_exit, "Exit");
		toolsmenu.append_menu(menu_taskmanager, "Task Manager");
		helpmenu.append_menu(menu_about, "About Ryukuo Suspender");

		window::get_window(wnd)->set_menu(mainmenu);

		rectangle r = window::get_window(wnd)->get_client_rectangle();

		this->m_groupbox_processlist = std::move(std::make_unique<groupbox>(groupbox_processlist, 5, 5, 300, r.bottom - 10, "Process List", wnd));
		this->m_groupbox_processlist->set_font(bold_font);

		this->m_checklistview_processlist = std::move(std::make_unique<checklistview>(checklistview_processlist, 10, 20, 290, r.bottom - 30, wnd, std::vector<std::string>({ "" , "Process Name", "Process Id", "Thread Status" }), true, true));
		this->processlist_imagelist = ImageList_Create(16, 16, ILC_COLOR32, 0, 256);
		ListView_SetImageList(m_checklistview_processlist->get_handle(), this->processlist_imagelist, LVSIL_SMALL);
		this->m_checklistview_processlist->send_message(LVM_SETEXTENDEDLISTVIEWSTYLE, 0, LVS_EX_CHECKBOXES | LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER | LVS_OWNERDATA | LVS_EX_SUBITEMIMAGES);
		
		this->m_groupbox_automaticsuspender = std::move(std::make_unique<groupbox>(groupbox_automaticsuspender, 315, 5, r.right - 320, r.bottom - 35, "Automatic Suspender", wnd));
		this->m_groupbox_automaticsuspender->set_font(bold_font);

		this->m_tabcontrolex_automaticsuspender = std::move(std::make_unique<tabcontrolex>(tabcontrolex_automaticsuspender, 320, 20, r.right - 325, r.bottom - 55, wnd, [this, r](tabcontrol * ptabcontrol, int32_t insert_index)
		{
			int32_t n = insert_index + 1;
			m_automaticsuspender[n] = std::make_shared<automaticsuspenderview>(ptabcontrol, this, r, this->automaticsuspenderid);
			return std::make_pair(std::to_string(n), m_automaticsuspender[n]->get_widgets());
		}));
		
		this->m_button_suspend = std::move(std::make_unique<button>(button_suspend, 315, r.bottom - 25, (r.right - 320) / 2, 20, "Suspend", wnd));
		this->m_button_resume = std::move(std::make_unique<button>(button_resume, 315 + (r.right - 320) / 2 + 5, r.bottom - 25, (r.right - 320) / 2 - 5, 20, "Resume", wnd));
	}), 1000, 600, CW_USEDEFAULT, CW_USEDEFAULT, false, GetSysColorBrush(15), CS_HREDRAW | CS_VREDRAW, MAKEINTRESOURCE(IDI_ICON1), IDC_ARROW, WS_OVERLAPPEDWINDOW, 0, false));

	std::thread([this](hinstance inst)
	{
		this->m_progresswindow = std::make_shared<progresswindow>(inst);
		this->m_progresswindow->async_message_loop();
	}, inst).detach();

	this->w->add_wndproc_listener(WM_SIZE, static_cast<window::window_event_t>([this](hwnd wnd, wparam, lparam)
	{
		rectangle r = window::get_window(wnd)->get_client_rectangle();

		this->m_groupbox_processlist->set_window_position(5, 5, 300, r.bottom - 10);
		this->m_checklistview_processlist->set_window_position(10, 20, 290, r.bottom - 30);

		this->m_groupbox_automaticsuspender->set_window_position(315, 5, r.right - 320, r.bottom - 35);
		this->m_tabcontrolex_automaticsuspender->set_window_position(320, 20, r.right - 325, r.bottom - 55);

		this->m_button_suspend->set_window_position(315, r.bottom - 25, (r.right - 320) / 2, 20);
		this->m_button_resume->set_window_position(315 + (r.right - 320) / 2 + 5, r.bottom - 25, (r.right - 320) / 2 - 5, 20);

		for (const std::pair<uint32_t, std::shared_ptr<automaticsuspenderview>> &p : m_automaticsuspender)
		{
			p.second->size(r);
		}
	}));


	this->w->add_wndproc_listener(WM_NOTIFY, static_cast<window::window_event_t>([this](hwnd wnd, wparam, lparam l)
	{
		if ((reinterpret_cast<LPNMHDR>(l))->code == NM_RCLICK &&
			(reinterpret_cast<LPNMHDR>(l))->hwndFrom == m_checklistview_processlist->get_handle())
		{
			popupmenu pm;
			pm.append_menu(menu_refresh, "Refresh");
			pm.append_separator();
			pm.append_menu(button_suspend, "Suspend");
			pm.append_menu(button_resume, "Resume");
			pm.append_menu(menu_terminate, "Terminate");
			pm.append_separator();
			pm.append_menu(menu_inject, "Inject Dll");

			point p;

			GetCursorPos(&p);
			TrackPopupMenu(pm.get_handle(), TPM_LEFTALIGN, p.x, p.y, 0, wnd, NULL);
		}
		
	}));
	
	this->w->add_wndproc_listener(WM_CTLCOLORSTATIC, static_cast<window::lresult_window_event_t>([this](hwnd, wparam w, lparam l) -> lresult
	{
		HDC hdc = reinterpret_cast<HDC>(w);
		SetTextColor(hdc, RGB(0, 0, 0));
		SetBkColor(hdc, RGB(255, 255, 255));

		if (l == reinterpret_cast<lparam>(this->m_groupbox_automaticsuspender->get_handle()) ||
			l == reinterpret_cast<lparam>(this->m_groupbox_processlist->get_handle()))
		{
			return reinterpret_cast<lresult>(GetSysColorBrush(15));
		}

		return reinterpret_cast<lresult>(GetSysColorBrush(COLOR_WINDOW));
	}));

	this->set_message_handler();

	this->w->send_message(WM_SIZE);
	this->w->send_message(WM_COMMAND, menu_refresh, 0);
	this->w->set_visible(true);
	
}


mainwindow::~mainwindow()
{
	m_progresswindow.reset();
	if (processlist_imagelist) ImageList_Destroy(processlist_imagelist);
}

int32_t mainwindow::message_loop()
{
	return w->handle_message();
}
