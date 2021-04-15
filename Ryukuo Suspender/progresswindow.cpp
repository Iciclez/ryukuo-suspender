#include "progresswindow.hpp"
#include "resource.h"

progresswindow::progresswindow(hinstance inst)
{
	this->w = std::move(std::make_unique<window>(inst, "Ryukuo Suspender: Please Wait...", "Ryukuo Suspender: Progress Window", [&](hwnd wnd, wparam, lparam) -> void
	{
		rectangle r = window::get_window(wnd)->get_client_rectangle();

		this->m_progressbar_main = std::move(std::make_unique<progressbar>(progressbar_main, 5, 5, r.right - 10, r.bottom - 10, wnd, true));
		this->m_progressbar_main->set_marquee();

	}, 300, 70, CW_USEDEFAULT, CW_USEDEFAULT, false, GetSysColorBrush(15), CS_HREDRAW | CS_VREDRAW, MAKEINTRESOURCE(IDI_ICON1), IDC_ARROW, WS_OVERLAPPED, WS_EX_TOPMOST));

	rectangle r = this->w->get_window_rectangle();
	this->w->set_window_position((GetSystemMetrics(SM_CXSCREEN) - r.right) / 2, (GetSystemMetrics(SM_CYSCREEN) - r.bottom) / 2);

	this->w->add_wndproc_listener(WM_CLOSE, static_cast<window::lresult_window_event_t>([&](hwnd, wparam, lparam) -> lresult
	{
		return 1;
	}));

	this->w->add_wndproc_listener(WM_SIZE, [&](hwnd wnd, wparam, lparam) -> void
	{
		rectangle r = window::get_window(wnd)->get_client_rectangle();

		this->m_progressbar_main->set_window_position(5, 5, r.right - 10, r.bottom - 10);
	});
}

progresswindow::~progresswindow()
{
}

void progresswindow::show()
{
	this->w->set_visible(true);
}

void progresswindow::hide()
{
	this->w->set_visible(false);
}

void progresswindow::async_message_loop()
{
	this->w->handle_message();
}

