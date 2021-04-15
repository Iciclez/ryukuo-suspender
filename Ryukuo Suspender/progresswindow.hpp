#pragma once
#include "progressbar.hpp"
#include "window.hpp"

class progresswindow
{
public:
	enum id : int32_t
	{
		progressbar_main = 1
	};

	progresswindow(hinstance inst);
	~progresswindow();

	void show();
	void hide();

	void async_message_loop();

private:
	std::unique_ptr<window> w;
	std::unique_ptr<progressbar> m_progressbar_main;

};