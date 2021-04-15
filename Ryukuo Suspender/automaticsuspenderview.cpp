#include "automaticsuspenderview.hpp"
#include "window.hpp"
#include "inject.hpp"
#include "resource.h"

#include <unordered_set>
#include <thread>
#include <atomic>
#include <functional>
#include <algorithm>
#include <sstream>

automaticsuspenderview::automaticsuspenderview(tabcontrol *ptabcontrol, mainwindow *pmainwindow, const rectangle &r, uint32_t &id)
{
	this->ptabcontrol = ptabcontrol;
	this->pmainwindow = pmainwindow;

	hfont bold_font = widget::make_font("Segoe UI", 14);
	//hfont bold_font = widget::make_font("Aria", 16);

	this->m_textbox_label = std::move(std::make_unique<label>(id++, 330, 50, 80, 20, "Process Name: ", ptabcontrol->get_parent()));
	this->m_numericupdown_label = std::move(std::make_unique<label>(id++, 330, 75, 80, 20, "Delay (ms): ", ptabcontrol->get_parent()));

	this->m_textbox_label->set_font(bold_font);
	this->m_numericupdown_label->set_font(bold_font);

	this->m_textbox = std::move(std::make_unique<textbox>(id++, 415, 50, r.right - 430, 20, "", ptabcontrol->get_parent()));
	this->m_numericupdown = std::move(std::make_unique<numericupdown>(id++, id++, 415, 75, r.right - 430, 20, "1000", ptabcontrol->get_parent(), 0));
	this->m_checkbox = std::move(std::make_unique<checkbox>(id++, r.right - 130, r.bottom - 60, 115, 20, "Automatic Suspend", ptabcontrol->get_parent()));
	
	this->m_textbox->append_style(ES_CENTER);

	window * w = window::get_window(ptabcontrol->get_parent());

	this->size(w->get_client_rectangle());

	w->add_message_handler(std::make_pair(GetDlgCtrlID(this->m_checkbox->get_handle()), [this](hwnd, wparam, lparam) -> lresult
	{

		if (this->m_textbox->get_text().empty() || !this->m_textbox->get_text().compare(""))
		{
			return 0;
		}		


		if (this->m_checkbox->is_checked())
		{
			this->m_textbox->set_enabled(false);
			this->m_numericupdown->set_enabled(false);
		
			std::thread([&]()
			{
				std::unordered_set<dword> suspended_container;
				std::vector<dword> process_id_container;
				while (this->m_checkbox->is_checked())
				{
					process_id_container = inject::get_process_id(this->m_textbox->get_text());
					if (!process_id_container.empty())
					{
						Sleep(std::stoi(this->m_numericupdown->get_text()) > 0 ?
							std::stoi(this->m_numericupdown->get_text()) : 333);

						for (dword process_id : process_id_container)
						{
							if (!suspended_container.count(process_id))
							{
								this->log(FOUND, process_id, this->m_textbox->get_text());
								handle process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
								if (process)
								{
									inject::suspend(process);
									this->log(SUSPENDED, process_id, this->m_textbox->get_text());
									CloseHandle(process);
									suspended_container.insert(process_id);
								}
								else
								{
									this->log(OPENPROCESS_ERROR, process_id, this->m_textbox->get_text());
								}
							}
						}
					}
				}

			}).detach();

		}
		else
		{
			this->m_textbox->set_enabled(true);
			this->m_numericupdown->set_enabled(true);

			std::vector<dword> process_id_container = inject::get_process_id(this->m_textbox->get_text());
			for (dword process_id : process_id_container)
			{
				this->log(FOUND, process_id, this->m_textbox->get_text());
				handle process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
				if (process)
				{
					inject::resume(process);
					this->log(RESUMED, process_id, this->m_textbox->get_text());
					CloseHandle(process);
				}
				else
				{
					this->log(OPENPROCESS_ERROR, process_id, this->m_textbox->get_text());
				}
			}
		}

		return 0;
	}));

}


automaticsuspenderview::~automaticsuspenderview()
{
}

std::vector<widget*> automaticsuspenderview::get_widgets()
{
	std::vector<widget*> pwidgets;
	pwidgets.push_back(m_checkbox.get());
	pwidgets.push_back(m_numericupdown.get());
	pwidgets.push_back(m_textbox.get());
	pwidgets.push_back(m_numericupdown->get_updown());
	return pwidgets;
}

void automaticsuspenderview::size(const rectangle & r)
{
	this->m_textbox->set_window_position(415, 50, r.right - 430, 20);
	this->m_numericupdown->set_window_position(415, 75, r.right - 430, 20);
	this->m_checkbox->set_window_position(r.right - 130, r.bottom - 60, 115, 20);
	this->m_numericupdown->set_buddy();
}

//info: copy process_name over as we will be mutating it
void automaticsuspenderview::log(log_type type, uint32_t process_id, std::string process_name)
{
	std::stringstream ss;

	ss << "[+] automatic:";

	switch (type)
	{
	case FOUND:
		ss << " successfully found process ";
		break;
	case SUSPENDED:
		ss << " successfully suspended process ";
		break;
	case RESUMED:
		ss << " successfully resumed process ";
		break;
	case OPENPROCESS_ERROR:
		ss << " openprocess error occur when transacting process ";
		break;
	case UNKNOWN_ERROR:
		ss << " unknown error occured when transacting process ";
		break;
	default:
		ss << " unknown error occured when transacting process ";
		break;
	}

	std::transform(process_name.begin(), process_name.end(), process_name.begin(), tolower);

	ss << "'" << process_name << "' "
		<< ", process id: %d (%.08X)";
	
	l.log(ss.str(), process_id, process_id);
}
