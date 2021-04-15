#pragma once
#include "checkbox.hpp"
#include "numericupdown.hpp"
#include "textbox.hpp"
#include "tabcontrol.hpp"
#include "label.hpp"

#include "mainwindow.hpp"

#include <memory>

class mainwindow;

class automaticsuspenderview
{
public:
	enum log_type : int32_t
	{
		FOUND = 1,
		SUSPENDED,
		RESUMED,
		OPENPROCESS_ERROR,
		UNKNOWN_ERROR,
	};
public:
	automaticsuspenderview(tabcontrol *ptabcontrol, mainwindow *pmainwindow, const rectangle &r, uint32_t &id);
	~automaticsuspenderview();

	std::vector<widget*> get_widgets();

	void size(const rectangle &r);
	void log(log_type type, uint32_t process_id, std::string process_name);

private:
	std::unique_ptr<checkbox> m_checkbox;
	std::unique_ptr<numericupdown> m_numericupdown;
	std::unique_ptr<textbox> m_textbox;
	std::unique_ptr<label> m_textbox_label;
	std::unique_ptr<label> m_numericupdown_label;

	tabcontrol *ptabcontrol;
	mainwindow *pmainwindow;
};

