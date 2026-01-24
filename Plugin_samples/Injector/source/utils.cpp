#include "utils.hpp"
#include <cstring>
#include <nid.hpp>
#include <fcntl.h>
#include <string>
#include <sys/sysctl.h>
#include <fstream>
#include <sstream>

extern "C" int sceKernelGetProcessName(int pid, char *out);

void write_log(const char* text)
{
	int text_len = strlen(text);
	int fd = open("/data/etaHEN/injector_plugin.log", O_WRONLY | O_CREAT | O_APPEND, 0777);
	if (fd < 0)
	{
		return;
	}
	write(fd, text, text_len);
	close(fd);
}

void plugin_log(const char* fmt, ...)
{
	char msg[0x1000]{};
	va_list args;
	va_start(args, fmt);
	int msg_len = vsnprintf(msg, sizeof(msg), fmt, args);
	va_end(args);

	// Append newline at the end
	if (msg[msg_len-1] == '\n')
	{
		write_log(msg);
	}
	else
	{
		strcat(msg, "\n");
		write_log(msg);
	}
}

GameConfig parse_config_for_tid(const char* tid)
{
	GameConfig config;
	config.delay = 30; // Default
	config.extra_frames = 0;
	
	std::ifstream file("/data/InjectorPlugin/config.ini");
	if (!file.is_open())
	{
		plugin_log("No config.ini found, using defaults");
		return config;
	}
	
	std::string line;
	std::string current_section = "";
	bool in_target_section = false;
	bool in_default_section = false;
	
	while (std::getline(file, line))
	{
		// Trim whitespace
		line.erase(0, line.find_first_not_of(" \t\r\n"));
		line.erase(line.find_last_not_of(" \t\r\n") + 1);
		
		// Skip empty lines and comments
		if (line.empty() || line[0] == ';' || line[0] == '#')
			continue;
		
		// Section header
		if (line[0] == '[' && line[line.length()-1] == ']')
		{
			current_section = line.substr(1, line.length()-2);
			in_target_section = (current_section == tid);
			in_default_section = (current_section == "default");
			continue;
		}
		
		// Parse key=value
		if (in_target_section || in_default_section)
		{
			size_t eq_pos = line.find('=');
			if (eq_pos != std::string::npos)
			{
				std::string key = line.substr(0, eq_pos);
				std::string value = line.substr(eq_pos + 1);
				
				// Trim key and value
				key.erase(0, key.find_first_not_of(" \t"));
				key.erase(key.find_last_not_of(" \t") + 1);
				value.erase(0, value.find_first_not_of(" \t"));
				value.erase(value.find_last_not_of(" \t") + 1);
				
				if (key == "delay")
				{
					config.delay = std::stoi(value);
				}
				else if (key == "extra_frames")
				{
					config.extra_frames = std::stoi(value);
				}
				else if (key.rfind("/data/", 0) == 0) // Path to PRX
				{
					bool enabled = (value == "true" || value == "1");
					// Section TID override default
					if (in_target_section)
					{
						config.prx_files[key] = enabled;
					}
					else if (in_default_section && config.prx_files.find(key) == config.prx_files.end())
					{
						config.prx_files[key] = enabled;
					}
				}
			}
		}
	}
	
	file.close();
	plugin_log("Config loaded for %s - delay: %d sec, extra_frames: %d, PRX files: %zu", 
			   tid, config.delay, config.extra_frames, config.prx_files.size());
	
	return config;
}
