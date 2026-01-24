#include "utils.hpp"
#include <cstdio>
#include <cstring>
#include <nid.hpp>
#include <fcntl.h>
#include <string>
#include <fstream>
#include <sstream>

void write_log(const char* text)
{
	int text_len = strlen(text);
	int fd = open("/data/etaHEN/plloader_plugin.log", O_WRONLY | O_CREAT | O_APPEND, 0777);
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

	if (msg_len > 0 && msg[msg_len-1] == '\n')
	{
		write_log(msg);
	}
	else
	{
	     strcat(msg, "\n");
	     write_log(msg);
	}
}

extern "C" int sceSystemServiceGetAppIdOfRunningBigApp();
extern "C" int sceSystemServiceGetAppTitleId(int app_id, char* title_id);

bool Is_Game_Running(int &BigAppid, const char* title_id)
{
	char tid[256]{};
	BigAppid = sceSystemServiceGetAppIdOfRunningBigApp();
	if (BigAppid < 0)
	{
		return false;
	}

	if (sceSystemServiceGetAppTitleId(BigAppid, &tid[0]) != 0)
	{
		return false;
	}

	tid[255] = '\0';

    if(std::string(tid) == std::string(title_id))
	{
	   plugin_log("%s is running, appid 0x%X", title_id, BigAppid);
       return true;
	}

	return false;
}

bool HookGame(UniquePtr<Hijacker> &hijacker, uint64_t alsr_b, const char* prx_path, bool auto_load, int frame_delay) 
{
  plugin_log("Patching Game Now (PRX: %s, Auto-load: %s, Frame delay: %d frames)", 
             prx_path, auto_load ? "YES" : "NO", frame_delay);

  GameBuilder builder = auto_load ? BUILDER_TEMPLATE_AUTO : BUILDER_TEMPLATE;
  size_t shellcode_size = auto_load ? GameBuilder::SHELLCODE_SIZE_AUTO : GameBuilder::SHELLCODE_SIZE;
  
  plugin_log("Using shellcode size: %zu bytes (auto-load: %s)", 
             shellcode_size, auto_load ? "YES with frame delay" : "NO");
  
  GameStuff stuff{*hijacker};

  UniquePtr<SharedLib> lib = hijacker->getLib("libScePad.sprx");
  plugin_log("libScePad.sprx addr: 0x%llx", lib->imagebase());
  stuff.scePadReadState = hijacker->getFunctionAddress(lib.get(), nid::scePadReadState);

  plugin_log("scePadReadState addr: 0x%llx", stuff.scePadReadState);
  if (stuff.scePadReadState == 0) {
    plugin_log("failed to locate scePadReadState");
    return false;
  }

  stuff.ASLR_Base = alsr_b;
  strncpy(stuff.prx_path, prx_path, sizeof(stuff.prx_path) - 1);
  stuff.prx_path[sizeof(stuff.prx_path) - 1] = '\0';
  stuff.frame_delay = frame_delay;
  stuff.frame_counter = 0; // Reset counter
  
  plugin_log("GameStuff configured:");
  plugin_log("  - prx_path: %s", stuff.prx_path);
  plugin_log("  - frame_delay: %d frames (~%.1f seconds at 60fps)", 
             frame_delay, frame_delay / 60.0f);
  plugin_log("  - frame_counter: %d (initial)", stuff.frame_counter);

  auto code = hijacker->getTextAllocator().allocate(shellcode_size);
  plugin_log("shellcode addr: 0x%llx (size: %zu bytes)", code, shellcode_size);
  auto stuffAddr = hijacker->getDataAllocator().allocate(sizeof(GameStuff));
  plugin_log("GameStuff addr: 0x%llx (size: %zu bytes)", stuffAddr, sizeof(GameStuff));
  
  auto meta = hijacker->getEboot()->getMetaData();
  const auto &plttab = meta->getPltTable();
  auto index = meta->getSymbolTable().getSymbolIndex(nid::scePadReadState);
  
  for (const auto &plt : plttab) {
    if (ELF64_R_SYM(plt.r_info) == index) {
      builder.setExtraStuffAddr(stuffAddr);
      
      uint8_t shellcode_buffer[GameBuilder::SHELLCODE_SIZE];
      memcpy(shellcode_buffer, builder.shellcode, shellcode_size);
      
      hijacker->write(code, shellcode_buffer);
      hijacker->write(stuffAddr, stuff);

      uintptr_t hook_adr = hijacker->getEboot()->imagebase() + plt.r_offset;

      hijacker->write<uintptr_t>(hook_adr, code);
      plugin_log("hook addr: 0x%llx", hook_adr);
      plugin_log("PRX injection setup completed successfully!");

      return true;
    }
  }
  
  plugin_log("Failed to find scePadReadState in PLT table");
  return false;
}

GameConfig parse_config_for_tid(const char* tid)
{
	GameConfig config;
	config.default_frame_delay = 300; // Default
	config.apply_fps_patch = false;
	
	std::ifstream file("/data/etaHEN/gtrdloader_config.ini");
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
				
				if (key == "frame_delay")
				{
					config.default_frame_delay = std::stoi(value);
				}
				else if (key == "apply_fps_patch")
				{
					config.apply_fps_patch = (value == "true" || value == "1");
				}
				else if (key.rfind("/data/", 0) == 0) // Path to PRX
				{
					// Format: /path/to/file.prx=true:frame_delay:required
					// Exemple: /data/etaHEN/plugins/BeachMenu105.prx=true:600:true
					
					std::vector<std::string> parts;
					std::stringstream ss(value);
					std::string part;
					while (std::getline(ss, part, ':'))
					{
						parts.push_back(part);
					}
					
					PRXConfig prx;
					prx.path = key;
					
					// Extract filename for name
					size_t slash_pos = key.find_last_of('/');
					if (slash_pos != std::string::npos)
					{
						prx.name = key.substr(slash_pos + 1);
						// Remove .prx extension
						size_t dot_pos = prx.name.find_last_of('.');
						if (dot_pos != std::string::npos)
						{
							prx.name = prx.name.substr(0, dot_pos);
						}
					}
					else
					{
						prx.name = key;
					}
					
					// Parse enabled
					prx.required = (parts.size() > 0 && (parts[0] == "true" || parts[0] == "1"));
					
					// Parse frame_delay (optional, defaults to config.default_frame_delay)
					if (parts.size() > 1)
					{
						prx.frame_delay = std::stoi(parts[1]);
					}
					else
					{
						prx.frame_delay = config.default_frame_delay;
					}
					
					// Parse required (optional, defaults to true)
					if (parts.size() > 2)
					{
						// Note: parts[2] is actually "required" flag
						bool is_required = (parts[2] == "true" || parts[2] == "1");
						prx.required = is_required;
					}
					else
					{
						prx.required = true; // Default to required
					}
					
					// Only add if enabled
					if (parts.size() > 0 && (parts[0] == "true" || parts[0] == "1"))
					{
						config.prx_list.push_back(prx);
					}
				}
			}
		}
	}
	
	file.close();
	plugin_log("Config loaded for %s - default_frame_delay: %d, apply_fps_patch: %s, PRX files: %zu", 
			   tid, config.default_frame_delay, config.apply_fps_patch ? "true" : "false", config.prx_list.size());
	
	return config;
}