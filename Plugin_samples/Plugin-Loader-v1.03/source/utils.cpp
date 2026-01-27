#include "utils.hpp"
#include <cstdio>
#include <cstring>
#include <nid.hpp>
#include <fcntl.h>
#include <string>

void write_log(const char* text)
{
	int text_len = strlen(text);
	int fd = open("/data/PluginLoader/PluginLoader.log", O_WRONLY | O_CREAT | O_APPEND, 0777);
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
  // Legacy function - just call HookMultiPRX with single PRX
  std::vector<PRXConfig> single_prx;
  PRXConfig prx;
  prx.path = prx_path;
  prx.frame_delay = frame_delay;
  single_prx.push_back(prx);
  
  return HookMultiPRX(hijacker, alsr_b, single_prx);
}

GameInjectorConfig parse_injector_config()
{
	GameInjectorConfig config;

	// Use POSIX open instead of std::ifstream for PS5 compatibility
	int fd = open("/data/PluginLoader/PluginLoader.ini", O_RDONLY);
	if (fd < 0)
	{
		plugin_log("No PluginLoader.ini found at /data/PluginLoader/PluginLoader.ini");
		return config;
	}

	// Read entire file (max 8KB config)
	char buffer[8192];
	int bytes_read = read(fd, buffer, sizeof(buffer) - 1);
	close(fd);
	
	if (bytes_read <= 0)
	{
		plugin_log("Failed to read PluginLoader.ini");
		return config;
	}
	buffer[bytes_read] = '\0';

	plugin_log("Config file read successfully: %d bytes", bytes_read);

	// Parse buffer line by line manually
	std::string current_tid = "";
	char* ptr = buffer;
	char* line_start = ptr;

	while (ptr < buffer + bytes_read)
	{
		// Find end of line
		if (*ptr == '\n' || *ptr == '\r' || ptr >= buffer + bytes_read - 1)
		{
			// Extract line
			size_t line_len = ptr - line_start;
			if (ptr >= buffer + bytes_read - 1 && *ptr != '\n' && *ptr != '\r')
			{
				line_len++;
			}
			
			std::string line(line_start, line_len);
			
			// Trim whitespace
			size_t start = line.find_first_not_of(" \t\r");
			size_t end = line.find_last_not_of(" \t\r");
			
			if (start != std::string::npos && end != std::string::npos)
			{
				line = line.substr(start, end - start + 1);
			}
			else
			{
				line = "";
			}

			// Skip empty lines and comments
			if (!line.empty() && line[0] != ';' && line[0] != '#')
			{
				// Section header [TID]
				if (line[0] == '[' && line[line.length()-1] == ']')
				{
					current_tid = line.substr(1, line.length()-2);
					plugin_log("Config: Found section [%s]", current_tid.c_str());
				}
				// PRX line
				else if (!current_tid.empty())
				{
					// Format: filename.prx:frame_delay
					size_t colon_pos = line.find(':');
					std::string prx_file;
					int frame_delay = 60;

					if (colon_pos != std::string::npos)
					{
						prx_file = line.substr(0, colon_pos);
						frame_delay = atoi(line.substr(colon_pos + 1).c_str());
					}
					else
					{
						prx_file = line;
					}

					// Build full path
					std::string full_path = "/data/PluginLoader/" + prx_file;

					PRXConfig prx;
					prx.path = full_path;
					prx.frame_delay = frame_delay;

					config.games[current_tid].push_back(prx);

					plugin_log("Config: [%s] -> %s (delay: %d frames)",
							   current_tid.c_str(), full_path.c_str(), frame_delay);
				}
			}

			// Move to next line
			if (*ptr == '\r' && ptr + 1 < buffer + bytes_read && *(ptr + 1) == '\n')
			{
				ptr += 2;  // Skip \r\n
			}
			else if (*ptr == '\n' || *ptr == '\r')
			{
				ptr++;  // Skip \n or \r
			}
			else
			{
				ptr++;  // End of buffer
			}
			line_start = ptr;
		}
		else
		{
			ptr++;
		}
	}

	plugin_log("Config parsing complete: %zu games configured", config.games.size());
	return config;
}

// Multi-PRX hook - UN SEUL hook pour TOUS les PRX!
bool HookMultiPRX(UniquePtr<Hijacker> &hijacker, uint64_t alsr_b, const std::vector<PRXConfig> &prx_list)
{
	if (prx_list.empty()) {
		plugin_log("HookMultiPRX: No PRX to inject");
		return false;
	}
	
	if (prx_list.size() > 8) {
		plugin_log("HookMultiPRX: Too many PRX (%zu), max is 8", prx_list.size());
		return false;
	}
	
	plugin_log("========================================");
	plugin_log("Multi-PRX Hook: Setting up %zu PRX", prx_list.size());
	plugin_log("========================================");
	
	GameStuff stuff{*hijacker};
	
	UniquePtr<SharedLib> lib = hijacker->getLib("libScePad.sprx");
	plugin_log("libScePad.sprx addr: 0x%llx", lib->imagebase());
	stuff.scePadReadState = hijacker->getFunctionAddress(lib.get(), nid::scePadReadState);
	
	plugin_log("scePadReadState addr: 0x%llx", stuff.scePadReadState);
	if (stuff.scePadReadState == 0) {
		plugin_log("FAILED: scePadReadState not found");
		return false;
	}
	
	stuff.ASLR_Base = alsr_b;
	stuff.frame_counter = 0;
	stuff.prx_count = prx_list.size();
	
	// Fill PRX list
	for (size_t i = 0; i < prx_list.size(); i++) {
		strncpy(stuff.prx_list[i].path, prx_list[i].path.c_str(), 255);
		stuff.prx_list[i].path[255] = '\0';
		stuff.prx_list[i].frame_delay = prx_list[i].frame_delay;
		stuff.prx_list[i].loaded = 0;
		stuff.prx_list[i]._pad = 0;
		
		plugin_log("  [%zu] %s (delay: %d frames = %.1f sec)", 
		           i, stuff.prx_list[i].path, 
		           stuff.prx_list[i].frame_delay,
		           stuff.prx_list[i].frame_delay / 60.0f);
	}
	
	// Allocate shellcode and data
	auto code = hijacker->getTextAllocator().allocate(GameBuilder::SHELLCODE_SIZE_MULTI);
	plugin_log("Shellcode addr: 0x%llx (size: %d bytes)", code, GameBuilder::SHELLCODE_SIZE_MULTI);
	
	auto stuffAddr = hijacker->getDataAllocator().allocate(sizeof(GameStuff));
	plugin_log("GameStuff addr: 0x%llx (size: %zu bytes)", stuffAddr, sizeof(GameStuff));
	
	// Setup builder
	GameBuilder builder = BUILDER_TEMPLATE_MULTI;
	builder.setExtraStuffAddr(stuffAddr);
	
	uint8_t shellcode_buffer[256];
	memcpy(shellcode_buffer, builder.shellcode, GameBuilder::SHELLCODE_SIZE_MULTI);
	
	// Write shellcode and data
	hijacker->write(code, shellcode_buffer);
	hijacker->write(stuffAddr, stuff);
	
	// Hook scePadReadState PLT entry
	auto meta = hijacker->getEboot()->getMetaData();
	const auto &plttab = meta->getPltTable();
	auto index = meta->getSymbolTable().getSymbolIndex(nid::scePadReadState);
	
	for (const auto &plt : plttab) {
		if (ELF64_R_SYM(plt.r_info) == index) {
			uintptr_t hook_adr = hijacker->getEboot()->imagebase() + plt.r_offset;
			hijacker->write<uintptr_t>(hook_adr, code);
			
			plugin_log("Hook installed at 0x%llx", hook_adr);
			plugin_log("========================================");
			plugin_log("SUCCESS! All %zu PRX will auto-load:", prx_list.size());
			for (size_t i = 0; i < prx_list.size(); i++) {
				plugin_log("  %s @ frame %d", prx_list[i].path.c_str(), prx_list[i].frame_delay);
			}
			plugin_log("========================================");
			
			return true;
		}
	}
	
	plugin_log("FAILED: scePadReadState not in PLT");
	return false;
}