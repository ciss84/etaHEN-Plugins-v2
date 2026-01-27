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
  stuff.loaded = 0;        // Force reset - permet multi-PRX
  stuff.game_hash = 0;     // Force reset - ignore hash check
  
  plugin_log("GameStuff configured:");
  plugin_log("  - prx_path: %s", stuff.prx_path);
  plugin_log("  - frame_delay: %d frames (~%.1f seconds at 60fps)", 
             frame_delay, frame_delay / 60.0f);
  plugin_log("  - frame_counter: %d (initial)", stuff.frame_counter);
  plugin_log("  - loaded: %d (forced to 0 for multi-PRX)", stuff.loaded);

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

// ============================================================
// HookGameMultiPRX - VERSION TEMPORAIRE FALLBACK
// ============================================================
// Cette version appelle HookGame() pour chaque PRX
// ATTENTION: Seul le DERNIER PRX fonctionnera car les hooks s'écrasent!
// Pour la vraie solution multi-PRX, il faut compiler Shellcode_MultiPRX.c
// ============================================================
bool HookGameMultiPRX(UniquePtr<Hijacker> &executable, uint64_t text_base, const std::vector<PRXConfig> &prx_list)
{
	plugin_log("=== MULTI-PRX HOOK (TEMPORARY FALLBACK MODE) ===");
	plugin_log("WARNING: Using old method - only last PRX will work!");
	plugin_log("To fix: compile Shellcode_MultiPRX.c and update this function");
	
	if (prx_list.empty())
	{
		plugin_log("ERROR: No PRX to inject");
		return false;
	}
	
	int success_count = 0;
	
	// Appelle l'ancien HookGame() pour chaque PRX
	// PROBLÈME: Chaque appel écrase le hook précédent!
	for (const auto& prx : prx_list)
	{
		plugin_log("Installing hook for: %s (frame_delay: %d)", 
		           prx.path.c_str(), prx.frame_delay);
		
		if (HookGame(executable, text_base, prx.path.c_str(), true, prx.frame_delay))
		{
			plugin_log("Hook installed (but may be overwritten by next PRX)");
			success_count++;
		}
		else
		{
			plugin_log("FAILED to install hook for: %s", prx.path.c_str());
		}
		
		usleep(100000);  // 100ms entre chaque
	}
	
	plugin_log("========================================");
	plugin_log("Fallback: %d/%zu hooks installed", success_count, prx_list.size());
	plugin_log("Only the LAST PRX (%s) will actually work!", 
	           prx_list.back().path.c_str());
	plugin_log("========================================");
	
	return (success_count > 0);
}