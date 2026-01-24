#include "utils.hpp"
#include <cstdio>
#include <cstring>
#include <nid.hpp>
#include <fcntl.h>
#include <string>

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
  plugin_log("Patching Game Now (PRX: %s, Auto-load: %s, Frame delay: %d)", prx_path, auto_load ? "YES" : "NO", frame_delay);

  GameBuilder builder = auto_load ? BUILDER_TEMPLATE_AUTO : BUILDER_TEMPLATE;
  size_t shellcode_size = auto_load ? GameBuilder::SHELLCODE_SIZE_AUTO : GameBuilder::SHELLCODE_SIZE;
  
  plugin_log("Using shellcode size: %zu bytes", shellcode_size);
  
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

  auto code = hijacker->getTextAllocator().allocate(shellcode_size);
  plugin_log("shellcode addr: 0x%llx (size: %zu bytes)", code, shellcode_size);
  auto stuffAddr = hijacker->getDataAllocator().allocate(sizeof(GameStuff));
  
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

      return true;
    }
  }
  
  plugin_log("Failed to find scePadReadState in PLT table");
  return false;
}
