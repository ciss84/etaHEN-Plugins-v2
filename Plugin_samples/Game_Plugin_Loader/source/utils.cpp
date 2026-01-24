#include "utils.hpp"
#include <cstdio>
#include <cstring>
#include <nid.hpp>
#include <fcntl.h>
#include <string>

void write_log(const char* text)
{
	// Get the REAL length of the text
	int text_len = strlen(text);
	
	// Also print to console for debugging
	printf("%s", text);
	
	// Write to file
	int fd = open("/data/etaHEN/plloader_plugin.log", O_WRONLY | O_CREAT | O_APPEND, 0777);
	if (fd < 0)
	{
		printf("ERROR: Cannot open log file! fd=%d\n", fd);
		return;
	}
	
	int written = write(fd, text, text_len);
	if (written < 0) {
		printf("ERROR: Cannot write to log! written=%d\n", written);
	}
	
	close(fd);
}

void plugin_log(const char* fmt, ...)
{
	char msg[0x1000]{};
	va_list args;
	va_start(args, fmt);
	int msg_len = vsnprintf(msg, sizeof(msg), fmt, args);
	va_end(args);

	// Append newline at the end if not present
	if (msg_len > 0 && msg[msg_len-1] != '\n')
	{
	     strcat(msg, "\n");
	}
	
	write_log(msg);
}

extern "C" int sceSystemServiceGetAppIdOfRunningBigApp();
extern "C" int sceSystemServiceGetAppTitleId(int app_id, char* title_id);

bool Is_Game_Running(int &BigAppid, const char* title_id)
{
	char tid[255];
	BigAppid = sceSystemServiceGetAppIdOfRunningBigApp();
	if (BigAppid < 0)
	{
		return false;
	}

	if (sceSystemServiceGetAppTitleId(BigAppid, &tid[0]) != 0)
	{
		return false;
	}

    if(std::string (tid) == std::string(title_id))
	{
	   plugin_log("%s is running, appid 0x%X", title_id, BigAppid);
       return true;
	}

	return false;
}

bool HookGame(UniquePtr<Hijacker> &hijacker, uint64_t alsr_b, uintptr_t *out_stuffAddr) {
  plugin_log("=== HookGame() START ===");
  plugin_log("ASLR base: 0x%llx", alsr_b);

  GameBuilder builder = BUILDER_TEMPLATE;
  GameStuff stuff{*hijacker};

  plugin_log("Getting libScePad.sprx...");
  UniquePtr<SharedLib> lib = hijacker->getLib("libScePad.sprx");
  if (!lib) {
    plugin_log("ERROR: Failed to get libScePad.sprx!");
    return false;
  }
  plugin_log("libScePad.sprx addr: 0x%llx", lib->imagebase());
  
  plugin_log("Getting scePadReadState address...");
  stuff.scePadReadState = hijacker->getFunctionAddress(lib.get(), nid::scePadReadState);
  plugin_log("scePadReadState addr: 0x%llx", stuff.scePadReadState);
  
  if (stuff.scePadReadState == 0) {
    plugin_log("ERROR: failed to locate scePadReadState");
    return false;
  }

  stuff.ASLR_Base = alsr_b;
  strcpy(stuff.prx_path, "/data/etaHEN/plugins/BeachMenu100.prx");
  plugin_log("PRX path set to: %s", stuff.prx_path);

  plugin_log("Allocating shellcode memory...");
  auto code = hijacker->getTextAllocator().allocate(GameBuilder::SHELLCODE_SIZE);
  plugin_log("Shellcode addr: 0x%llx", code);
  
  plugin_log("Allocating GameStuff memory...");
  auto stuffAddr = hijacker->getDataAllocator().allocate(sizeof(GameStuff));
  plugin_log("GameStuff addr: 0x%llx, size: 0x%zx", stuffAddr, sizeof(GameStuff));
  
  // Save stuffAddr for caller
  if (out_stuffAddr) {
    *out_stuffAddr = stuffAddr;
  }
  
  plugin_log("GameStuff contents:");
  plugin_log("  scePadReadState: 0x%llx", stuff.scePadReadState);
  plugin_log("  debugout: 0x%llx", stuff.debugout);
  plugin_log("  sceKernelLoadStartModule: 0x%llx", stuff.sceKernelLoadStartModule);
  plugin_log("  sceKernelDlsym: 0x%llx", stuff.sceKernelDlsym);
  plugin_log("  ASLR_Base: 0x%llx", stuff.ASLR_Base);
  plugin_log("  prx_path: %s", stuff.prx_path);
  plugin_log("  loaded: %d", stuff.loaded);
  
  plugin_log("Getting eboot metadata...");
  auto meta = hijacker->getEboot()->getMetaData();
  const auto &plttab = meta->getPltTable();
  plugin_log("PLT table obtained");
  
  plugin_log("Getting symbol index for scePadReadState...");
  auto index = meta->getSymbolTable().getSymbolIndex(nid::scePadReadState);
  plugin_log("Symbol index: %u", index);
  
  plugin_log("Searching PLT table...");
  int plt_count = 0;
  for (const auto &plt : plttab) {
    plt_count++;
    if (ELF64_R_SYM(plt.r_info) == index) {
      plugin_log("Found scePadReadState in PLT at entry %d!", plt_count);
      plugin_log("PLT r_offset: 0x%llx", plt.r_offset);
      
      builder.setExtraStuffAddr(stuffAddr);
      plugin_log("Writing shellcode to 0x%llx...", code);
      hijacker->write(code, builder.shellcode);
      
      plugin_log("Writing GameStuff to 0x%llx...", stuffAddr);
      hijacker->write(stuffAddr, stuff);

      uintptr_t hook_adr = hijacker->getEboot()->imagebase() + plt.r_offset;
      plugin_log("PLT hook address: 0x%llx", hook_adr);
      plugin_log("Eboot imagebase: 0x%llx", hijacker->getEboot()->imagebase());

      // Read original PLT entry
      uintptr_t original_plt = hijacker->read<uintptr_t>(hook_adr);
      plugin_log("Original PLT value: 0x%llx", original_plt);

      // Write the hook
      plugin_log("Writing hook pointer...");
      hijacker->write<uintptr_t>(hook_adr, code);
      
      // Verify the hook was written
      uintptr_t verify = hijacker->read<uintptr_t>(hook_adr);
      plugin_log("Verification - Expected: 0x%llx, Got: 0x%llx", code, verify);
      
      if (verify == code) {
        plugin_log("=== Hook installed successfully! ===");
        return true;
      } else {
        plugin_log("ERROR: Hook verification failed!");
        return false;
      }
    }
  }
  
  plugin_log("ERROR: scePadReadState PLT entry not found! Searched %d entries", plt_count);
  return false;
}