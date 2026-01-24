#include "utils.hpp"
#include <notify.hpp>
#include <signal.h>

void sig_handler(int signo)
{
	printBacktraceForCrash();
    printf("ItemzLocalKillApp(sceSystemServiceGetAppId(BLOP60000)) returned %i\n", 
           sceSystemServiceKillApp(sceSystemServiceGetAppId("BLOP60000"), -1, 0, 0));
}

extern "C"{
	int32_t sceKernelPrepareToSuspendProcess(pid_t pid);
	int32_t sceKernelSuspendProcess(pid_t pid);
	int32_t sceKernelPrepareToResumeProcess(pid_t pid);
	int32_t sceKernelResumeProcess(pid_t pid);
	int32_t sceUserServiceInitialize(int32_t* priority);
	int32_t sceUserServiceGetForegroundUser(int32_t* new_id);
	int32_t sceSysmoduleLoadModuleInternal(uint32_t moduleId);
	int32_t sceSysmoduleUnloadModuleInternal(uint32_t moduleId);
	int32_t sceVideoOutOpen();
	int32_t sceVideoOutConfigureOutput();
	int32_t sceVideoOutIsOutputSupported();

	int sceKernelLoadStartModule(const char *name, size_t argc, const void *argv, 
	                             uint32_t flags, void *option, int *res);
}

static void SuspendApp(pid_t pid)
{
	sceKernelPrepareToSuspendProcess(pid);
	sceKernelSuspendProcess(pid);
}

#define HOOKED_GAME_TID "PPSA04264"

static void ResumeApp(pid_t pid)
{
	usleep(1000);
	sceKernelPrepareToResumeProcess(pid);
	sceKernelResumeProcess(pid);
}

uintptr_t kernel_base = 0;
uintptr_t g_stuffAddr = 0;

int main()
{
	plugin_log("=== Game Plugin Loader 0.0.5 FINAL ===");

	payload_args_t *args = payload_get_args();
	kernel_base = args->kdata_base_addr;

	struct sigaction new_SIG_action;
	new_SIG_action.sa_handler = sig_handler;
	sigemptyset(&new_SIG_action.sa_mask);
	new_SIG_action.sa_flags = 0;

	for (int i = 0; i < 12; i++)
		sigaction(i, &new_SIG_action, NULL);

	unlink("/data/etaHEN/plloader_plugin.log");

	printf_notification("Game Plugin Loader 0.0.5");
	plugin_log("Starting plugin loader...");
    
	String title_id;
	int appid = 0;
	plugin_log("Waiting for game %s to start...", HOOKED_GAME_TID);
	
	while(!Is_Game_Running(appid, HOOKED_GAME_TID))
	{
		usleep(200000);
	}

	plugin_log("Game detected! AppID: 0x%X", appid);
	printf_notification("Game detected!");

	// DON'T suspend yet - let the game load its libraries first
	plugin_log("Waiting for game to initialize libraries...");
	sleep(3); // Wait 3 seconds for game to load its libraries

	// Now suspend
	SuspendApp(appid);
	plugin_log("Game suspended");

	int bappid = 0, pid = 0;
	for (size_t j = 0; j <= 9999; j++) {
        if(_sceApplicationGetAppId(j, &bappid) < 0)
            continue;

        if(appid == bappid){
            pid = j;
	        plugin_log("Found PID: %i for AppID: 0x%X", pid, appid);
            break;
        }
    }

	if (pid == 0) {
		plugin_log("ERROR: Failed to find PID");
		printf_notification("ERROR: No PID!");
		return -1;
	}

	plugin_log("Getting hijacker for PID %d...", pid);
	UniquePtr<Hijacker> executable = Hijacker::getHijacker(pid);
	if (!executable)
	{
		plugin_log("ERROR: Failed to get hijacker");
		printf_notification("ERROR: Hijacker failed!");
		return -1;
	}
	plugin_log("Hijacker obtained successfully");

	// Check if libScePad.sprx is loaded
	plugin_log("Checking if libScePad.sprx is loaded...");
	UniquePtr<SharedLib> test_lib = executable->getLib("libScePad.sprx");
	
	if (!test_lib) {
		plugin_log("libScePad.sprx not loaded yet, resuming game to let it load...");
		printf_notification("Waiting for libraries...");
		ResumeApp(pid);
		
		// Wait for libScePad.sprx to be loaded
		int wait_count = 0;
		bool lib_loaded = false;
		
		while (!lib_loaded && wait_count < 30) { // Wait max 30 seconds
			sleep(1);
			wait_count++;
			
			// Try to get the library again
			test_lib = executable->getLib("libScePad.sprx");
			if (test_lib) {
				lib_loaded = true;
				plugin_log("libScePad.sprx loaded after %d seconds!", wait_count);
				break;
			}
			
			if (wait_count % 5 == 0) {
				plugin_log("Still waiting for libScePad.sprx... (%d seconds)", wait_count);
			}
		}
		
		if (!lib_loaded) {
			plugin_log("ERROR: libScePad.sprx never loaded after 30 seconds!");
			printf_notification("ERROR: Library not loaded!");
			return -1;
		}
		
		// Suspend again now that library is loaded
		plugin_log("Library loaded, suspending game again...");
		SuspendApp(appid);
		sleep(1);
		
		// Re-get hijacker after resume/suspend
		plugin_log("Re-getting hijacker...");
		executable = Hijacker::getHijacker(pid);
		if (!executable) {
			plugin_log("ERROR: Failed to re-get hijacker");
			printf_notification("ERROR: Hijacker failed!");
			ResumeApp(pid);
			return -1;
		}
	} else {
		plugin_log("libScePad.sprx already loaded!");
	}

	uintptr_t text_base = executable->getEboot()->getTextSection()->start();
	uint64_t text_size = executable->getEboot()->getTextSection()->sectionLength();
	
	if (text_base == 0 || text_size == 0)
	{
		plugin_log("ERROR: Invalid text section - base: 0x%llx, size: 0x%llx", 
		           text_base, text_size);
		printf_notification("ERROR: Invalid memory!");
		ResumeApp(pid);
		return -1;
	}

	plugin_log("Text section OK - base: 0x%llx, size: 0x%llx", text_base, text_size);
	printf_notification("Installing hook...");
	
	plugin_log("Calling HookGame()...");
	bool hook_result = HookGame(executable, text_base, &g_stuffAddr);
	plugin_log("HookGame() returned: %d", hook_result);
	
	if(!hook_result){
		plugin_log("ERROR: HookGame failed!");
		printf_notification("ERROR: Hook failed!");
		ResumeApp(pid);
		return -1;
	}

	plugin_log("Hook installed successfully!");
	plugin_log("GameStuff is at address: 0x%llx", g_stuffAddr);
	printf_notification("Hook OK! Resuming...");

	sleep(2);
	
	plugin_log("Resuming game...");
	ResumeApp(pid);
	plugin_log("Game resumed!");
	//printf_notification("Game running! Use controller to load PRX...");

	// Monitor the loaded flag
	plugin_log("Monitoring PRX load status...");
	plugin_log("Waiting for scePadReadState to be called...");
	
	bool prx_loaded = false;
	int check_count = 0;
	int seconds_waited = 0;
	
	while(!prx_loaded) {
		sleep(2);
		seconds_waited += 2;
		check_count++;
		
		// Try to read the 'loaded' flag from game memory
		int loaded_flag = 0;
		bool read_success = executable->read(g_stuffAddr + 0x128, &loaded_flag, sizeof(int));
		
		if (read_success && loaded_flag == 1) {
			plugin_log("=================================================");
			plugin_log("!!! PRX LOADED SUCCESSFULLY !!!");
			plugin_log("PRX loaded after %d seconds", seconds_waited);
			plugin_log("=================================================");
			printf_notification("PRX LOADED!");
			prx_loaded = true;
			break;
		}
		
		// Log every 10 seconds
		if (check_count % 5 == 0) {
			plugin_log("Still waiting for controller input... (%d seconds)", seconds_waited);
		}
		
		// After 2 minutes, warn user
		if (seconds_waited == 120) {
			plugin_log("WARNING: PRX still not loaded after 2 minutes");
			plugin_log("Make sure you are using the controller in the game!");
			//printf_notification("Use your controller in game!");
		}
	}

	// PRX is loaded, continue monitoring
	plugin_log("Plugin loader will continue running in background...");
	
	while(1) {
		sleep(60);
		plugin_log("Plugin loader still active (PRX loaded)");
	}

	return 0;
}