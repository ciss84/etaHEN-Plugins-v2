#include "utils.hpp"
#include <notify.hpp>
#include <signal.h>
#include <string>
#include <ps5/kernel.h>

extern "C"
{
	int sceSystemServiceGetAppIdOfRunningBigApp();
	int sceSystemServiceGetAppTitleId(int app_id, char *title_id);
	int32_t sceKernelPrepareToSuspendProcess(pid_t pid);
	int32_t sceKernelSuspendProcess(pid_t pid);
	int32_t sceKernelPrepareToResumeProcess(pid_t pid);
	int32_t sceKernelResumeProcess(pid_t pid);
}

void sig_handler(int signo)
{
	printf_notification("Plugin Loader v1.05 Multi-PRX crashed with signal %d", signo);
	printBacktraceForCrash();
	exit(-1);
}

bool Get_Running_App_TID(std::string &title_id, int &BigAppid)
{
	char tid[255];
	BigAppid = sceSystemServiceGetAppIdOfRunningBigApp();
	if (BigAppid < 0) return false;

	memset(tid, 0, sizeof(tid));
	if (sceSystemServiceGetAppTitleId(BigAppid, &tid[0]) != 0)
		return false;

	title_id = std::string(tid);
	return true;
}

bool IsProcessRunning(pid_t pid)
{
	int bappid = 0;
	return (_sceApplicationGetAppId(pid, &bappid) >= 0);
}

static void SuspendApp(pid_t pid)
{
	sceKernelPrepareToSuspendProcess(pid);
	sceKernelSuspendProcess(pid);
}

static void ResumeApp(pid_t pid)
{
	usleep(500000);
	sceKernelPrepareToResumeProcess(pid);
	sceKernelResumeProcess(pid);
}

uintptr_t kernel_base = 0;

int main()
{
	plugin_log("=== PLUGIN LOADER v1.05 MULTI-PRX UNIFIED HOOK ===");
	plugin_log("This version uses ONE hook to load multiple PRX");

	payload_args_t *args = payload_get_args();
	kernel_base = args->kdata_base_addr;

	struct sigaction new_SIG_action;
	new_SIG_action.sa_handler = sig_handler;
	sigemptyset(&new_SIG_action.sa_mask);
	new_SIG_action.sa_flags = 0;

	for (int i = 0; i < 12; i++)
		sigaction(i, &new_SIG_action, NULL);

	plugin_log("Plugin Loader v1.05 ready - monitoring games");
	printf_notification("Plugin Loader v1.05 Multi-PRX started");

	int last_attempted_appid = -1;

	while(1)
	{
		GameInjectorConfig config = parse_injector_config();
		plugin_log("Config loaded - %zu games configured", config.games.size());

		int appid = 0;
		std::string tid;
		const char* detected_tid = nullptr;

		// Wait for game to launch
		while(true)
		{
			if (!Get_Running_App_TID(tid, appid))
			{
				usleep(500000);
				continue;
			}

			if (appid == last_attempted_appid)
			{
				usleep(500000);
				continue;
			}

			if (tid.rfind("CUSA") != std::string::npos ||
				tid.rfind("SCUS") != std::string::npos ||
				tid.rfind("PPSA") != std::string::npos)
			{
				detected_tid = tid.c_str();
				break;
			}

			usleep(500000);
		}

		plugin_log("========================================");
		plugin_log("Game detected: %s (appid: %d)", detected_tid, appid);
		plugin_log("========================================");

		last_attempted_appid = appid;

		// Check if we have config for this game
		auto it = config.games.find(detected_tid);
		if (it == config.games.end())
		{
			plugin_log("No config for %s - skipping", detected_tid);
			int current_appid = appid;
			while(true)
			{
				int check_appid = 0;
				std::string check_tid;
				if (!Get_Running_App_TID(check_tid, check_appid) || check_appid != current_appid)
				{
					break;
				}
				sleep(5);
			}
			last_attempted_appid = -1;
			continue;
		}

		std::vector<PRXConfig> &prx_list = it->second;
		plugin_log("Found %zu PRX to inject for %s", prx_list.size(), detected_tid);

		// CRITICAL: Limit to MAX 4 PRX (shellcode limitation)
		if (prx_list.size() > 4)
		{
			plugin_log("WARNING: More than 4 PRX configured, only first 4 will be loaded");
		}

		// Find the real PID
		plugin_log("Searching for real PID (appid=%d)...", appid);
		int bappid = 0;
		pid_t pid = 0;
		
		for (int retry = 0; retry < 10 && pid == 0; retry++) {
			for (size_t j = 0; j <= 9999; j++) {
				if (_sceApplicationGetAppId(j, &bappid) < 0)
					continue;
				if (appid == bappid) {
					pid = j;
					plugin_log("Real PID found: %d (retry %d)", pid, retry);
					break;
				}
			}
			if (pid == 0) {
				usleep(50000);
			}
		}
		
		if (pid == 0) {
			plugin_log("ERROR: Failed to find real PID after 10 retries");
			last_attempted_appid = -1;
			continue;
		}

		plugin_log("PID: %d (converted from appid: %d)", pid, appid);

		// Wait for process initialization
		plugin_log("Waiting for process initialization...");
		
		int alive_count = 0;
		for (int i = 0; i < 5; i++)
		{
			usleep(100000);
			if (IsProcessRunning(pid))
				alive_count++;
		}
		
		plugin_log("Process check: %d/5 alive", alive_count);
		
		if (alive_count == 0)
		{
			plugin_log("WARNING: Process appears dead, trying injection anyway");
		}

		// Create hijacker
		plugin_log("Creating hijacker for PID %d...", pid);
		UniquePtr<Hijacker> executable = Hijacker::getHijacker(pid);
		
		if (!executable)
		{
			plugin_log("First hijacker attempt failed, retrying in 1s...");
			sleep(1);
			executable = Hijacker::getHijacker(pid);
		}
		
		if (!executable)
		{
			plugin_log("FAILED to create Hijacker for pid %d", pid);
			
			int current_appid = appid;
			int wait_count = 0;
			while(wait_count < 60)
			{
				int check_appid = 0;
				std::string check_tid;
				if (!Get_Running_App_TID(check_tid, check_appid) || check_appid != current_appid)
				{
					break;
				}
				sleep(5);
				wait_count++;
			}
			last_attempted_appid = -1;
			continue;
		}

		plugin_log("Hijacker created successfully!");

		uint64_t text_base = executable->getEboot()->imagebase();
		plugin_log("Process attached - text_base: 0x%llx", text_base);

		// Suspend game
		plugin_log("Suspending game...");
		SuspendApp(pid);
		usleep(500000); // 500ms apres suspend

		// ========================================
		// MULTI-PRX INJECTION - ONE HOOK FOR ALL
		// ========================================
		plugin_log("Installing unified multi-PRX hook for %zu PRX...", prx_list.size());
		
		bool hook_success = HookGameMultiPRX(executable, text_base, prx_list);
		
		if (hook_success)
		{
			plugin_log("SUCCESS: Unified hook installed for %zu PRX", prx_list.size());
			for (size_t i = 0; i < prx_list.size(); i++)
			{
				plugin_log("  [%zu] %s (delay: %d frames)", 
					i+1, prx_list[i].path.c_str(), prx_list[i].frame_delay);
			}
		}
		else
		{
			plugin_log("FAILED: Could not install unified hook");
		}

		usleep(500000); // 500ms apres injection

		// Resume game
		plugin_log("Resuming game...");
		ResumeApp(pid);

		plugin_log("========================================");
		if (hook_success)
		{
			plugin_log("Multi-PRX hook active: %zu PRX will auto-load", prx_list.size());
		}
		else
		{
			plugin_log("Hook installation failed");
		}
		plugin_log("========================================");

		if (hook_success)
		{
			printf_notification("Multi-PRX hook: %zu plugins for %s", 
								prx_list.size(), detected_tid);
		}
		else
		{
			printf_notification("Hook failed for %s", detected_tid);
		}

		// Wait for game to close
		plugin_log("Waiting for game to close (monitoring appid %d)...", appid);
		int current_appid = appid;
		int monitor_count = 0;
		while(monitor_count < 720)
		{
			int check_appid = 0;
			std::string check_tid;
			if (!Get_Running_App_TID(check_tid, check_appid) || check_appid != current_appid)
			{
				plugin_log("Game closed (was %d, now %d)", current_appid, check_appid);
				break;
			}
			sleep(5);
			monitor_count++;
		}

		plugin_log("Game closed - ready for next launch");
		last_attempted_appid = -1;
	}

	return 0;
}