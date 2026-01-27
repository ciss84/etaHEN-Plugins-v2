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
	printf_notification("Plugin Loader v1.04 crashed with signal %d", signo);
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
	plugin_log("=== Plugin Loader v1.04 WITH SUSPEND CONTROL ===");
	plugin_log("Config format: PRX:delay=true/false (true=suspend game)");

	payload_args_t *args = payload_get_args();
	kernel_base = args->kdata_base_addr;

	struct sigaction new_SIG_action;
	new_SIG_action.sa_handler = sig_handler;
	sigemptyset(&new_SIG_action.sa_mask);
	new_SIG_action.sa_flags = 0;

	for (int i = 0; i < 12; i++)
		sigaction(i, &new_SIG_action, NULL);

	plugin_log("Plugin Loader v1.04 ready - monitoring games");
	printf_notification("Plugin Loader v1.04 started");

	int last_attempted_appid = -1;

	while(1)
	{
		// Reload config at each iteration
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

			// Skip if same appid we just attempted
			if (appid == last_attempted_appid)
			{
				usleep(500000);
				continue;
			}

			// Check if it's a game
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
			// Wait for game to close
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

		// Find real PID
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
		plugin_log("Waiting 2 seconds for process initialization...");
		sleep(2);

		// Create hijacker
		plugin_log("Creating hijacker for PID %d...", pid);
		UniquePtr<Hijacker> executable = Hijacker::getHijacker(pid);
		
		if (!executable)
		{
			plugin_log("First hijacker attempt failed, waiting 1s and retrying...");
			sleep(1);
			executable = Hijacker::getHijacker(pid);
		}
		
		if (!executable)
		{
			plugin_log("FAILED to create Hijacker for pid %d after retries", pid);
			
			// Wait for game to close
			int current_appid = appid;
			while(current_appid == appid)
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

		plugin_log("Hijacker created successfully!");

		uint64_t text_base = executable->getEboot()->imagebase();
		plugin_log("Process attached - text_base: 0x%llx", text_base);

		// INJECT EACH PRX WITH INDIVIDUAL SUSPEND CONTROL
		int success_count = 0;
		for (size_t i = 0; i < prx_list.size(); i++)
		{
			const PRXConfig &prx = prx_list[i];
			
			plugin_log("========================================");
			plugin_log("Injecting PRX %zu/%zu: %s", i+1, prx_list.size(), prx.path.c_str());
			plugin_log("  Frame delay: %d frames", prx.frame_delay);
			plugin_log("  Suspend game: %s", prx.suspend_game ? "YES" : "NO");
			plugin_log("========================================");

			// Suspend ONLY if config says so
			if (prx.suspend_game)
			{
				plugin_log("Suspending game (suspend_game=true)...");
				SuspendApp(pid);
				usleep(500000);
			}
			else
			{
				plugin_log("NOT suspending game (suspend_game=false)");
			}

			// Install hook
			bool success = HookGame(executable, text_base, prx.path.c_str(), true, prx.frame_delay);

			// Resume ONLY if we suspended
			if (prx.suspend_game)
			{
				plugin_log("Resuming game...");
				ResumeApp(pid);
			}

			if (success)
			{
				success_count++;
				plugin_log("PRX %zu injection: SUCCESS", i+1);
			}
			else
			{
				plugin_log("PRX %zu injection: FAILED", i+1);
			}
		}

		plugin_log("========================================");
		plugin_log("Injection complete: %d/%zu PRX successful", success_count, prx_list.size());
		plugin_log("========================================");

		printf_notification("Injected %d/%zu PRX for %s",
							success_count, prx_list.size(), detected_tid);

		// Wait for game to close
		plugin_log("Waiting for game to close (monitoring appid %d)...", appid);
		int current_appid = appid;
		while(true)
		{
			int check_appid = 0;
			std::string check_tid;
			if (!Get_Running_App_TID(check_tid, check_appid) || check_appid != current_appid)
			{
				plugin_log("Game closed (appid changed)");
				break;
			}
			sleep(5);
		}

		plugin_log("Game closed - ready for next launch");
		last_attempted_appid = -1;
	}

	return 0;
}
