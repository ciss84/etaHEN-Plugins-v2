#include "utils.hpp"
#include <notify.hpp>
#include <signal.h>
#include <string>

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
	printf_notification("Injector plugin crashed with signal %d", signo);
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
	plugin_log("=== INJECTOR WITH SHELLCODE STARTING ===");

	payload_args_t *args = payload_get_args();
	kernel_base = args->kdata_base_addr;

	struct sigaction new_SIG_action;
	new_SIG_action.sa_handler = sig_handler;
	sigemptyset(&new_SIG_action.sa_mask);
	new_SIG_action.sa_flags = 0;

	for (int i = 0; i < 12; i++)
		sigaction(i, &new_SIG_action, NULL);

	// Load config
	GameInjectorConfig config = parse_injector_config();

	plugin_log("Config loaded - %zu games configured", config.games.size());
	printf_notification("Injector started - monitoring games");

	while(1)
	{
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

			// Check if it's a game (CUSA/SCUS/PPSA)
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
		plugin_log("Game detected: %s", detected_tid);
		plugin_log("========================================");

		// Check if we have config for this game
		auto it = config.games.find(detected_tid);
		if (it == config.games.end())
		{
			plugin_log("No config for %s - skipping", detected_tid);
			// Wait for game to close
			while(IsProcessRunning(appid))
			{
				sleep(5);
			}
			continue;
		}

		std::vector<PRXConfig> &prx_list = it->second;
		plugin_log("Found %zu PRX to inject for %s", prx_list.size(), detected_tid);

		// Get process info
		pid_t pid = appid;

		// Attach hijacker
		plugin_log("Attaching to process...");
		auto executable = makeUnique<Hijacker>(pid);

		uint64_t text_base = executable->getEboot()->imagebase();
		plugin_log("Process attached - text_base: 0x%llx", text_base);

		// Suspend game
		plugin_log("Suspending game...");
		SuspendApp(pid);
		usleep(500000);

		// Inject all PRX
		int success_count = 0;
		for (const auto& prx : prx_list)
		{
			plugin_log("Injecting: %s", prx.path.c_str());

			if (HookGame(executable, text_base, prx.path.c_str(), false, prx.frame_delay))
			{
				plugin_log("SUCCESS: %s injected (frame_delay: %d)",
						   prx.path.c_str(), prx.frame_delay);
				success_count++;
			}
			else
			{
				plugin_log("FAILED: %s", prx.path.c_str());
			}

			usleep(100000);
		}

		// Resume game
		plugin_log("Resuming game...");
		ResumeApp(pid);

		plugin_log("========================================");
		plugin_log("Injection complete: %d/%zu PRX loaded",
				   success_count, prx_list.size());
		plugin_log("========================================");

		printf_notification("%d/%zu PRX injected into %s",
							success_count, prx_list.size(), detected_tid);

		// Wait for game to close
		while(IsProcessRunning(pid))
		{
			sleep(5);
		}

		plugin_log("Game closed - waiting for next launch");
	}

	return 0;
}