#include "crash_handler.hpp"
#include <notify.hpp>
#include <signal.h>
#include <string>
#include <ps5/kernel.h>

extern "C"
{
	int sceSystemServiceGetAppIdOfRunningBigApp();
	int sceSystemServiceGetAppTitleId(int app_id, char *title_id);
}

void sig_handler(int signo)
{
	printf_notification("Crash Logger v1.0 crashed with signal %d", signo);
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

uintptr_t kernel_base = 0;

int main()
{
	klog("=== CRASH LOGGER v1.0 - UNIVERSAL GAME CRASH MONITOR ===");
	klog("By @84Ciss - 2025");

	payload_args_t *args = payload_get_args();
	kernel_base = args->kdata_base_addr;

	struct sigaction new_SIG_action;
	new_SIG_action.sa_handler = sig_handler;
	sigemptyset(&new_SIG_action.sa_mask);
	new_SIG_action.sa_flags = 0;

	for (int i = 0; i < 12; i++)
		sigaction(i, &new_SIG_action, NULL);

	// Créer le dossier de logs
	mkdir(LOG_DIR, 0777);

	klog("Crash Logger ready - monitoring all games");
	printf_notification("Crash Logger v1.0 started\nBy @84Ciss");

	int last_monitored_appid = -1;

	while(1)
	{
		int appid = 0;
		std::string tid;
		const char* detected_tid = nullptr;

		// Attendre qu'un jeu démarre
		while(true)
		{
			if (!Get_Running_App_TID(tid, appid))
			{
				usleep(500000);
				continue;
			}

			// Skip si c'est le même jeu qu'on monitore déjà
			if (appid == last_monitored_appid)
			{
				usleep(500000);
				continue;
			}

			// Check si c'est un jeu (CUSA/SCUS/PPSA)
			if (tid.rfind("CUSA") != std::string::npos ||
				tid.rfind("SCUS") != std::string::npos ||
				tid.rfind("PPSA") != std::string::npos)
			{
				detected_tid = tid.c_str();
				break;
			}

			usleep(500000);
		}

		klog("========================================");
		klog("Game detected: %s (appid: %d)", detected_tid, appid);
		klog("Installing crash handlers...");
		klog("========================================");

		last_monitored_appid = appid;

		// Trouver le vrai PID du processus
		klog("Searching for real PID (appid=%d)...", appid);
		int bappid = 0;
		pid_t pid = 0;
		
		for (int retry = 0; retry < 10 && pid == 0; retry++) {
			for (size_t j = 0; j <= 9999; j++) {
				if (_sceApplicationGetAppId(j, &bappid) < 0)
					continue;
				if (appid == bappid) {
					pid = j;
					klog("Real PID found: %d", pid);
					break;
				}
			}
			if (pid == 0) {
				usleep(50000);
			}
		}
		
		if (pid == 0) {
			klog("ERROR: Failed to find real PID");
			last_monitored_appid = -1;
			continue;
		}

		// Attendre que le jeu soit prêt
		klog("Waiting for game initialization...");
		sleep(2);

		// Installer les crash handlers dans le jeu
		if (InstallCrashHandlers(pid, detected_tid))
		{
			klog("SUCCESS: Crash handlers installed for %s (PID: %d)", detected_tid, pid);
			printf_notification("Crash monitoring active for %s", detected_tid);
		}
		else
		{
			klog("FAILED: Could not install crash handlers");
		}

		// Monitorer le jeu jusqu'à ce qu'il ferme
		klog("Monitoring %s for crashes...", detected_tid);
		int current_appid = appid;
		while(true)
		{
			int check_appid = 0;
			std::string check_tid;
			if (!Get_Running_App_TID(check_tid, check_appid) || check_appid != current_appid)
			{
				klog("Game closed: %s", detected_tid);
				break;
			}
			sleep(5);
		}

		klog("Ready for next game");
		last_monitored_appid = -1;
	}

	return 0;
}
