#include "utils.hpp"
#include <notify.hpp>
#include <signal.h>
#include <ps5/klog.h>
#include <string>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <dirent.h>
#include <ifaddrs.h>

extern "C"
{
	int sceSystemServiceGetAppIdOfRunningBigApp();
	int sceSystemServiceGetAppTitleId(int app_id, char *title_id);
}

extern uint8_t elf_start[];
extern const unsigned int elf_size;

void sig_handler(int signo)
{
	printf_notification("the injector plugin has crashed with signal %d\nif you need it you can relaunch via the etaHEN toolbox in debug settings", signo);
	printBacktraceForCrash();
	exit(-1);
}

#define MAX_PROC_NAME 0x100

bool get_console_ip(char *ip_out, size_t ip_size)
{
	struct ifaddrs *ifaddr, *ifa;
	bool found = false;

	if (getifaddrs(&ifaddr) == -1)
	{
		klog_perror("getifaddrs");
		return false;
	}

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
	{
		if (ifa->ifa_addr == NULL)
			continue;

		// Chercher une interface IPv4 qui n'est pas loopback
		if (ifa->ifa_addr->sa_family == AF_INET)
		{
			struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
			const char *ip = inet_ntoa(addr->sin_addr);

			// Ignorer localhost (127.x.x.x)
			if (strncmp(ip, "127.", 4) != 0)
			{
				snprintf(ip_out, ip_size, "%s", ip);
				plugin_log("Console IP detected: %s (interface: %s)", ip_out, ifa->ifa_name);
				found = true;
				break;
			}
		}
	}

	freeifaddrs(ifaddr);

	if (!found)
	{
		// Fallback to localhost if no network IP found
		snprintf(ip_out, ip_size, "127.0.0.1");
		plugin_log("No network IP found, using localhost: 127.0.0.1");
	}

	return found;
}

bool Get_Running_App_TID(std::string &title_id, int &BigAppid)
{
	char tid[255];
	BigAppid = sceSystemServiceGetAppIdOfRunningBigApp();
	if (BigAppid < 0)
	{
		return false;
	}
	(void)memset(tid, 0, sizeof tid);

	if (sceSystemServiceGetAppTitleId(BigAppid, &tid[0]) != 0)
	{
		return false;
	}

	title_id = std::string(tid);
	return true;
}

int send_injector_data(const char *ip, int port,
					   const char *proc_name,
					   const uint8_t *data, size_t data_size)
{
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0)
	{
		klog_perror("socket");
		return -1;
	}

	struct sockaddr_in addr = {0};
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);

	if (inet_pton(AF_INET, ip, &addr.sin_addr) <= 0)
	{
		klog_perror("inet_pton");
		close(sock);
		return -1;
	}

	if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
	{
		klog_perror("connect");
		close(sock);
		return -1;
	}

	uint8_t header[MAX_PROC_NAME] = {0};
	size_t name_len = strlen(proc_name);

	if (name_len > MAX_PROC_NAME)
		name_len = MAX_PROC_NAME;

	memcpy(header, proc_name, name_len);

	// Send header
	if (send(sock, header, MAX_PROC_NAME, 0) != MAX_PROC_NAME)
	{
		klog_perror("send header");
		close(sock);
		return -1;
	}

	// Send payload
	ssize_t sent = send(sock, data, data_size, 0);
	if (sent < 0 || (size_t)sent != data_size)
	{
		klog_perror("send data");
		close(sock);
		return -1;
	}

	plugin_log("Sent %zu bytes to %s:%d", MAX_PROC_NAME + data_size, ip, port);

	close(sock);
	return 0;
}

void send_all_payloads_legacy()
{
	const char* dir_path = "/data/InjectorPlugin";
	DIR* dir = opendir(dir_path);
	if (!dir) {
		plugin_log("Cannot open directory: %s", dir_path);
		return;
	}

	// Detect console IP address
	char console_ip[64];
	get_console_ip(console_ip, sizeof(console_ip));

	struct dirent* entry;

	while ((entry = readdir(dir)) != NULL) {

		if (strcmp(entry->d_name, ".") == 0 ||
			strcmp(entry->d_name, "..") == 0)
			continue;

		char fullpath[512];
		snprintf(fullpath, sizeof(fullpath), "%s/%s", dir_path, entry->d_name);

		struct stat st;
		if (stat(fullpath, &st) < 0 || !S_ISREG(st.st_mode))
			continue;

		// Skip config.ini
		if (strcmp(entry->d_name, "config.ini") == 0)
			continue;

		plugin_log("Sending payload: %s (%lld bytes)",
			   fullpath, (long long)st.st_size);

		FILE* f = fopen(fullpath, "rb");
		if (!f) {
			plugin_log("Cannot open file: %s", fullpath);
			continue;
		}

		uint8_t* buf = (uint8_t*)malloc(st.st_size);
		fread(buf, 1, st.st_size, f);
		fclose(f);

		send_injector_data(console_ip, 9021, "eboot.bin", buf, st.st_size);

		free(buf);
		sleep(1);
	}

	closedir(dir);
}

void send_all_payloads(const char* tid)
{
	// Load config for this game
	GameConfig config = parse_config_for_tid(tid);
	
	if (config.prx_files.empty())
	{
		plugin_log("No PRX files configured for %s, using directory scan", tid);
		// Fallback to legacy system (scan directory)
		send_all_payloads_legacy();
		return;
	}
	
	// Detect console IP
	char console_ip[64];
	get_console_ip(console_ip, sizeof(console_ip));
	
	// Inject only enabled PRX from config
	for (const auto& entry : config.prx_files)
	{
		const std::string& prx_path = entry.first;
		bool enabled = entry.second;
		
		if (!enabled)
		{
			plugin_log("Skipping disabled PRX: %s", prx_path.c_str());
			continue;
		}
		
		struct stat st;
		if (stat(prx_path.c_str(), &st) < 0 || !S_ISREG(st.st_mode))
		{
			plugin_log("PRX file not found or invalid: %s", prx_path.c_str());
			continue;
		}
		
		plugin_log("Injecting: %s (%lld bytes)", prx_path.c_str(), (long long)st.st_size);
		
		FILE* f = fopen(prx_path.c_str(), "rb");
		if (!f)
		{
			plugin_log("Cannot open: %s", prx_path.c_str());
			continue;
		}
		
		uint8_t* buf = (uint8_t*)malloc(st.st_size);
		fread(buf, 1, st.st_size, f);
		fclose(f);
		
		send_injector_data(console_ip, 9021, "eboot.bin", buf, st.st_size);
		
		free(buf);
		sleep(1);
	}
}

uintptr_t kernel_base = 0;

int main()
{
	// Premier log AVANT tout pour confirmer le demarrage
	plugin_log("=== PLUGIN INJECTOR STARTING ===");
	
	payload_args_t *args = payload_get_args();
	kernel_base = args->kdata_base_addr;

	struct sigaction new_SIG_action;
	new_SIG_action.sa_handler = sig_handler;
	sigemptyset(&new_SIG_action.sa_mask);
	new_SIG_action.sa_flags = 0;

	for (int i = 0; i < 12; i++)
		sigaction(i, &new_SIG_action, NULL);

	plugin_log("=== Injector Plugin Started ===");
	plugin_log("Monitoring for game launches...");

	std::string tid;
	int bappid, last_bappid = -1;
	
	while (true)
	{
		if (!Get_Running_App_TID(tid, bappid))
		{
			sleep(5);
			continue;
		}

		plugin_log("Current app - TID: %s, AppID: %d, Last AppID: %d", tid.c_str(), bappid, last_bappid);

		if ((bappid != last_bappid) && (tid.rfind("CUSA") != std::string::npos || tid.rfind("SCUS") != std::string::npos || tid.rfind("PPSA") != std::string::npos))
		{
			// Load config to get delay and extra frames
			GameConfig config = parse_config_for_tid(tid.c_str());
			
			plugin_log("Game detected! TID: %s - Waiting %d sec + %d frames...", 
					   tid.c_str(), config.delay, config.extra_frames);
			
			// Wait for game to load
			sleep(config.delay);
			
			// Wait extra frames for renderer init (60 frames = ~1 sec at 60fps)
			if (config.extra_frames > 0)
			{
				int extra_delay = config.extra_frames / 60; // Convert frames to seconds
				if (extra_delay < 1) extra_delay = 1;
				
				plugin_log("Waiting %d extra frames (~%d sec) for renderer init...", 
						   config.extra_frames, extra_delay);
				sleep(extra_delay);
			}
			
			int bappid_tmp;
			if (!Get_Running_App_TID(tid, bappid_tmp))
			{
				plugin_log("App closed before injection");
				last_bappid = -1;
				continue;
			}
			
			plugin_log("Starting injection now...");
			
			if (bappid == bappid_tmp)
			{
				send_all_payloads(tid.c_str());
				last_bappid = bappid;
				plugin_log("Injection completed for TID: %s", tid.c_str());
				printf_notification("PRX injected into %s", tid.c_str());
			}
			else
			{
				plugin_log("App ID changed during wait - maybe app closed");
				last_bappid = -1;
			}
		}
		
		sleep(5);
	}

	return 0;
}
