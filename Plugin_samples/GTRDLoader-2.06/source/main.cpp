#include "utils.hpp"
#include <notify.hpp>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <vector>
#include <nid.hpp>

void sig_handler(int signo)
{
    printf_notification("GTRDLoader v2.06 crashed with signal %d", signo);
}

extern "C"{
    int32_t sceKernelPrepareToSuspendProcess(pid_t pid);
    int32_t sceKernelSuspendProcess(pid_t pid);
    int32_t sceKernelPrepareToResumeProcess(pid_t pid);
    int32_t sceKernelResumeProcess(pid_t pid);
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

bool IsProcessRunning(pid_t pid)
{
    int bappid = 0;
    return (_sceApplicationGetAppId(pid, &bappid) >= 0);
}

// Patch FPS direct pour GTA V a l'adresse specifique
int32_t patch_GTAV_FPS_Direct(Hijacker &hijacker) {
    plugin_log("========== GTA V DIRECT FPS PATCH START ==========");
    
    // Get executable base
    uintptr_t eboot_base = hijacker.getEboot()->imagebase();
    plugin_log("[GTAV] Executable base: 0x%llx", eboot_base);
    
    // Calculate absolute address
    uint64_t APP_BASE = 0x400000;
    uint64_t fpsBypass_addr = 0xBC151D + APP_BASE;
    uint64_t absolute_addr = eboot_base + (fpsBypass_addr - APP_BASE);
    
    plugin_log("[GTAV] Target offset: 0x%llx", fpsBypass_addr);
    plugin_log("[GTAV] Absolute address: 0x%llx", absolute_addr);
    
    // Read original bytes
    uint8_t original[8];
    hijacker.read(absolute_addr, original, sizeof(original));
    plugin_log("[GTAV] Original bytes at 0x%llx:", absolute_addr);
    plugin_log("    %02X %02X %02X %02X %02X %02X %02X %02X",
               original[0], original[1], original[2], original[3],
               original[4], original[5], original[6], original[7]);
    
    // Write patch: BF 01 00 00 00 (mov edi, 1)
    uint8_t patch[] = {0xBF, 0x01, 0x00, 0x00, 0x00};
    plugin_log("[GTAV] Writing patch: BF 01 00 00 00 (mov edi, 1)");
    
    hijacker.write(absolute_addr, patch);
    
    // Verify patch
    uint8_t verify[8];
    hijacker.read(absolute_addr, verify, sizeof(verify));
    plugin_log("[GTAV] After patch bytes at 0x%llx:", absolute_addr);
    plugin_log("    %02X %02X %02X %02X %02X %02X %02X %02X",
               verify[0], verify[1], verify[2], verify[3],
               verify[4], verify[5], verify[6], verify[7]);
    
    // Verify the first 5 bytes match our patch
    if (verify[0] == 0xBF && verify[1] == 0x01 && verify[2] == 0x00 && 
        verify[3] == 0x00 && verify[4] == 0x00) {
        plugin_log("[GTAV] SUCCESS: Direct FPS Patch VERIFIED!");
        plugin_log("========== GTA V DIRECT FPS PATCH SUCCESS ==========");
        return 0;
    } else {
        plugin_log("[GTAV] ERROR: Direct FPS Patch VERIFICATION FAILED!");
        plugin_log("[GTAV] Expected: BF 01 00 00 00, Got: %02X %02X %02X %02X %02X", 
                   verify[0], verify[1], verify[2], verify[3], verify[4]);
        plugin_log("========== GTA V DIRECT FPS PATCH FAILED ==========");
        return -1;
    }
}

// Patch FPS pour RDR2 et GTA V (PS4 only)
int32_t patch_SetFlipRate(Hijacker &hijacker, const char* game_name) {
    plugin_log("========== FPS PATCH START ==========");
    
    // Wait for lib to be loaded
    UniquePtr<SharedLib> lib = hijacker.getLib("libSceVideoOut.sprx");
    int retries = 0;
    while (lib == nullptr && retries < 100) {
        usleep(10000);
        lib = hijacker.getLib("libSceVideoOut.sprx");
        retries++;
    }
    
    if (lib == nullptr) {
        plugin_log("[%s] FAILED: libSceVideoOut.sprx NOT FOUND after %d retries", game_name, retries);
        printf_notification("[%s] FPS PATCH FAILED - Lib not found", game_name);
        plugin_log("========== FPS PATCH FAILED ==========");
        return -1;
    }
    
    plugin_log("[%s] SUCCESS: libSceVideoOut.sprx found after %d retries", game_name, retries);
    plugin_log("[%s] libSceVideoOut.sprx imagebase: 0x%llx", game_name, lib->imagebase());
    
    // Get function address
    static constexpr Nid sceVideoOutSetFlipRate_Nid{"CBiu4mCE1DA"};
    uintptr_t fliprate_addr = hijacker.getFunctionAddress(lib.get(), sceVideoOutSetFlipRate_Nid);
    
    if (fliprate_addr == 0) {
        plugin_log("[%s] FAILED: sceVideoOutSetFlipRate NOT FOUND", game_name);
        printf_notification("[%s] FPS PATCH FAILED - Function not found", game_name);
        plugin_log("========== FPS PATCH FAILED ==========");
        return -1;
    }
    
    plugin_log("[%s] SUCCESS: sceVideoOutSetFlipRate found at 0x%llx", game_name, fliprate_addr);
    
    // Read original bytes BEFORE patching
    uint8_t original[16];
    hijacker.read(fliprate_addr, original, sizeof(original));
    plugin_log("[%s] Original bytes at 0x%llx:", game_name, fliprate_addr);
    plugin_log("    %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
               original[0], original[1], original[2], original[3],
               original[4], original[5], original[6], original[7],
               original[8], original[9], original[10], original[11],
               original[12], original[13], original[14], original[15]);
    
    // Write patch: xor eax, eax; ret
    uint8_t patch[] = {0x31, 0xC0, 0xC3};
    plugin_log("[%s] Writing patch: 31 C0 C3 (xor eax,eax; ret)", game_name);
    
    hijacker.write(fliprate_addr, patch);
    
    // Verify patch was written correctly
    uint8_t verify[16];
    hijacker.read(fliprate_addr, verify, sizeof(verify));
    plugin_log("[%s] After patch bytes at 0x%llx:", game_name, fliprate_addr);
    plugin_log("    %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
               verify[0], verify[1], verify[2], verify[3],
               verify[4], verify[5], verify[6], verify[7],
               verify[8], verify[9], verify[10], verify[11],
               verify[12], verify[13], verify[14], verify[15]);
    
    // Verify the first 3 bytes match our patch
    if (verify[0] == 0x31 && verify[1] == 0xC0 && verify[2] == 0xC3) {
        plugin_log("[%s] SUCCESS: Patch VERIFIED - bytes match!", game_name);
        //printf_notification("[%s] FPS UNLOCKED!", game_name);
        plugin_log("========== FPS PATCH SUCCESS ==========");
        return 0;
    } else {
        plugin_log("[%s] ERROR: Patch VERIFICATION FAILED!", game_name);
        plugin_log("[%s] Expected: 31 C0 C3, Got: %02X %02X %02X", 
                   game_name, verify[0], verify[1], verify[2]);
        printf_notification("[%s] FPS PATCH FAILED - Verify error", game_name);
        plugin_log("========== FPS PATCH FAILED ==========");
        return -1;
    }
}

// Structure to manage multiple PRX files
struct PRXConfig {
    const char* path;
    const char* name;
    bool required;
};

uintptr_t kernel_base = 0;

int main()
{
    plugin_log("GTRDLoader v2.06 Plugin entered");
    payload_args_t *args = payload_get_args();
    kernel_base = args->kdata_base_addr;
    
    plugin_log("========== SYSTEM INFO ==========");
    plugin_log("Kernel base: 0x%llx", kernel_base);
    plugin_log("Plugin compiled: %s %s", __DATE__, __TIME__);
    plugin_log("=================================");
    
    plugin_log("Waiting 2 seconds for system initialization...");
    sleep(2);
    
    struct sigaction new_SIG_action;
    new_SIG_action.sa_handler = sig_handler;
    sigemptyset(&new_SIG_action.sa_mask);
    new_SIG_action.sa_flags = 0;
    for (int i = 0; i < 12; i++)
        sigaction(i, &new_SIG_action, NULL);
    
    unlink("/data/etaHEN/plloader_plugin.log");
    printf_notification("GTRDLoader v2.06 Starting.");
    plugin_log("GTRDLoader v2.06 Starting...");
    
    while(1)
    {
        int appid = 0;
        std::vector<PRXConfig> prx_list;
        const char* game_name = nullptr;
        bool apply_fps_patch = false;
        
        while(true)
        {
            // GTAV Detection (PS4 only)
            if (Is_Game_Running(appid, "CUSA00411") || // PS4 US
                Is_Game_Running(appid, "CUSA00419"))   // PS4 EU
            {
                game_name = "GTAV";
                apply_fps_patch = true;
                
                int fd = open("/data/LSO153exp.prx", O_RDONLY);
                if (fd >= 0)
                {
                    close(fd);
                    prx_list.push_back({"/data/LSO153exp.prx", "BEACHMenu", true});
                    plugin_log("LSO153exp.prx found");
                }
                else
                {
                    prx_list.push_back({"/data/BeachOffline.prx", "BeachOffline", true});
                    plugin_log("Using BeachOffline.prx");
                }
                
                break;
            }
            
            // RDR2 Detection (PS4 only)
            if (Is_Game_Running(appid, "CUSA03041") || // PS4 US
                Is_Game_Running(appid, "CUSA08519"))   // PS4 EU
            {
                game_name = "RDR2";
                apply_fps_patch = true;
                prx_list.push_back({"/data/Sheriff.prx", "Sheriff", true});
                
                break;
            }
            
            // Check more frequently to catch game startup faster
            usleep(500000); // 0.5 secondes au lieu de 3
        }
        
        plugin_log("========================================");
        plugin_log("========== GAME DETECTED: %s ==========", game_name);
        plugin_log("========================================");
        plugin_log("AppID: 0x%X", appid);
        
        // Find PID - Optimized for speed
        plugin_log("Searching for PID...");
        int bappid = 0, pid = 0;
        
        // Search multiple times if needed (GTA Online starts fast)
        for (int retry = 0; retry < 10 && pid == 0; retry++) {
            for (size_t j = 0; j <= 9999; j++) {
                if(_sceApplicationGetAppId(j, &bappid) < 0)
                    continue;
                if(appid == bappid){
                    pid = j;
                    plugin_log("PID found: %i (retry %d)", pid, retry);
                    break;
                }
            }
            if (pid == 0) {
                usleep(50000); // Wait 50ms before retry
            }
        }
        
        if (pid == 0) {
            plugin_log("FAILED to find PID after retries");
            usleep(500000); // Wait before trying again
            continue;
        }
        
        plugin_log("PID %d found for %s", pid, game_name);
        
        // ========== GTA V ONLINE: SUSPEND IMMEDIATELY AFTER PID DETECTION ==========
        bool is_lso153 = false;
        const char* lso153_path = nullptr;
        
        // Quick check if this is LSO153 (GTA Online)
        for (const auto& prx : prx_list) {
            if (strstr(prx.path, "LSO153exp.prx") != nullptr) {
                is_lso153 = true;
                lso153_path = prx.path;
                break;
            }
        }
        
        // If GTA Online, SUSPEND IMMEDIATELY before game can start
        // CRITICAL: Do this BEFORE creating Hijacker to win the race
        if (is_lso153 && strcmp(game_name, "GTAV") == 0) {
            plugin_log("========================================");
            plugin_log("GTA V ONLINE DETECTED - EMERGENCY SUSPEND");
            plugin_log("========================================");
            plugin_log("Suspending IMMEDIATELY (pid %d) to prevent startup", pid);
            
            // Suspend as fast as possible - no delays
            sceKernelPrepareToSuspendProcess(pid);
            sceKernelSuspendProcess(pid);
            
            plugin_log("Game frozen - safe to patch");
        }
        
        // NOW create hijacker after suspension
        plugin_log("Creating hijacker for PID %d", pid);
        
        UniquePtr<Hijacker> executable = Hijacker::getHijacker(pid);
        
        if (!executable)
        {
            plugin_log("FAILED to get hijacker");
            // Resume if we suspended
            if (is_lso153 && strcmp(game_name, "GTAV") == 0) {
                ResumeApp(pid);
            }
            sleep(2);
            continue;
        }
        
        // ========== LOAD LSO153exp.prx FIRST (BEFORE EVERYTHING) ==========
        
        if (is_lso153 && lso153_path && apply_fps_patch && strcmp(game_name, "GTAV") == 0)
        {
            plugin_log("========================================");
            plugin_log("GTA V ONLINE - SUSPEND FIRST STRATEGY");
            plugin_log("========================================");
            
            // Game already suspended early - just wait for lib
            plugin_log("Game already suspended - waiting for libSceVideoOut.sprx...");
            UniquePtr<SharedLib> lib = nullptr;
            int wait_retries = 0;
            while (lib == nullptr && wait_retries < 100) {
                lib = executable->getLib("libSceVideoOut.sprx");
                if (lib == nullptr) {
                    usleep(30000); // Check every 30ms
                    wait_retries++;
                }
            }
            
            if (lib != nullptr) {
                plugin_log("SUCCESS: libSceVideoOut.sprx detected after %d checks (%.1fs)", 
                          wait_retries, wait_retries * 0.05);
                plugin_log("Library loaded at: 0x%llx", lib->imagebase());
            } else {
                plugin_log("WARNING: libSceVideoOut.sprx not found after 10s wait");
            }
            
            plugin_log("========================================");
            plugin_log("APPLYING BOTH FPS PATCHES WITH 5 ATTEMPTS");
            plugin_log("========================================");
            
            int direct_result = -1;
            int fliprate_result = -1;
            
            // Single loop for BOTH patches - stops when both succeed
            for (int attempt = 0; attempt < 5; attempt++)
            {
                plugin_log("========== FPS PATCH ATTEMPT %d/5 ==========", attempt + 1);
                
                // PATCH 1: Direct memory patch
                if (direct_result != 0) {
                    plugin_log("Trying Direct FPS patch...");
                    direct_result = patch_GTAV_FPS_Direct(*executable);
                    if (direct_result == 0) {
                        plugin_log("Direct patch SUCCESS!");
                    } else {
                        plugin_log("Direct patch FAILED");
                    }
                }
                
                usleep(50000); // 0.05s between patches
                
                // PATCH 2: FlipRate patch
                if (fliprate_result != 0) {
                    plugin_log("Trying FlipRate patch...");
                    fliprate_result = patch_SetFlipRate(*executable, game_name);
                    if (fliprate_result == 0) {
                        plugin_log("FlipRate patch SUCCESS!");
                    } else {
                        plugin_log("FlipRate patch FAILED");
                    }
                }
                
                // Check if BOTH patches succeeded
                if (direct_result == 0 && fliprate_result == 0) {
                    plugin_log("========================================");
                    plugin_log("SUCCESS: BOTH FPS PATCHES applied on attempt %d!", attempt + 1);
                    plugin_log("========================================");
                    //printf_notification("[GTA V Online] FPS Unlocked!");
                    break;
                }
                
                // If not last attempt and at least one failed, wait before retry
                if (attempt < 4 && (direct_result != 0 || fliprate_result != 0)) {
                    plugin_log("Waiting 3.5s before next attempt...");
                    usleep(350000);
                }
            }
            
            // Final status
            if (direct_result != 0 || fliprate_result != 0) {
                plugin_log("========================================");
                plugin_log("WARNING: FPS PATCHES incomplete after 5 attempts");
                plugin_log("Direct patch: %s | FlipRate patch: %s",
                          direct_result == 0 ? "OK" : "FAILED",
                          fliprate_result == 0 ? "OK" : "FAILED");
                plugin_log("========================================");
                printf_notification("[GTA V Online] FPS patch incomplete");
            }
            
            plugin_log("========================================");
            plugin_log("NOW LOADING LSO153exp.prx WHILE SUSPENDED");
            plugin_log("========================================");
            
            // Need text_base to load the PRX
            uintptr_t early_text_base = executable->getEboot()->getTextSection()->start();
            
            if (early_text_base != 0)
            {
                plugin_log("Loading LSO153exp.prx from: %s", lso153_path);
                plugin_log("Using extended frame delay (300 frames = ~5 sec) for GTA Online");
                
                // 300 frames = ~5 secondes pour GTA Online
                // Donne le temps à l'anti-cheat et au réseau de s'initialiser
                if(HookGame(executable, early_text_base, lso153_path, false, 300))
                {
                    plugin_log("LSO153exp.prx loaded successfully!");
                    printf_notification("LSO153exp.prx loaded");
                }
                else
                {
                    plugin_log("WARNING: Failed to load LSO153exp.prx");
                }
                
                plugin_log("Waiting for PRX and FPS patches to stabilize...");
                //usleep(1500000); // 1.5s to let PRX initialize and patches settle
                usleep(10000); // // 0.05s to let PRX initialize and patches settle
                plugin_log("All patches and PRX ready - proceeding to game suspension");
            }
            
            plugin_log("========================================");
        }
        
        uintptr_t text_base = 0;
        uint64_t text_size = 0;
        
        if (executable)
        {
            text_base = executable->getEboot()->getTextSection()->start();
            text_size = executable->getEboot()->getTextSection()->sectionLength();
            plugin_log("Executable base (ASLR): 0x%llx", executable->getEboot()->imagebase());
            plugin_log("Text section start: 0x%lX", text_base);
            plugin_log("Text section size: 0x%lX (%lu bytes)", text_size, text_size);
        }
        else
        {
            plugin_log("FAILED to get hijacker");
            sleep(2);
            continue;
        }
        
        if (text_base == 0 || text_size == 0)
        {
            plugin_log("INVALID text section");
            sleep(2);
            continue;
        }
        
        plugin_log("FPS patch enabled: %s", apply_fps_patch ? "YES" : "NO");
        plugin_log("PRX to load: %d", (int)prx_list.size());
        for (size_t i = 0; i < prx_list.size(); i++) {
            plugin_log("  - PRX %zu: %s (%s)", i+1, prx_list[i].name, 
                      prx_list[i].required ? "required" : "optional");
        }
        plugin_log("========================================");
        
        // ========== GTA V OFFLINE: EARLY DETECTION + PATCHES ==========
        if (apply_fps_patch && strcmp(game_name, "GTAV") == 0 && !is_lso153)
        {
            plugin_log("========================================");
            plugin_log("GTA V OFFLINE - EARLY LIBRARY DETECTION");
            plugin_log("========================================");
            
            // Wait for libSceVideoOut.sprx to be loaded BEFORE patches
            plugin_log("Waiting for libSceVideoOut.sprx to load...");
            UniquePtr<SharedLib> lib = nullptr;
            int wait_retries = 0;
            while (lib == nullptr && wait_retries < 200) {
                lib = executable->getLib("libSceVideoOut.sprx");
                if (lib == nullptr) {
                    usleep(50000); // Check every 50ms
                    wait_retries++;
                }
            }
            
            if (lib != nullptr) {
                plugin_log("SUCCESS: libSceVideoOut.sprx detected after %d checks (%.1fs)", 
                          wait_retries, wait_retries * 0.05);
                plugin_log("Library loaded at: 0x%llx", lib->imagebase());
            } else {
                plugin_log("WARNING: libSceVideoOut.sprx not found after 10s wait");
            }
            
            plugin_log("========================================");
            plugin_log("APPLYING FPS PATCHES NOW");
            plugin_log("Game is RUNNING - memory is accessible");
            plugin_log("========================================");
            
            // PATCH 1: Direct memory patch at 0xBC151D
            plugin_log("PATCH 1/2: Direct memory patch (offset 0xBC151D)");
            int direct_result = patch_GTAV_FPS_Direct(*executable);
            
            if (direct_result == 0)
            {
                plugin_log("SUCCESS: Direct FPS patch applied!");
            }
            else
            {
                plugin_log("WARNING: Direct FPS patch failed");
            }
            
            usleep(50000); // 0.05s delay between patches
            
            // PATCH 2: FlipRate patch (lib already detected)
            plugin_log("PATCH 2/2: FlipRate patch");
            
            int patch_result = patch_SetFlipRate(*executable, game_name);
            
            if (patch_result == 0)
            {
                plugin_log("SUCCESS: FlipRate patch applied!");
                printf_notification("[GTA V] FPS Unlocked!");
            }
            else
            {
                plugin_log("WARNING: FlipRate patch failed");
                printf_notification("[GTA V] FPS patch failed");
            }
            
            plugin_log("========================================");
            plugin_log("GTA V FPS PATCH COMPLETED");
            plugin_log("========================================");
        }
        
        // Suspend game ONLY if not already suspended (LSO153 suspends early)
        if (!is_lso153) {
            plugin_log("Suspending game (pid %d)", pid);
            SuspendApp(pid);
            usleep(500000);
            plugin_log("Game suspended successfully");
        } else {
            plugin_log("Game already suspended (LSO153) - skipping suspension");
        }
        
        // ========== RDR2: PATCH APRES LA SUSPENSION (ORIGINAL BEHAVIOR) ==========
        if (apply_fps_patch && strcmp(game_name, "RDR2") == 0)
        {
            plugin_log("========================================");
            plugin_log("RDR2 detected - Patching AFTER suspension");
            plugin_log("Waiting 3.5 seconds for libs to be mapped...");
            plugin_log("========================================");
            //sleep(3);
            usleep(3500000);
            
            int patch_result = patch_SetFlipRate(*executable, game_name);
            
            if (patch_result == 0)
            {
                plugin_log("SUCCESS: RDR2 FPS PATCH on first attempt!");
                printf_notification("[RDR2] FPS Unlocked!");
            }
            else
            {
                plugin_log("WARNING: RDR2 FPS PATCH FAILED - 30fps mode");
                printf_notification("[RDR2] FPS patch failed - 30fps");
            }
        }
        
        plugin_log("========================================");
        plugin_log("Starting PRX injection...");
        plugin_log("========================================");
        
        // Load all PRX files
        bool critical_failed = false;
        int loaded_count = 0;
        
        for (const auto& prx : prx_list)
        {
            // Skip LSO153exp.prx - already loaded early
            if (is_lso153 && strstr(prx.path, "LSO153exp.prx") != nullptr) {
                plugin_log("Skipping %s - already loaded early", prx.name);
                loaded_count++;
                continue;
            }
            
            plugin_log("Loading PRX: %s from %s", prx.name, prx.path);
            
            // Déterminer le frame delay selon le jeu et le PRX
            // GTA V Story et RDR2 utilisent le même délai standard (60 frames = 1 sec)
            int frame_delay = 60; // Défaut: 1 seconde pour tous les jeux
            
            plugin_log("Using standard frame delay: 60 frames (~1 sec) for %s", game_name);
            
            bool loaded = false;
            for (int attempt = 0; attempt < 2; attempt++)
            {
                if (attempt > 0)
                {
                    plugin_log("Retry attempt %d for %s", attempt + 1, prx.name);
                    usleep(200000);
                }
                
                if(HookGame(executable, text_base, prx.path, false, frame_delay))
                {
                    plugin_log("%s loaded successfully!", prx.name);
                    loaded = true;
                    loaded_count++;
                    break;
                }
            }
            
            if (!loaded)
            {
                plugin_log("FAILED to load %s after 2 attempts", prx.name);
                if (prx.required)
                {
                    critical_failed = true;
                    break;
                }
                else
                {
                    plugin_log("Non-critical PRX failed, continuing...");
                }
            }
            
            usleep(100000);
        }
        
        plugin_log("========================================");
        plugin_log("PRX LOADING SUMMARY:");
        plugin_log("Loaded: %d/%d PRX modules", loaded_count, (int)prx_list.size());
        plugin_log("========================================");
        
        if (critical_failed)
        {
            plugin_log("CRITICAL PRX FAILED - Aborting");
            ResumeApp(pid);
            sleep(2);
            continue;
        }
        
        plugin_log("All PRX loaded successfully!");
        
        usleep(500000);
        plugin_log("Resuming game (pid %d)", pid);
        ResumeApp(pid);
        plugin_log("Game resumed successfully");
        
        plugin_log("========================================");
        plugin_log("MONITORING GAME PROCESS...");
        plugin_log("========================================");
        
        while(IsProcessRunning(pid)){
            sleep(5);
        }
        
        plugin_log("========================================");
        plugin_log("%s CLOSED - Waiting for next launch", game_name);
        plugin_log("========================================");
        
        // Specific notification when game closes
        if (strcmp(game_name, "RDR2") == 0) {
            printf_notification("Game closed - Wait for next launch");
            plugin_log("Waiting 3.5 seconds ...");
            usleep(3500000);
            printf_notification("RDR 2 GTA V ready for next launch");
        } 
        else if (strcmp(game_name, "GTAV") == 0) {
            if (is_lso153) {
                printf_notification("Game closed - Wait for next launch");
                plugin_log("Waiting 3.5 seconds ...");
                usleep(3500000);
                printf_notification("RDR2 GTA V ready for next launch");
            } else {
                printf_notification("Game closed - Wait for next launch");
                plugin_log("Waiting 3.5 seconds ...");
                usleep(3500000);
                printf_notification("RDR2 GTA V ready for next launch");
            }
        }
        
        plugin_log("Returning to game detection loop in 2 seconds...");
        //sleep(2);
        plugin_log("Waiting 3.5 seconds ...");
        usleep(3500000);
    }
    
    return 0;
}