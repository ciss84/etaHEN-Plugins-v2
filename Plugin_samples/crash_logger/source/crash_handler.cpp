#include "crash_handler.hpp"
#include <signal.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ucontext.h>

// Structure pour stocker les infos de crash
typedef struct {
    char title_id[32];
    int signal;
    void* fault_addr;
    uint64_t rip;
    uint64_t rsp;
    uint64_t rax;
    uint64_t rbx;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
} CrashInfo;

// Thread-safe global pour le Title ID
static char g_current_title_id[32] = {0};

const char* signal_name(int sig)
{
    switch(sig) {
        case SIGSEGV: return "SIGSEGV (Segmentation Fault)";
        case SIGABRT: return "SIGABRT (Abort)";
        case SIGBUS: return "SIGBUS (Bus Error)";
        case SIGILL: return "SIGILL (Illegal Instruction)";
        case SIGFPE: return "SIGFPE (Floating Point Exception)";
        case SIGTRAP: return "SIGTRAP (Trace/Breakpoint)";
        default: return "UNKNOWN";
    }
}

void LogCrash(const char* title_id, int signal, void* fault_addr, void* context)
{
    char filename[256];
    time_t now = time(NULL);
    struct tm* t = localtime(&now);
    
    // Nom du fichier : TITLEID_DATE_TIME.txt
    snprintf(filename, sizeof(filename), 
             "%s%s_%04d%02d%02d_%02d%02d%02d.txt",
             LOG_DIR, title_id,
             t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
             t->tm_hour, t->tm_min, t->tm_sec);
    
    FILE* log = fopen(filename, "w");
    if (!log) {
        mkdir(LOG_DIR, 0777);
        log = fopen(filename, "w");
        if (!log) return;
    }

    ucontext_t* uc = (ucontext_t*)context;
    
    fprintf(log, "╔══════════════════════════════════════════════════════════════╗\n");
    fprintf(log, "║                    CRASH REPORT                              ║\n");
    fprintf(log, "╚══════════════════════════════════════════════════════════════╝\n\n");
    
    fprintf(log, "Title ID: %s\n", title_id);
    fprintf(log, "Date/Time: %04d-%02d-%02d %02d:%02d:%02d\n",
            t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
            t->tm_hour, t->tm_min, t->tm_sec);
    fprintf(log, "Signal: %d - %s\n", signal, signal_name(signal));
    fprintf(log, "Fault Address: 0x%016lx\n\n", (unsigned long)fault_addr);
    
    fprintf(log, "════════════════ CPU REGISTERS ════════════════\n");
    
#ifdef __x86_64__
    uint64_t rip = uc->uc_mcontext.gregs[REG_RIP];
    uint64_t rsp = uc->uc_mcontext.gregs[REG_RSP];
    uint64_t rax = uc->uc_mcontext.gregs[REG_RAX];
    uint64_t rbx = uc->uc_mcontext.gregs[REG_RBX];
    uint64_t rcx = uc->uc_mcontext.gregs[REG_RCX];
    uint64_t rdx = uc->uc_mcontext.gregs[REG_RDX];
    uint64_t rsi = uc->uc_mcontext.gregs[REG_RSI];
    uint64_t rdi = uc->uc_mcontext.gregs[REG_RDI];
    uint64_t r8 = uc->uc_mcontext.gregs[REG_R8];
    uint64_t r9 = uc->uc_mcontext.gregs[REG_R9];
    uint64_t r10 = uc->uc_mcontext.gregs[REG_R10];
    uint64_t r11 = uc->uc_mcontext.gregs[REG_R11];
    
    fprintf(log, "RIP: 0x%016llx    RSP: 0x%016llx\n", rip, rsp);
    fprintf(log, "RAX: 0x%016llx    RBX: 0x%016llx\n", rax, rbx);
    fprintf(log, "RCX: 0x%016llx    RDX: 0x%016llx\n", rcx, rdx);
    fprintf(log, "RSI: 0x%016llx    RDI: 0x%016llx\n", rsi, rdi);
    fprintf(log, "R8:  0x%016llx    R9:  0x%016llx\n", r8, r9);
    fprintf(log, "R10: 0x%016llx    R11: 0x%016llx\n\n", r10, r11);
    
    fprintf(log, "════════════════ STACK TRACE ═══════════════════\n");
    
    uint64_t* stack = (uint64_t*)rsp;
    if (stack && rsp > 0x1000) {
        for (int i = 0; i < MAX_STACK_FRAMES; i++) {
            if ((uint64_t)&stack[i] < 0x1000) break;
            fprintf(log, "[%02d] RSP+0x%03x: 0x%016llx\n", 
                    i, i * 8, stack[i]);
        }
    } else {
        fprintf(log, "Stack pointer invalid\n");
    }
#else
    fprintf(log, "CPU register dump not available on this architecture\n");
#endif
    
    fprintf(log, "\n════════════════════════════════════════════════\n");
    fprintf(log, "Logged by Crash Logger v1.0\n");
    fprintf(log, "By @84Ciss - 2025\n");
    
    fclose(log);
    
    klog("CRASH LOGGED: %s", filename);
}

// Handler de crash injecté dans le jeu
void game_crash_handler(int sig, siginfo_t* si, void* context)
{
    klog("!!! GAME CRASH DETECTED !!!");
    klog("Signal: %d, Fault Address: %p", sig, si->si_addr);
    
    // Logger le crash
    LogCrash(g_current_title_id, sig, si->si_addr, context);
    
    // Laisser le jeu crash normalement
    signal(sig, SIG_DFL);
    raise(sig);
}

bool InstallCrashHandlers(pid_t pid, const char* title_id)
{
    klog("Installing crash handlers for PID %d (%s)", pid, title_id);
    
    // Sauvegarder le Title ID
    strncpy(g_current_title_id, title_id, sizeof(g_current_title_id) - 1);
    g_current_title_id[sizeof(g_current_title_id) - 1] = '\0';
    
    // Configuration du signal handler
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = game_crash_handler;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    sigemptyset(&sa.sa_mask);
    
    // Installer les handlers pour tous les signaux critiques
    int signals[] = {SIGSEGV, SIGABRT, SIGBUS, SIGILL, SIGFPE, SIGTRAP};
    int installed = 0;
    
    for (size_t i = 0; i < sizeof(signals) / sizeof(signals[0]); i++)
    {
        if (sigaction(signals[i], &sa, NULL) == 0)
        {
            installed++;
            klog("Handler installed for signal %d", signals[i]);
        }
        else
        {
            klog("WARNING: Failed to install handler for signal %d", signals[i]);
        }
    }
    
    if (installed > 0)
    {
        klog("Successfully installed %d/%zu crash handlers", 
             installed, sizeof(signals) / sizeof(signals[0]));
        return true;
    }
    
    klog("ERROR: Failed to install any crash handlers");
    return false;
}
