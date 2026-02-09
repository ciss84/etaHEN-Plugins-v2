#pragma once

#include <ps5/kernel.h>
#include <stdio.h>
#include <string>

#define LOG_DIR "/data/crash_logs/"
#define MAX_STACK_FRAMES 32

// Installer les crash handlers dans un processus de jeu
bool InstallCrashHandlers(pid_t pid, const char* title_id);

// Logger un crash
void LogCrash(const char* title_id, int signal, void* fault_addr, void* context);