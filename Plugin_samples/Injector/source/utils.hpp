#pragma once

#include <stddef.h>
#include <stdio.h>
#include <sys/_pthreadtypes.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <notify.hpp>
#include <unistd.h>
#include "dbg.hpp"
#include "dbg/dbg.hpp"
#include "elf/elf.hpp"
#include "hijacker/hijacker.hpp"
#include "notify.hpp"
#include "backtrace.hpp"
#include <map>
#include <string>

struct GameConfig {
    int delay = 30;
    int extra_frames = 0;
    std::map<std::string, bool> prx_files;
};

void plugin_log(const char* fmt, ...);
GameConfig parse_config_for_tid(const char* tid);
