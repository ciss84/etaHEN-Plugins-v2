#pragma once
#include <stddef.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/stat.h>
#include <notify.hpp>
#include "backtrace.hpp"

void plugin_log(const char* fmt, ...);
