#include "libmysyslog.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>

static const char *get_level_string(int level) {
    if (level == LOG_INFO) return "INFO";
    if (level == LOG_WARNING) return "WARNING";
    if (level == LOG_ERR) return "ERROR";
    return "UNKNOWN";
}

void libmysyslog(int level, const char *fmt, ...) {
    FILE *log = fopen("/var/log/myrpc.log", "a");
    if (!log) return;

    time_t ts = time(NULL);
    struct tm tmval;
    localtime_r(&ts, &tmval);

    fprintf(log, "[%04d-%02d-%02d %02d:%02d:%02d] [%s] ",
        tmval.tm_year + 1900, tmval.tm_mon + 1, tmval.tm_mday,
        tmval.tm_hour, tmval.tm_min, tmval.tm_sec,
        get_level_string(level));

    va_list ap;
    va_start(ap, fmt);
    vfprintf(log, fmt, ap);
    va_end(ap);

    fprintf(log, "\n");
    fclose(log);
}
