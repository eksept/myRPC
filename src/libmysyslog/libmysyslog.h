#ifndef MYSYSLOG_H
#define MYSYSLOG_H

#ifdef cplusplus
extern "C" {
#endif

#define LOG_INFO    1
#define LOG_WARNING 2
#define LOG_ERR     3

void libmysyslog(int level, const char *format, ...);

#define log_info(...)    libmysyslog(LOG_INFO, __VA_ARGS__)
#define log_warning(...) libmysyslog(LOG_WARNING, __VA_ARGS__)
#define log_error(...)   libmysyslog(LOG_ERR, __VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif
