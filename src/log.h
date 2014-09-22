#ifndef _NPROXY_LOG_H_
#define _NPROXY_LOG_H_

#include <stdio.h>

#define LOG_DEBUG       0
#define LOG_VERBOSE     1
#define LOG_INFO        2
#define LOG_NOTICE      3
#define LOG_WARN        4
#define LOG_ERROR       5
#define LOG_CRITICAL    6

#define LOG_MAX_LENGTH  512

#define log_debug(...) do {                                     \
    _log(LOG_DEBUG, __FILE__, __LINE__, __VA_ARGS__);           \
} while (0)                                                     \

#define log_info(...) do {                                     \
    _log(LOG_INFO, __FILE__, __LINE__, __VA_ARGS__);           \
} while (0)                                                     \

#define log_notice(...) do {                                     \
    _log(LOG_NOTICE, __FILE__, __LINE__, __VA_ARGS__);           \
} while (0)                                                     \

#define log_warn(...) do {                                     \
    _log(LOG_WARN, __FILE__, __LINE__, __VA_ARGS__);           \
} while (0)                                                     \

#define log_error(...) do {                                     \
    _log(LOG_ERROR, __FILE__, __LINE__, __VA_ARGS__);           \
} while (0)                                                     \

#define log_crit(...) do {                                     \
    _log(LOG_CRITICAL, __FILE__, __LINE__, __VA_ARGS__);           \
} while (0)                                                     \


#define log_stderr(...) do {                            \
    _log_stream(stderr, __VA_ARGS__);                   \
} while (0)                                              \

#define log_stdout(...) do {                            \
    _log_stream(stdout, __VA_ARGS__);                   \
} while (0)                                              \

struct logger {
    char *name;
    int level;
    FILE *fd;
};

int log_init(int level, const char *name);
void log_destory(void);
void log_set_level(int level);
char *log_level_to_text(int level);
void _log(int level, const char *file, int line, const char *fmt, ...);
void _log_stream(FILE *stream, const char *fmt, ...);

#endif
