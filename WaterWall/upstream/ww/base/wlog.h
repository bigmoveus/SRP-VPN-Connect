#ifndef WW_LOG_H_
#define WW_LOG_H_

/**
 * @file wlog.h
 * @brief Thread-safe logging API with console and rotating-file backends.
 *
 * `wlog` provides log level filtering, formatted output, optional color,
 * and file rotation/retention controls.
 */

#include "wlibc.h"


#ifdef _WIN32
#define DIR_SEPARATOR     '\\'
#define DIR_SEPARATOR_STR "\\"
#else
#define DIR_SEPARATOR     '/'
#define DIR_SEPARATOR_STR "/"
#endif

#ifndef __FILENAME__
// #define __FILENAME__  (strrchr(__FILE__, DIR_SEPARATOR) ? strrchr(__FILE__, DIR_SEPARATOR) + 1 : __FILE__)
#define __FILENAME__ (strrchr(DIR_SEPARATOR_STR __FILE__, DIR_SEPARATOR) + 1)
#endif

#include "wexport.h"

#define CLR_CLR     "\033[0m"  /* 恢复颜色 */
#define CLR_BLACK   "\033[30m" /* 黑色字 */
#define CLR_RED     "\033[31m" /* 红色字 */
#define CLR_GREEN   "\033[32m" /* 绿色字 */
#define CLR_YELLOW  "\033[33m" /* 黄色字 */
#define CLR_BLUE    "\033[34m" /* 蓝色字 */
#define CLR_PURPLE  "\033[35m" /* 紫色字 */
#define CLR_SKYBLUE "\033[36m" /* 天蓝字 */
#define CLR_WHITE   "\033[37m" /* 白色字 */

#define CLR_BLK_WHT     "\033[40;37m" /* 黑底白字 */
#define CLR_RED_WHT     "\033[41;37m" /* 红底白字 */
#define CLR_GREEN_WHT   "\033[42;37m" /* 绿底白字 */
#define CLR_YELLOW_WHT  "\033[43;37m" /* 黄底白字 */
#define CLR_BLUE_WHT    "\033[44;37m" /* 蓝底白字 */
#define CLR_PURPLE_WHT  "\033[45;37m" /* 紫底白字 */
#define CLR_SKYBLUE_WHT "\033[46;37m" /* 天蓝底白字 */
#define CLR_WHT_BLK     "\033[47;30m" /* 白底黑字 */

// XXX(id, str, clr)
#define LOG_LEVEL_MAP(XXX)                                                                                             \
    XXX(LOG_LEVEL_DEBUG, "DEBUG", CLR_WHITE)                                                                           \
    XXX(LOG_LEVEL_INFO, "INFO ", CLR_GREEN)                                                                            \
    XXX(LOG_LEVEL_WARN, "WARN ", CLR_YELLOW)                                                                           \
    XXX(LOG_LEVEL_ERROR, "ERROR", CLR_RED)                                                                             \
    XXX(LOG_LEVEL_FATAL, "FATAL", CLR_RED_WHT)

typedef enum
{
    LOG_LEVEL_VERBOSE = 0,
#define XXX(id, str, clr) id,
    LOG_LEVEL_MAP(XXX)
#undef XXX
    LOG_LEVEL_SILENT
} log_level_e;

#define DEFAULT_LOG_FILE         "libhv"
#define DEFAULT_LOG_LEVEL        LOG_LEVEL_INFO
#define DEFAULT_LOG_FORMAT       "%y-%m-%d %H:%M:%S.%z %L %s"
#define DEFAULT_LOG_REMAIN_DAYS  1
#define DEFAULT_LOG_MAX_BUFSIZE  (1 << 14) // 16k
#define DEFAULT_LOG_MAX_FILESIZE (1 << 24) // 16M

// logger: default fileLogger
// network_logger() see event/nlog.h
/**
 * @brief Log sink callback signature.
 *
 * @param loglevel Log level of the message.
 * @param buf Rendered message bytes.
 * @param len Number of bytes in `buf`.
 */
typedef void (*logger_handler)(int loglevel, const char *buf, int len);
typedef struct logger_s logger_t;

/**
 * @brief Write an already-formatted log line via the logger backend.
 *
 * @param logger Logger instance.
 * @param buf Log bytes to write.
 * @param len Number of bytes in `buf`.
 */
WW_EXPORT void loggerWrite(logger_t *logger, const char *buf, int len);
/**
 * @brief Console sink that writes to stdout.
 *
 * @param loglevel Message log level.
 * @param buf Rendered message bytes.
 * @param len Number of bytes in `buf`.
 */
WW_EXPORT void stdoutLogger(int loglevel, const char *buf, int len);
/**
 * @brief Console sink that writes to stderr.
 *
 * @param loglevel Message log level.
 * @param buf Rendered message bytes.
 * @param len Number of bytes in `buf`.
 */
WW_EXPORT void stderrLogger(int loglevel, const char *buf, int len);
/**
 * @brief File sink that writes through the default logger.
 *
 * @param loglevel Message log level.
 * @param buf Rendered message bytes.
 * @param len Number of bytes in `buf`.
 */
WW_EXPORT void fileLogger(int loglevel, const char *buf, int len);
// network_logger implement see event/nlog.h
// WW_EXPORT void network_logger(int loglevel, const char* buf, int len);

/**
 * @brief Allocate and initialize a logger instance.
 *
 * @return New logger object.
 */
WW_EXPORT logger_t *loggerCreate(void);
/**
 * @brief Destroy a logger instance and release resources.
 *
 * @param logger Logger instance to destroy.
 */
WW_EXPORT void      loggerDestroy(logger_t *logger);

/**
 * @brief Set the sink callback used to emit log records.
 *
 * @param logger Logger instance.
 * @param fn Sink callback function.
 */
WW_EXPORT void loggerSetHandler(logger_t *logger, logger_handler fn);
/**
 * @brief Set minimum enabled log level.
 *
 * @param logger Logger instance.
 * @param level One value from `log_level_e`.
 */
WW_EXPORT void loggerSetLevel(logger_t *logger, int level);
// level = [VERBOSE,DEBUG,INFO,WARN,ERROR,FATAL,SILENT]
/**
 * @brief Set minimum enabled log level from a string value.
 *
 * @param logger Logger instance.
 * @param level Text level (for example `"INFO"`).
 */
WW_EXPORT void           loggerSetLevelByString(logger_t *logger, const char *level);
/**
 * @brief Check whether a message level should be emitted.
 *
 * @param logger Logger instance.
 * @param level Message level to test.
 * @return Non-zero when the message should be written.
 */
WW_EXPORT int            loggerCheckWriteLevel(logger_t *logger, log_level_e level);
/**
 * @brief Get the currently configured sink callback.
 *
 * @param logger Logger instance.
 * @return Sink callback.
 */
WW_EXPORT logger_handler loggerGetHandle(logger_t *logger);
/*
 * format  = "%y-%m-%d %H:%M:%S.%z %L %s"
 * message = "2020-01-02 03:04:05.067 DEBUG message"
 * %y year
 * %m month
 * %d day
 * %H hour
 * %M min
 * %S sec
 * %z ms
 * %Z us
 * %l First character of level
 * %L All characters of level
 * %s message
 * %% %
 */
/**
 * @brief Set output format template.
 *
 * @param logger Logger instance.
 * @param format Format string (supports `%y %m %d %H %M %S %z %Z %l %L %s %%`).
 */
WW_EXPORT void loggerSetFormat(logger_t *logger, const char *format);
/**
 * @brief Resize the internal temporary formatting buffer.
 *
 * @param logger Logger instance.
 * @param bufsize Buffer size in bytes.
 */
WW_EXPORT void loggerSetMaxBufSIze(logger_t *logger, unsigned int bufsize);
/**
 * @brief Enable or disable ANSI color sequences.
 *
 * @param logger Logger instance.
 * @param on Non-zero to enable, zero to disable.
 */
WW_EXPORT void loggerEnableColor(logger_t *logger, int on);
/**
 * @brief Print a formatted log message with a `va_list`.
 *
 * @param logger Logger instance.
 * @param level Message level.
 * @param fmt Format string.
 * @param ap Variadic argument list.
 * @return Number of bytes formatted/written, or negative on skip/error.
 */
WW_EXPORT int  loggerPrintVA(logger_t *logger, int level, const char *fmt, va_list ap);

/**
 * @brief Convenience variadic wrapper around `loggerPrintVA`.
 *
 * @param logger Logger instance.
 * @param level Message level.
 * @param fmt Format string.
 * @return Number of bytes formatted/written, or negative on skip/error.
 */
static inline int loggerPrint(logger_t *logger, int level, const char *fmt, ...)
{
    va_list myargs;
    va_start(myargs, fmt);
    int ret = loggerPrintVA(logger, level, fmt, myargs);
    va_end(myargs);
    return ret;
}

// below for file logger
/**
 * @brief Configure base log file path.
 *
 * @param logger Logger instance.
 * @param filepath Log file path/prefix.
 * @return `true` when file logging remains enabled.
 */
WW_EXPORT bool loggerSetFile(logger_t *logger, const char *filepath);
/**
 * @brief Set max size of a single rotated log file.
 *
 * @param logger Logger instance.
 * @param filesize Maximum bytes per file.
 */
WW_EXPORT void loggerSetMaxFileSize(logger_t *logger, unsigned long long filesize);
// 16, 16M, 16MB
/**
 * @brief Set max file size from a human-readable string.
 *
 * @param logger Logger instance.
 * @param filesize Size text such as `"16M"`.
 */
WW_EXPORT void        loggerSetMaxFileSizeByStr(logger_t *logger, const char *filesize);
/**
 * @brief Set log retention window in days.
 *
 * @param logger Logger instance.
 * @param days Number of days to keep logs.
 */
WW_EXPORT void        loggerSetRemainDays(logger_t *logger, int days);
/**
 * @brief Enable or disable flushing on each write.
 *
 * @param logger Logger instance.
 * @param on Non-zero to enable immediate flush.
 */
WW_EXPORT void        loggerEnableFileSync(logger_t *logger, int on);
/**
 * @brief Flush current log file buffer.
 *
 * @param logger Logger instance.
 */
WW_EXPORT void        loggerSyncFile(logger_t *logger);
/**
 * @brief Get current active log file name.
 *
 * @param logger Logger instance.
 * @return Current log file path.
 */
WW_EXPORT const char *loggerSetCurrentFile(logger_t *logger);

// wlog: default logger instance
/**
 * @brief Get singleton default logger instance.
 *
 * @return Default logger.
 */
WW_EXPORT logger_t *loggerGetDefaultLogger(void);
/**
 * @brief Destroy singleton default logger instance.
 */
WW_EXPORT void      loggerDestroyDefaultLogger(void);

// macro wlog*
#ifndef wlog
#define wlog loggerGetDefaultLogger()
#endif

#define checkWLogWriteLevel(level)        loggerCheckWriteLevel(wlog, level)

// below for android
#if defined(ANDROID) || defined(__ANDROID__)
#include <android/log.h>
#define LOG_TAG "JNI"
/**
 * @brief Log a debug message through the default logger backend.
 *
 * @param fmt Format string.
 */
static inline void wlogd(const char *fmt, ...)
{
    va_list myargs;
    va_start(myargs, fmt);
    __android_log_vprint(ANDROID_LOG_DEBUG, LOG_TAG, fmt, myargs);
    va_end(myargs);
}

/**
 * @brief Log an info message through the default logger backend.
 *
 * @param fmt Format string.
 */
static inline void wlogi(const char *fmt, ...)
{
    va_list myargs;
    va_start(myargs, fmt);
    __android_log_vprint(ANDROID_LOG_INFO, LOG_TAG, fmt, myargs);
    va_end(myargs);
}

/**
 * @brief Log a warning message through the default logger backend.
 *
 * @param fmt Format string.
 */
static inline void wlogw(const char *fmt, ...)
{
    va_list myargs;
    va_start(myargs, fmt);
    __android_log_vprint(ANDROID_LOG_WARN, LOG_TAG, fmt, myargs);
    va_end(myargs);
}

/**
 * @brief Log an error message through the default logger backend.
 *
 * @param fmt Format string.
 */
static inline void wloge(const char *fmt, ...)
{
    va_list myargs;
    va_start(myargs, fmt);
    __android_log_vprint(ANDROID_LOG_ERROR, LOG_TAG, fmt, myargs);
    va_end(myargs);
}
/**
 * @brief Log a fatal message through the default logger backend.
 *
 * @param fmt Format string.
 */
static inline void wlogf(const char *fmt, ...)
{
    va_list myargs;
    va_start(myargs, fmt);
    __android_log_vprint(ANDROID_LOG_FATAL, LOG_TAG, fmt, myargs);
    va_end(myargs);
}
#else

/**
 * @brief Log a debug message through the default logger backend.
 *
 * @param fmt Format string.
 */
static void wlogd(const char *fmt, ...)
{
    va_list myargs;
    va_start(myargs, fmt);
    loggerPrintVA(wlog, LOG_LEVEL_DEBUG, fmt, myargs);
    va_end(myargs);
}

/**
 * @brief Log an info message through the default logger backend.
 *
 * @param fmt Format string.
 */
static void wlogi(const char *fmt, ...)
{
    va_list myargs;
    va_start(myargs, fmt);
    loggerPrintVA(wlog, LOG_LEVEL_INFO, fmt, myargs);
    va_end(myargs);
}

/**
 * @brief Log a warning message through the default logger backend.
 *
 * @param fmt Format string.
 */
static void wlogw(const char *fmt, ...)
{
    va_list myargs;
    va_start(myargs, fmt);
    loggerPrintVA(wlog, LOG_LEVEL_WARN, fmt, myargs);
    va_end(myargs);
}

/**
 * @brief Log an error message through the default logger backend.
 *
 * @param fmt Format string.
 */
static void wloge(const char *fmt, ...)
{
    va_list myargs;
    va_start(myargs, fmt);
    loggerPrintVA(wlog, LOG_LEVEL_ERROR, fmt, myargs);
    va_end(myargs);
}
/**
 * @brief Log a fatal message through the default logger backend.
 *
 * @param fmt Format string.
 */
static void wlogf(const char *fmt, ...)
{
    va_list myargs;
    va_start(myargs, fmt);
    loggerPrintVA(wlog, LOG_LEVEL_FATAL, fmt, myargs);
    va_end(myargs);
}
#endif

// macro alias
#if ! defined(LOGD) && ! defined(LOGI) && ! defined(LOGW) && ! defined(LOGE) && ! defined(LOGF)
#define LOGD wlogd
#define LOGI wlogi
#define LOGW wlogw
#define LOGE wloge
#define LOGF wlogf
#endif

#endif // WW_LOG_H_
