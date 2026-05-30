package logger

import (
    "log"
    "sync"
    "strings"
    "os"
)

type LogLevel int

const (
    FATAL LogLevel = iota
    ERROR
    WARN
    INFO
    DEBUG
    TRACE
)

var levelName = map[LogLevel]string {
    FATAL: "FATAL",
    ERROR: "ERROR",
    WARN: "WARN",
    INFO: "INFO",
    DEBUG: "DEBUG",
    TRACE: "TRACE",
}

func ConvertStringToLogLevel(levelName string) LogLevel {
    switch (strings.ToUpper(levelName)) {
    case "FATAL":
        return FATAL
    case "ERROR":
        return ERROR
    case "WARN":
        return WARN
    case "INFO":
        return INFO
    case "DEBUG":
        return DEBUG
    case "TRACE":
        return TRACE
    default:
        log.Printf("[ERROR]: Invalid log level: %v. Defaulting to `INFO`", levelName)
        return INFO
    }
}

var lock = &sync.Mutex{}

type logger struct {
    level LogLevel
    logPath string
}

var loggerInstance *logger

func GetLoggerInstance() *logger {
    if loggerInstance == nil {
        lock.Lock()
        defer lock.Unlock()
        if loggerInstance == nil {
            loggerInstance = &logger{INFO, "masque.log"}
        }
    }
    return loggerInstance
}

func UpdateLoggerInstance(level LogLevel, logPath string) {
    GetLoggerInstance().level = level
    GetLoggerInstance().logPath = logPath
}

func UpdateLogLevel(level LogLevel) {
    GetLoggerInstance().level = level
}

func UpdateLogLevelName(levelName string) {
    level := ConvertStringToLogLevel(levelName)
    GetLoggerInstance().level = level
}

func UpdateLogPath(logPath string) {
    GetLoggerInstance().logPath = logPath
}

func GetLogLevel() LogLevel {
    return GetLoggerInstance().level
}

func GetLogPath() string {
    return GetLoggerInstance().logPath
}

func (level LogLevel) string() string {
    return levelName[level]
}

// ShouldLog reports whether a message at the given level would be emitted at the
// current log level. Call it before building a (potentially large) log message so
// the formatting work is skipped entirely when the message would be dropped —
// important on memory-constrained / diskless clients. Matches the server logger.
func ShouldLog(level LogLevel) bool {
    return GetLogLevel() >= level
}

func Fatal(msg string) {
    if GetLogLevel() >= FATAL {
        log.Printf("[%v]: %v", FATAL.string(), msg)
        os.Exit(1)
    }
}

func Error(msg string) {
    if GetLogLevel() >= ERROR {
        log.Printf("[%v]: %v", ERROR.string(), msg)
    }
}

func Warn(msg string) {
    if GetLogLevel() >= WARN {
        log.Printf("[%v]: %v", WARN.string(), msg)
    }
}

func Info(msg string) {
    if GetLogLevel() >= INFO {
        log.Printf("[%v]: %v", INFO.string(), msg)
    }
}

func Debug(msg string) {
    if GetLogLevel() >= DEBUG {
        log.Printf("[%v]: %v", DEBUG.string(), msg)
    }
}

func Trace(msg string) {
    if GetLogLevel() >= TRACE {
        log.Printf("[%v]: %v", TRACE.string(), msg)
    }
}
