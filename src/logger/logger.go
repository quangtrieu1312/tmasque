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

// STATISTIC is a special on/off channel (set from ENABLE_STATISTIC), independent of
// the FATAL..TRACE verbosity ladder — so periodic counters/diagnostics can be turned
// on without raising the log level. ShouldLog(STATISTIC) returns its toggle and
// Statistic() emits "[STATISTIC]: ...".
const STATISTIC LogLevel = 100

var levelName = map[LogLevel]string {
    FATAL: "FATAL",
    ERROR: "ERROR",
    WARN: "WARN",
    INFO: "INFO",
    DEBUG: "DEBUG",
    TRACE: "TRACE",
    STATISTIC: "STATISTIC",
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
    statistic bool
}

var loggerInstance *logger

func GetLoggerInstance() *logger {
    if loggerInstance == nil {
        lock.Lock()
        defer lock.Unlock()
        if loggerInstance == nil {
            loggerInstance = &logger{level: INFO, logPath: "masque.log"}
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
    if level == STATISTIC {
        return GetLoggerInstance().statistic
    }
    return GetLogLevel() >= level
}

// SetStatistic toggles the STATISTIC channel on/off (set this from ENABLE_STATISTIC).
func SetStatistic(on bool) {
    GetLoggerInstance().statistic = on
}

// Statistic emits a "[STATISTIC]: ..." line when the STATISTIC channel is on.
func Statistic(msg string) {
    if GetLoggerInstance().statistic {
        log.Printf("[%v]: %v", STATISTIC.string(), msg)
    }
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
