package config

import (
    "bufio"
    "context"
    "fmt"
    "os"
    "strconv"
    "strings"
    "time"
    "unsafe"

    "golang.org/x/sys/unix"

    "github.com/quangtrieu1312/tmasque/constants"
    "github.com/quangtrieu1312/tmasque/logger"
    "github.com/quangtrieu1312/tmasque/stats"
)

// Watch starts an inotify watcher on the config file and, on each change, re-reads
// it and hot-applies the settings that are safe to change at runtime — currently
// LOG_LEVEL and ENABLE_STATISTIC. Everything else (server address, FWMARK, key
// logging / TLS, …) is read once at boot and needs a restart to change; those are
// intentionally ignored here. The watcher runs until ctx is cancelled.
//
// It watches the file itself and re-arms on replace, so both in-place writes and
// rename-on-save (most editors) are picked up on a normal filesystem (the diskless
// Pi client edits its conf on a real fs, so this works there).
func Watch(ctx context.Context) {
    go func() {
        fd, err := unix.InotifyInit1(unix.IN_CLOEXEC)
        if err != nil {
            if logger.ShouldLog(logger.ERROR) {
                logger.Error(fmt.Sprintf("config watch: inotify init failed: %v", err))
            }
            return
        }
        // Closing the fd from another goroutine unblocks the Read below on shutdown.
        go func() {
            <-ctx.Done()
            unix.Close(fd)
        }()

        const mask = unix.IN_CLOSE_WRITE | unix.IN_MODIFY | unix.IN_IGNORED | unix.IN_MOVE_SELF | unix.IN_DELETE_SELF
        addWatch := func() {
            if _, err := unix.InotifyAddWatch(fd, constants.CONF_PATH, mask); err != nil {
                if logger.ShouldLog(logger.ERROR) {
                    logger.Error(fmt.Sprintf("config watch: add watch failed: %v", err))
                }
            }
        }
        addWatch()

        buf := make([]byte, 4096)
        for {
            n, err := unix.Read(fd, buf)
            if err != nil {
                return // fd closed (ctx cancelled) or read error
            }
            changed, reArm := false, false
            for off := 0; off+unix.SizeofInotifyEvent <= n; {
                ev := (*unix.InotifyEvent)(unsafe.Pointer(&buf[off]))
                if ev.Mask&(unix.IN_CLOSE_WRITE|unix.IN_MODIFY) != 0 {
                    changed = true
                }
                if ev.Mask&(unix.IN_IGNORED|unix.IN_MOVE_SELF|unix.IN_DELETE_SELF) != 0 {
                    reArm = true // file was replaced/renamed; the old watch is gone
                }
                off += unix.SizeofInotifyEvent + int(ev.Len)
            }
            if reArm {
                time.Sleep(50 * time.Millisecond) // let the replacement file settle
                addWatch()
                changed = true
            }
            if changed {
                reloadAndApply()
            }
        }
    }()
}

// reloadAndApply re-reads the config file (non-fatal — a transient read error must
// not kill the client) and applies only the hot-reloadable settings.
func reloadAndApply() {
    f, err := os.Open(constants.CONF_PATH)
    if err != nil {
        if logger.ShouldLog(logger.ERROR) {
            logger.Error(fmt.Sprintf("config watch: reopen failed: %v", err))
        }
        return
    }
    defer f.Close()

    vals := map[string]string{}
    scanner := bufio.NewScanner(f)
    for scanner.Scan() {
        line := strings.TrimSpace(scanner.Text())
        if line == "" || strings.HasPrefix(line, "#") {
            continue
        }
        parts := strings.SplitN(line, "=", 2)
        if len(parts) != 2 {
            continue
        }
        key := strings.TrimSpace(parts[0])
        if key != "" {
            vals[key] = strings.TrimSpace(parts[1])
        }
    }

    if v, ok := vals["LOG_LEVEL"]; ok && v != "" {
        logger.UpdateLogLevelName(v)
    }
    if v, ok := vals["ENABLE_STATISTIC"]; ok {
        on, _ := strconv.ParseBool(v)
        stats.Enable(on)
    }
    if logger.ShouldLog(logger.INFO) {
        logger.Info("config: hot-reloaded (applied LOG_LEVEL, ENABLE_STATISTIC; other keys need a restart)")
    }
}
