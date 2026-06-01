package stats

import "log"

// The stats package is a SECOND, independent logging singleton — separate from the
// leveled `logger`. The leveled logger has exactly one verbosity level; statistics
// are an orthogonal concern (expensive per-packet counters/diagnostics), so they get
// their own on/off channel toggled from ENABLE_STATISTIC. Output goes through the
// standard `log` package, so it shares whatever destination logger set via
// log.SetOutput. Guard the (often expensive) message construction with ShouldLog().
var enabled bool

// Enable turns the statistic channel on or off (set this from ENABLE_STATISTIC at startup).
func Enable(on bool) {
	enabled = on
}

// ShouldLog reports whether statistics are enabled.
func ShouldLog() bool {
	return enabled
}

// Statistic emits a "[STATISTIC]: ..." line when the channel is on.
func Statistic(msg string) {
	if enabled {
		log.Printf("[STATISTIC]: %v", msg)
	}
}
