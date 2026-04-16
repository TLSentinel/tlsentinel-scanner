// Package logger configures the global slog logger from environment variables.
//
// Call [Build] once in main to initialise and install the global logger.
//
// Configuration (environment variables):
//
//	TLSENTINEL_LOG_LEVEL   debug | info | warn | error  (default: info)
//	TLSENTINEL_LOG_FORMAT  json  | text | auto          (default: auto)
//
// In "auto" mode the format is "text" (human-readable) when stdout is attached
// to a terminal, and "json" otherwise (Docker / production).
package logger

import (
	"log/slog"
	"os"
	"strings"
)

// Build constructs a slog.Logger from the TLSENTINEL_LOG_* environment
// variables and installs it as the global default logger.
func Build() {
	level := parseLevel(os.Getenv("TLSENTINEL_LOG_LEVEL"))
	useJSON := resolveFormat(os.Getenv("TLSENTINEL_LOG_FORMAT"))

	var handler slog.Handler
	opts := &slog.HandlerOptions{Level: level}
	if useJSON {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, opts)
	}

	slog.SetDefault(slog.New(handler))
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// resolveFormat returns true for JSON, false for text.
func resolveFormat(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "json":
		return true
	case "text":
		return false
	default: // "auto" or unset — JSON unless stdout is a terminal
		return !isTerminal(os.Stdout)
	}
}

func isTerminal(f *os.File) bool {
	stat, err := f.Stat()
	if err != nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) != 0
}
