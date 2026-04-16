//go:build windows

package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

// ScannerService implements the Windows Service Control Manager interface.
type ScannerService struct{}

func (s *ScannerService) Execute(_ []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	if elog, err := eventlog.Open(ServiceName); err == nil {
		slog.SetDefault(slog.New(&eventLogHandler{log: elog}))
		defer elog.Close()
	}

	ctx, cancel := context.WithCancel(context.Background())
	go run(ctx, buildClient())

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	for c := range r {
		switch c.Cmd {
		case svc.Interrogate:
			changes <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			slog.Info("service stopping")
			cancel()
			changes <- svc.Status{State: svc.StopPending}
			return false, 0
		}
	}
	return false, 0
}

// eventLogHandler is a slog.Handler that routes log records to the Windows
// Event Log, mapping slog levels to the appropriate event log severity.
type eventLogHandler struct {
	log   *eventlog.Log
	attrs []slog.Attr
}

func (h *eventLogHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }

func (h *eventLogHandler) Handle(_ context.Context, r slog.Record) error {
	var sb strings.Builder
	sb.WriteString(r.Message)
	// Append any structured attrs as key=value pairs.
	r.Attrs(func(a slog.Attr) bool {
		fmt.Fprintf(&sb, " %s=%v", a.Key, a.Value)
		return true
	})
	for _, a := range h.attrs {
		fmt.Fprintf(&sb, " %s=%v", a.Key, a.Value)
	}
	msg := sb.String()

	switch {
	case r.Level >= slog.LevelError:
		return h.log.Error(3, msg)
	case r.Level >= slog.LevelWarn:
		return h.log.Warning(3, msg)
	default:
		return h.log.Info(3, msg)
	}
}

func (h *eventLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	combined := make([]slog.Attr, len(h.attrs)+len(attrs))
	copy(combined, h.attrs)
	copy(combined[len(h.attrs):], attrs)
	return &eventLogHandler{log: h.log, attrs: combined}
}

func (h *eventLogHandler) WithGroup(name string) slog.Handler {
	// Groups not needed for Event Log — return self unchanged.
	return h
}

func installService(name, displayName string) error {
	exepath, err := os.Executable()
	if err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.CreateService(name, exepath, mgr.Config{
		DisplayName: displayName,
		StartType:   mgr.StartAutomatic,
	})
	if err != nil {
		return err
	}
	defer s.Close()

	if err := eventlog.InstallAsEventCreate(name, eventlog.Error|eventlog.Warning|eventlog.Info); err != nil {
		if !strings.Contains(err.Error(), "already installed") {
			_ = s.Delete()
			return err
		}
	}
	return nil
}

func removeService(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(name)
	if err != nil {
		return err
	}
	defer s.Close()

	if err := s.Delete(); err != nil {
		return err
	}
	return eventlog.Remove(name)
}

func isWindowsService() (bool, error) { return svc.IsWindowsService() }

func runService() {
	if err := svc.Run(ServiceName, &ScannerService{}); err != nil {
		slog.Error("service failed", "error", err)
	}
}
