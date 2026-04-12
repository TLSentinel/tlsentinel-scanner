//go:build windows

package main

import (
	"context"
	"os"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
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
		core := zapcore.NewCore(
			zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()),
			zapcore.AddSync(&eventLogWriter{log: elog}),
			zap.InfoLevel,
		)
		zap.ReplaceGlobals(zap.New(core))
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
			zap.L().Info("service stopping")
			cancel()
			changes <- svc.Status{State: svc.StopPending}
			return false, 0
		}
	}
	return false, 0
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
		zap.L().Error("service failed", zap.Error(err))
	}
}

// eventLogWriter routes zap output to the Windows Event Log.
type eventLogWriter struct{ log *eventlog.Log }

func (w *eventLogWriter) Write(p []byte) (int, error) {
	_ = w.log.Info(3, string(p))
	return len(p), nil
}

func (w *eventLogWriter) Sync() error { return nil }
