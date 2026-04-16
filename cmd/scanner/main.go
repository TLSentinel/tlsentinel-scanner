package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/tlsentinel/tlsentinel-scanner/internal/logger"
	"github.com/tlsentinel/tlsentinel-scanner/internal/version"
)

func main() {
	rootCmd := &cobra.Command{
		Use:          "scanner",
		Short:        "TLSentinel Scanner — TLS certificate scanner agent",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			isService, err := isWindowsService()
			if err != nil {
				return fmt.Errorf("determining execution mode: %w", err)
			}

			if isService {
				runService()
				return nil
			}

			logger.Build()

			slog.Info("starting",
				"version", version.Version,
				"commit", version.Commit,
				"built", version.BuildTime,
			)

			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

			// Restore default signal handling once the first signal fires so a
			// second Ctrl-C immediately kills the process during shutdown.
			go func() {
				<-ctx.Done()
				stop()
			}()

			run(ctx, buildClient())
			return nil
		},
	}

	installCmd := &cobra.Command{
		Use:   "install",
		Short: "Install as a Windows service (requires admin)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := installService(ServiceName, ServiceDisplayName); err != nil {
				return err
			}
			fmt.Println("Service installed successfully.")
			return nil
		},
	}

	removeCmd := &cobra.Command{
		Use:   "remove",
		Short: "Remove the Windows service (requires admin)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := removeService(ServiceName); err != nil {
				return err
			}
			fmt.Println("Service removed successfully.")
			return nil
		},
	}

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("Version:    %s\n", version.Version)
			fmt.Printf("Commit:     %s\n", version.Commit)
			fmt.Printf("Build time: %s\n", version.BuildTime)
		},
	}

	rootCmd.AddCommand(installCmd, removeCmd, versionCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
