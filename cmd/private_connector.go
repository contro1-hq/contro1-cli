package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/contro1-hq/contro1-cli/internal/broker"
	"github.com/contro1-hq/contro1-cli/internal/output"
	"github.com/contro1-hq/contro1-cli/internal/privateconnector"
	"github.com/spf13/cobra"
)

var privateConnectorStateDir string
var privateConnectorLogStdout bool

func privateConnectorState() string {
	if privateConnectorStateDir != "" {
		return privateConnectorStateDir
	}
	return privateconnector.ProductionLayout().StateDir
}

func init() {
	group := &cobra.Command{Use: "private-connector", Short: "Customer-hosted connector for private applications", GroupID: groupAdmin}
	install := &cobra.Command{Use: "install", Short: "Install the Windows, macOS or Linux (systemd) service from a JSON setup object on stdin", Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			input, err := privateconnector.DecodeSetup(os.Stdin)
			if err != nil {
				return output.Errf(output.CodeBadArgs, "%v", err)
			}
			if err := privateconnector.InstallService(input); err != nil {
				return output.Errf(output.CodeGeneral, "private connector install: %v", err)
			}
			fmt.Printf("Private connector service installed for %s.\n", input.InstallationID)
			return nil
		}}
	// For a container: the state is written to the volume and `serve` runs in
	// the foreground. No OS service is installed.
	provision := &cobra.Command{Use: "provision", Short: "Write an installation's local state from a JSON setup object on stdin, without installing a service (Docker)", Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			input, err := privateconnector.DecodeSetup(os.Stdin)
			if err != nil {
				return output.Errf(output.CodeBadArgs, "%v", err)
			}
			state := privateConnectorState()
			if err := privateconnector.CheckCapacity(state, input.InstallationID); err != nil {
				return output.Errf(output.CodeGeneral, "private connector provision: %v", err)
			}
			dir := privateconnector.InstallationDir(state, input.InstallationID)
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return output.Errf(output.CodeGeneral, "private connector provision: %v", err)
			}
			if err := privateconnector.Provision(dir, input); err != nil {
				return output.Errf(output.CodeGeneral, "private connector provision: %v", err)
			}
			fmt.Printf("Private connector state written for %s. Start it with: private-connector serve\n", input.InstallationID)
			return nil
		}}
	uninstall := &cobra.Command{Use: "uninstall", Short: "Stop and remove the local service; keep identity and configuration", Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := privateconnector.UninstallService(); err != nil {
				return output.Errf(output.CodeGeneral, "private connector uninstall: %v", err)
			}
			fmt.Println("Private connector service removed; local state was kept.")
			return nil
		}}
	serve := &cobra.Command{Use: "serve", Short: "Run the private connector worker", Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			state := privateConnectorState()
			// In a container the log is stdout, which the runtime collects.
			logTo := io.Writer(os.Stdout)
			if !privateConnectorLogStdout && os.Getenv("CONTRO1_CONNECTOR_LOG") != "stdout" {
				if err := os.MkdirAll(filepath.Join(state, "logs"), 0o700); err != nil {
					return err
				}
				file, err := os.OpenFile(filepath.Join(state, "logs", "connector.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
				if err != nil {
					return err
				}
				defer file.Close()
				logTo = file
			}
			logger := log.New(logTo, "private-connector ", log.LstdFlags|log.LUTC)
			version := strings.Map(func(r rune) rune {
				if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-' {
					return r
				}
				return '_'
			}, Version)
			if len(version) > 100 {
				version = version[:100]
			}
			run := func(ctx context.Context) error {
				logger.Printf("service started version=%s", version)
				err := privateconnector.Run(ctx, state, version, func(message string) { logger.Print(message) })
				if err != nil {
					logger.Printf("service stopped: %v", err)
				}
				return err
			}
			if runtime.GOOS == "windows" {
				if handled, err := broker.RunUnderServiceManager(privateconnector.WindowsServiceName, run); handled {
					return err
				}
			}
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			return run(ctx)
		}}
	status := &cobra.Command{Use: "status", Short: "Show local service and authenticated cloud contact", Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			running, serviceErr := privateconnector.ServiceRunning()
			result := map[string]any{"service_running": running, "state_dir": privateConnectorState()}
			if serviceErr != nil {
				result["service_error"] = serviceErr.Error()
			}
			workers := []privateconnector.PublicStatus{}
			if entries, err := os.ReadDir(filepath.Join(privateConnectorState(), "installations")); err == nil {
				for _, entry := range entries {
					if !entry.IsDir() {
						continue
					}
					path := filepath.Join(privateconnector.InstallationDir(privateConnectorState(), entry.Name()), "status.json")
					if raw, err := os.ReadFile(path); err == nil {
						var worker privateconnector.PublicStatus
						if json.Unmarshal(raw, &worker) == nil && worker.InstallationID == entry.Name() {
							workers = append(workers, worker)
						}
					}
				}
			}
			result["workers"] = workers
			if flagFormat == "json" || flagFormat == "yaml" {
				return output.Render(flagFormat, result, nil)
			}
			fmt.Printf("Private connector service: %v\n", running)
			for _, s := range workers {
				fmt.Printf("Installation: %s\nCloud: %s (last success %s)\nProvider: %s\n", s.InstallationID, s.CloudStatus, s.LastSuccess.Format("2006-01-02 15:04:05 MST"), s.ProviderStatus)
			}
			return nil
		}}
	serve.Flags().StringVar(&privateConnectorStateDir, "state-dir", "", "state directory (development only)")
	serve.Flags().BoolVar(&privateConnectorLogStdout, "log-stdout", false, "log to stdout instead of the state directory (containers)")
	provision.Flags().StringVar(&privateConnectorStateDir, "state-dir", "", "state directory")
	status.Flags().StringVar(&privateConnectorStateDir, "state-dir", "", "state directory")
	group.AddCommand(install, provision, serve, status, uninstall)
	rootCmd.AddCommand(group)
}
