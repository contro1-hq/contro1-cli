package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/contro1-hq/contro1-cli/internal/broker"
	"github.com/contro1-hq/contro1-cli/internal/brokerpaths"
	"github.com/contro1-hq/contro1-cli/internal/brokerstore"
	"github.com/contro1-hq/contro1-cli/internal/installer"
	"github.com/contro1-hq/contro1-cli/internal/localipc"
	"github.com/contro1-hq/contro1-cli/internal/output"
	"github.com/contro1-hq/contro1-cli/internal/runtimeproto"
)

var (
	flagBrokerForeground    bool
	flagBrokerStateDir      string
	flagBrokerControl       string
	flagBrokerDevUserCtrl   bool
	flagBrokerDryRun        bool
	flagBrokerInstallBinary string
	flagBrokerPurge         bool
)

var brokerInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install the Contro1 service (contro1 connect does this for you)",
	Args:  cobra.NoArgs,
	RunE:  runBrokerInstall,
}

var brokerUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Remove the Contro1 service (keeps connections unless --purge)",
	Args:  cobra.NoArgs,
	RunE:  runBrokerUninstall,
}

var brokerCmd = &cobra.Command{
	Use:     "broker",
	Short:   "The Contro1 service that holds agent connections on this computer",
	GroupID: groupAgent,
	Long: `The Contro1 service keeps each connected agent's key and credentials on this
computer and serves one private local endpoint per agent. You normally never run
these commands yourself: contro1 connect installs and configures the service.`,
}

var brokerServeCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run the Contro1 service (started by the service manager, or --foreground for development)",
	Args:  cobra.NoArgs,
	RunE:  runBrokerServe,
}

var brokerStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show the Contro1 service health and connections (no secrets)",
	Args:  cobra.NoArgs,
	RunE:  runBrokerStatus,
}

func init() {
	brokerServeCmd.Flags().BoolVar(&flagBrokerForeground, "foreground", false, "run in the foreground as the current user (development)")
	brokerServeCmd.Flags().StringVar(&flagBrokerStateDir, "state-dir", "", "state directory (default depends on mode)")
	brokerServeCmd.Flags().StringVar(&flagBrokerControl, "control-endpoint", "", "control endpoint (npipe:// or unix://)")
	brokerServeCmd.Flags().BoolVar(&flagBrokerDevUserCtrl, "dev-allow-current-user-control", false, "let the current user use the control endpoint (development only; doctor reports it as blocked)")
	for _, c := range []*cobra.Command{brokerStatusCmd} {
		c.Flags().StringVar(&flagBrokerStateDir, "state-dir", "", "state directory")
		c.Flags().StringVar(&flagBrokerControl, "control-endpoint", "", "control endpoint")
		c.Flags().BoolVar(&flagBrokerForeground, "dev", false, "inspect the development broker")
	}
	brokerInstallCmd.Flags().BoolVar(&flagBrokerDryRun, "dry-run", false, "print exactly what would change, change nothing")
	brokerUninstallCmd.Flags().BoolVar(&flagBrokerDryRun, "dry-run", false, "print exactly what would change, change nothing")
	brokerUninstallCmd.Flags().BoolVar(&flagBrokerPurge, "purge", false, "also delete local connection state and keys")
	brokerCmd.AddCommand(brokerServeCmd, brokerStatusCmd, brokerInstallCmd, brokerUninstallCmd)
	rootCmd.AddCommand(brokerCmd)
}

func brokerLayout(foreground bool) brokerpaths.Layout {
	layout := brokerpaths.Production(runtime.GOOS)
	if foreground {
		layout = brokerpaths.Development()
	}
	if flagBrokerStateDir != "" {
		layout.StateDir = flagBrokerStateDir
	}
	if flagBrokerControl != "" {
		layout.ControlEndpoint = flagBrokerControl
	}
	return layout
}

// servicePrincipal is who the running broker is: the per-service SID on
// Windows, the dedicated user on unix, the current user in development.
func servicePrincipal(foreground bool) (string, error) {
	if foreground || runtime.GOOS != "windows" {
		me, err := localipc.CurrentIdentity()
		if err != nil {
			return "", err
		}
		return me.User, nil
	}
	return brokerpaths.WindowsServiceSID(brokerpaths.ServiceName), nil
}

func controlPrincipals(service string) []localipc.Principal {
	if runtime.GOOS == "windows" {
		return []localipc.Principal{"S-1-5-18", "S-1-5-32-544", localipc.Principal(service)}
	}
	return []localipc.Principal{"uid:0", localipc.Principal(service)}
}

func runBrokerServe(cmd *cobra.Command, _ []string) error {
	layout := brokerLayout(flagBrokerForeground)
	control, err := localipc.ParseEndpoint(layout.ControlEndpoint)
	if err != nil {
		return output.Errf(output.CodeBadArgs, "%v", err)
	}
	principal, err := servicePrincipal(flagBrokerForeground)
	if err != nil {
		return output.Errf(output.CodeGeneral, "resolving service identity: %v", err)
	}
	if err := os.MkdirAll(layout.LogDir, 0o700); err != nil {
		return output.Errf(output.CodeGeneral, "log directory: %v", err)
	}
	logFile, err := os.OpenFile(fmt.Sprintf("%s/broker.log", layout.LogDir), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	var sink io.Writer = os.Stderr
	if err == nil {
		defer logFile.Close()
		if flagBrokerForeground {
			sink = io.MultiWriter(os.Stderr, logFile)
		} else {
			sink = logFile
		}
	}
	logger := log.New(sink, "contro1-broker ", log.LstdFlags|log.LUTC)

	cfg := broker.Config{
		StateDir:                   layout.StateDir,
		APIURL:                     flagAPIURL,
		Version:                    Version,
		Foreground:                 flagBrokerForeground,
		ControlEndpoint:            control,
		ControlPrincipals:          controlPrincipals(principal),
		ServicePrincipal:           principal,
		EndpointDir:                layout.EndpointDir,
		PlatformsDir:               layout.PlatformsDir,
		DevAllowCurrentUserControl: flagBrokerForeground && flagBrokerDevUserCtrl,
		Logf:                       logger.Printf,
	}
	run := func(ctx context.Context) error {
		b, err := broker.New(cfg)
		if err != nil {
			logger.Printf("start failed: %v", err)
			return err
		}
		logger.Printf("started version=%s state=%s control=%s", Version, layout.StateDir, control)
		return b.Run(ctx)
	}

	if !flagBrokerForeground {
		if handled, err := broker.RunUnderServiceManager(brokerpaths.ServiceName, run); handled {
			return err
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		if err == brokerstore.ErrLocked {
			return output.Errf(output.CodeConflict, "%v", err)
		}
		return output.Errf(output.CodeGeneral, "%v", err)
	}
	return nil
}

func runBrokerStatus(cmd *cobra.Command, _ []string) error {
	layout := brokerLayout(flagBrokerForeground)
	result := map[string]any{"state_dir": layout.StateDir, "control_endpoint": layout.ControlEndpoint}
	if ep, err := localipc.ParseEndpoint(layout.ControlEndpoint); err == nil {
		client := localipc.HTTPClient(ep, "")
		client.Timeout = 3 * time.Second
		if resp, err := client.Get(localipc.BaseURL + "/control/v1/health"); err == nil {
			var health map[string]any
			_ = json.NewDecoder(resp.Body).Decode(&health)
			resp.Body.Close()
			result["running"] = true
			result["health"] = health
		} else {
			result["running"] = false
			result["control_error"] = err.Error()
		}
	}
	if st, err := brokerstore.OpenReadOnly(layout.StateDir).ReadStatus(); err == nil {
		result["status"] = st
	}
	format := flagFormat
	if format == "" || format == "table" {
		running, _ := result["running"].(bool)
		fmt.Printf("Contro1 service: %s\n", map[bool]string{true: "running", false: "not reachable"}[running])
		if st, ok := result["status"].(*brokerstore.PublicStatus); ok {
			fmt.Printf("Key protection: %s\n", st.KeyProtection)
			for _, en := range st.Enrollments {
				fmt.Printf("  %-24s %-10s %-24s %s\n", en.Subject, en.State, en.EndpointMode, en.EndpointHealth)
			}
		}
		return nil
	}
	return output.Render(format, result, nil)
}

func installOptions() (installer.Options, error) {
	exe, err := os.Executable()
	if err != nil {
		return installer.Options{}, err
	}
	return installer.Options{SourceBinary: exe, APIURL: flagAPIURL, Version: Version}, nil
}

func needsElevationError(command string) error {
	next := installer.SudoHint(command)
	if next == "" {
		next = "Approve the Windows prompt, or run the command from an administrator terminal."
	}
	return output.Errf(output.CodeUnsafeBlocked, "installing the Contro1 service needs administrator rights").WithRemediation(&runtimeproto.Remediation{
		Code:          "LOCAL_CONFIRMATION_REQUIRED",
		PublicMessage: "Installing the Contro1 service changes this computer and needs administrator approval.",
		Missing:       "Administrator approval on this computer.",
		NextStep:      next,
		Retryable:     true,
	})
}

func runBrokerInstall(cmd *cobra.Command, _ []string) error {
	opts, err := installOptions()
	if err != nil {
		return output.Errf(output.CodeGeneral, "%v", err)
	}
	plan := installer.Plan(runtime.GOOS, opts)
	if flagBrokerDryRun {
		return renderPlan(plan)
	}
	if !installer.IsElevated() {
		if runtime.GOOS != "windows" {
			return needsElevationError("contro1 broker install")
		}
		args := []string{"broker", "install"}
		if flagAPIURL != "" {
			args = append(args, "--api-url", flagAPIURL)
		}
		code, err := installer.RunElevated(args)
		if err == installer.ErrElevationDeclined {
			return needsElevationError("contro1 broker install")
		}
		if err != nil {
			return output.Errf(output.CodeGeneral, "%v", err)
		}
		if code != 0 {
			return output.Errf(code, "the elevated installer exited with code %d; see %s", code, brokerpaths.Production(runtime.GOOS).LogDir)
		}
		output.Info("Contro1 service installed and running (starts automatically)")
		return nil
	}
	journal := brokerpaths.Production(runtime.GOOS).StateDir + "/install-journal.json"
	res, err := installer.Apply(plan, installer.SystemRunner{}, journal)
	if err != nil {
		return output.Errf(output.CodeGeneral, "%v (rolled back: %v)", err, res.RolledBack)
	}
	return output.Render(firstFormat("json"), res, nil)
}

func runBrokerUninstall(cmd *cobra.Command, _ []string) error {
	plan := installer.UninstallPlan(runtime.GOOS, flagBrokerPurge)
	if flagBrokerDryRun {
		return renderPlan(plan)
	}
	return output.Errf(output.CodeUnsafeBlocked, "run contro1 disconnect first; uninstall is applied by disconnect when no connections remain (use --dry-run to preview)")
}

func renderPlan(plan installer.InstallPlan) error {
	if flagFormat == "json" || flagFormat == "yaml" {
		return output.Render(flagFormat, plan, nil)
	}
	fmt.Println("Contro1 service plan (nothing has changed):")
	for _, line := range plan.Summary {
		fmt.Println("  - " + line)
	}
	if plan.Unverified {
		fmt.Println("  Note: this operating system path has not been verified yet.")
	}
	return nil
}

func firstFormat(fallback string) string {
	if flagFormat != "" {
		return flagFormat
	}
	return fallback
}
