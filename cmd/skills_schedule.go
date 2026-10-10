package cmd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

// The scheduled skills report.
//
// ONE PER COMPUTER, NOT PER TOOL. A report reads the folders every coding
// agent loads skills from (Claude Code, Codex, Cursor, Gemini CLI), so one
// schedule on a computer covers all of them.
//
// IT RUNS OFTEN AND SENDS RARELY. The schedule fires every four hours so a
// laptop that was asleep at the set time still reports the same day, and
// `--every 20h` makes all but one of those runs a no-op.
//
// What a scheduled run cannot see: skills inside a project folder. It runs in
// the home directory; project skills are reported by a run inside the project
// (the Claude Code SessionStart hook does that as people work).

const (
	skillsTaskName   = "Contro1 skills report"
	skillsCronMarker = "# contro1-skills-report"
)

var (
	skillsScheduleOff    bool
	skillsScheduleStatus bool
)

func init() {
	scheduleCmd := &cobra.Command{
		Use:   "schedule",
		Short: "Report this computer's agent skills automatically, once a day",
		Long: `Sets up an automatic skills report on this computer: every coding agent on it
(Claude Code, Codex, Cursor, Gemini CLI) is covered by one schedule.

It checks every four hours and sends at most once a day, so a laptop that was
off still reports the same day. Windows uses Task Scheduler (no window opens);
macOS and Linux use your crontab. Nothing else is changed.

Run it once after contro1 auth login. Skills inside a project folder are
reported by a run inside that project, for example the Claude Code hook.`,
		Example: `  contro1 skills schedule            # turn it on
  contro1 skills schedule --status   # is it on?
  contro1 skills schedule --off      # turn it off`,
		RunE: runSkillsSchedule,
	}
	scheduleCmd.Flags().BoolVar(&skillsScheduleOff, "off", false, "remove the schedule")
	scheduleCmd.Flags().BoolVar(&skillsScheduleStatus, "status", false, "say whether the schedule is on")
	for _, c := range rootCmd.Commands() {
		if c.Name() == "skills" {
			c.AddCommand(scheduleCmd)
		}
	}
}

func contro1Binary() (string, error) {
	bin, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("could not find the contro1 program: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(bin); err == nil {
		bin = resolved
	}
	return bin, nil
}

func runSkillsSchedule(cmd *cobra.Command, _ []string) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	var err error
	if runtime.GOOS == "windows" {
		err = scheduleWindows(ctx)
	} else {
		err = scheduleCron(ctx)
	}
	if err == nil && skillsScheduleStatus {
		printLastReport()
	}
	return err
}

// printLastReport says when this computer last reported, and why the last
// attempt failed if it did: a scheduler reports success either way.
func printLastReport() {
	if b, err := os.ReadFile(lastReportPath()); err == nil {
		infof("Last report sent: %s", strings.TrimSpace(string(b)))
	} else {
		infof("No report has been sent from this computer yet.")
	}
	if b, err := os.ReadFile(lastReportErrorPath()); err == nil {
		infof("Last attempt failed: %s", strings.TrimSpace(string(b)))
	}
}

// --- Windows: Task Scheduler ------------------------------------------------

func scheduleWindows(ctx context.Context) error {
	exists := exec.CommandContext(ctx, "schtasks", "/Query", "/TN", skillsTaskName).Run() == nil
	switch {
	case skillsScheduleStatus:
		if exists {
			infof("On: Task Scheduler runs %q every 4 hours and reports at most once a day.", skillsTaskName)
		} else {
			infof("Off. Turn it on with: contro1 skills schedule")
		}
		return nil
	case skillsScheduleOff:
		if !exists {
			infof("Already off.")
			return nil
		}
		if out, err := exec.CommandContext(ctx, "schtasks", "/Delete", "/TN", skillsTaskName, "/F").CombinedOutput(); err != nil {
			return fmt.Errorf("could not remove the task: %s", strings.TrimSpace(string(out)))
		}
		infof("Off. This computer no longer reports its skills automatically.")
		return nil
	}
	bin, err := contro1Binary()
	if err != nil {
		return err
	}
	// conhost --headless keeps a console window from flashing every 4 hours.
	action := fmt.Sprintf(`conhost.exe --headless "%s" skills report --every 20h --quiet`, bin)
	out, err := exec.CommandContext(ctx, "schtasks", "/Create", "/F", "/TN", skillsTaskName,
		"/SC", "HOURLY", "/MO", "4", "/TR", action).CombinedOutput()
	if err != nil {
		return fmt.Errorf("Task Scheduler refused the task: %s", strings.TrimSpace(string(out)))
	}
	infof("On. This computer reports its agent skills automatically, at most once a day.")
	infof("Covers Claude Code, Codex, Cursor and Gemini CLI. Turn off with: contro1 skills schedule --off")
	return nil
}

// --- macOS and Linux: crontab -----------------------------------------------

func scheduleCron(ctx context.Context) error {
	if _, err := exec.LookPath("crontab"); err != nil {
		return fmt.Errorf("crontab is not installed on this computer; run contro1 skills report from your own scheduler instead")
	}
	current, _ := exec.CommandContext(ctx, "crontab", "-l").Output()
	lines := strings.Split(strings.TrimRight(string(current), "\n"), "\n")
	var kept []string
	exists := false
	for _, line := range lines {
		if strings.Contains(line, skillsCronMarker) {
			exists = true
			continue
		}
		if line != "" {
			kept = append(kept, line)
		}
	}
	switch {
	case skillsScheduleStatus:
		if exists {
			infof("On: your crontab runs the skills report every 4 hours and it reports at most once a day.")
		} else {
			infof("Off. Turn it on with: contro1 skills schedule")
		}
		return nil
	case skillsScheduleOff:
		if !exists {
			infof("Already off.")
			return nil
		}
		if err := writeCrontab(ctx, kept); err != nil {
			return err
		}
		infof("Off. This computer no longer reports its skills automatically.")
		return nil
	}
	bin, err := contro1Binary()
	if err != nil {
		return err
	}
	kept = append(kept, fmt.Sprintf("23 */4 * * * %s skills report --every 20h --quiet >/dev/null 2>&1 %s", shellQuote(bin), skillsCronMarker))
	if err := writeCrontab(ctx, kept); err != nil {
		return err
	}
	infof("On. This computer reports its agent skills automatically, at most once a day.")
	infof("Covers Claude Code, Codex, Cursor and Gemini CLI. Turn off with: contro1 skills schedule --off")
	return nil
}

func writeCrontab(ctx context.Context, lines []string) error {
	body := strings.Join(lines, "\n")
	if body != "" {
		body += "\n"
	}
	c := exec.CommandContext(ctx, "crontab", "-")
	c.Stdin = strings.NewReader(body)
	if out, err := c.CombinedOutput(); err != nil {
		return fmt.Errorf("crontab refused the change: %s", strings.TrimSpace(string(out)))
	}
	return nil
}
