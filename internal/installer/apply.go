package installer

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ErrElevationDeclined means the person dismissed the operating system prompt.
// Callers turn it into the `needs_local_confirmation` next step.
var ErrElevationDeclined = errors.New("installer: elevation was declined")

// Step is one reversible change. Existed reports whether the target was
// already there, in which case Undo is never called for it: rollback never
// touches what a previous, working install created.
type Step struct {
	ID      string
	Existed func() (bool, error)
	Do      func() error
	Undo    func() error
}

// Runner turns a plan into steps for the current operating system.
type Runner interface {
	Steps(plan InstallPlan) ([]Step, error)
}

type JournalEntry struct {
	ID      string `json:"id"`
	Created bool   `json:"created"`
	At      string `json:"at"`
}

type Journal struct {
	Path    string         `json:"-"`
	Entries []JournalEntry `json:"entries"`
}

func (j *Journal) save() error {
	if j.Path == "" {
		return nil
	}
	raw, _ := json.MarshalIndent(j, "", "  ")
	if err := os.MkdirAll(filepath.Dir(j.Path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(j.Path, raw, 0o600)
}

// Result reports what Apply did.
type Result struct {
	Applied    []string `json:"applied"`
	Skipped    []string `json:"skipped"`
	RolledBack []string `json:"rolled_back,omitempty"`
	Failed     string   `json:"failed,omitempty"`
	Error      string   `json:"error,omitempty"`
}

// Apply runs every step in order. On failure it undoes, in reverse, only the
// steps this run created, and returns the original error.
func Apply(plan InstallPlan, runner Runner, journalPath string) (Result, error) {
	steps, err := runner.Steps(plan)
	if err != nil {
		return Result{Error: err.Error()}, err
	}
	journal := &Journal{Path: journalPath}
	var res Result
	var created []Step
	for _, step := range steps {
		existed := false
		if step.Existed != nil {
			if existed, err = step.Existed(); err != nil {
				return rollback(res, created, step.ID, err, journal)
			}
		}
		if existed {
			res.Skipped = append(res.Skipped, step.ID)
			journal.Entries = append(journal.Entries, JournalEntry{ID: step.ID, Created: false, At: now()})
			_ = journal.save()
			continue
		}
		if err := step.Do(); err != nil {
			return rollback(res, created, step.ID, err, journal)
		}
		created = append(created, step)
		res.Applied = append(res.Applied, step.ID)
		journal.Entries = append(journal.Entries, JournalEntry{ID: step.ID, Created: true, At: now()})
		_ = journal.save()
	}
	return res, nil
}

func rollback(res Result, created []Step, failed string, cause error, journal *Journal) (Result, error) {
	res.Failed = failed
	res.Error = cause.Error()
	for i := len(created) - 1; i >= 0; i-- {
		if created[i].Undo == nil {
			continue
		}
		if err := created[i].Undo(); err == nil {
			res.RolledBack = append(res.RolledBack, created[i].ID)
		}
	}
	_ = journal.save()
	return res, fmt.Errorf("installer: step %s failed: %w", failed, cause)
}

func now() string { return time.Now().UTC().Format(time.RFC3339) }
