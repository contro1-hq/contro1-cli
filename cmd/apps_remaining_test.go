package cmd

import (
	"errors"
	"strings"
	"testing"

	"github.com/contro1-hq/contro1-cli/internal/doctor"
	"github.com/contro1-hq/contro1-cli/internal/platforms"
)

// A host where the channel is loaded and Contro1 is the approver no longer ends
// with "not working end to end yet". It does not end with a plain "Done."
// either: whether cards from WhatsApp prefer Contro1 is in NanoClaw's own code,
// which nothing here can see, so that step is named to confirm.
func TestNanoRemainingSetupOnlyWhatIsNotDone(t *testing.T) {
	a, err := platforms.New("nanoclaw", platforms.Options{})
	if err != nil {
		t.Fatal(err)
	}
	steps := a.RemainingSetup()
	try := "Try it."

	remaining, unchecked := nanoRemainingSetup(steps, doctor.ApproverStatus{ChannelPresent: true, ApproverExists: true, ApproverMayResolve: true}, nil)
	if len(remaining) != 0 || len(unchecked) != 1 || unchecked[0] != platforms.NanoPreferContro1Step {
		t.Fatalf("finished setup: remaining %v unchecked %v", remaining, unchecked)
	}
	closing := withUnchecked(appsEnableClosing("nanoclaw", remaining, nil, nil, try), unchecked, remaining, nil, try)
	text := strings.Join(closing, "\n")
	if strings.HasPrefix(closing[0], "Done.") || !strings.Contains(text, platforms.NanoPreferContro1Step) || !strings.Contains(text, try) {
		t.Fatalf("an unchecked step is named instead of Done: %q", text)
	}
	if strings.Contains(text, "not working end to end yet") {
		t.Fatalf("a finished setup is not called broken: %q", text)
	}

	remaining, unchecked = nanoRemainingSetup(steps, doctor.ApproverStatus{ChannelPresent: true, ApproverExists: true}, nil)
	if len(remaining) != 2 || !strings.Contains(remaining[0], "--confirm-roles") || len(unchecked) != 1 {
		t.Fatalf("channel loaded, approver missing: %v %v", remaining, unchecked)
	}
	text = strings.Join(withUnchecked(appsEnableClosing("nanoclaw", remaining, nil, nil, try), unchecked, remaining, nil, try), "\n")
	if !strings.Contains(text, "If not done yet: "+platforms.NanoPreferContro1Step) || !strings.HasSuffix(text, "contro1 doctor nanoclaw") {
		t.Fatalf("with steps left, the unchecked one joins them before the check: %q", text)
	}

	if remaining, unchecked := nanoRemainingSetup(steps, doctor.ApproverStatus{}, nil); len(remaining) != len(steps) || len(unchecked) != 0 {
		t.Fatalf("nothing installed lists every step once: %v %v", remaining, unchecked)
	}
	remaining, _ = nanoRemainingSetup(steps, doctor.ApproverStatus{}, errors.New("ncl not found"))
	if len(remaining) != len(steps) || !strings.HasPrefix(remaining[0], "If not done yet: ") {
		t.Fatalf("unknown state is said as conditional: %v", remaining)
	}

	// Other platforms have nothing unchecked: the closing is unchanged.
	plain := appsEnableClosing("claude-code", nil, nil, nil, try)
	if got := withUnchecked(plain, nil, nil, nil, try); len(got) != 1 || got[0] != "Done. "+try {
		t.Fatalf("no unchecked steps, no change: %v", got)
	}
}
