package installer

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

/*
ServiceComparison is the installed Contro1 service set against the CLI that is
running now.

WHY. The service is only replaced by the elevated install step, and connect
ran that step only when it had new agents to register. A computer connected
once kept the service it was connected with, while the CLI moved on: a fix in
the service (the mapping republished after a revoke, for one) never reached
it, and nothing said so. Connect now compares, and updates in the elevation it
asks for anyway; doctor says the same thing with the command.

The signal is the version the service itself publishes in status.json, which
every service version writes and any user can read. When the two versions are
the same, or one of them is not a release ("dev"), the installed binary's hash
against this executable decides: the same version string can be two builds,
and an equal hash is the only proof they are one. A service newer than the CLI
is never replaced by an older one.
*/
type ServiceComparison struct {
	// From is the version the installed service reports ("" when unknown).
	From string
	// To is this CLI's version.
	To string
	// Needed: the installed service runs an older or a different binary.
	Needed bool
	// Newer: the service is a newer release than this CLI. Nothing is
	// downgraded; the CLI is what needs updating.
	Newer bool
}

// CompareService decides whether the installed service should be replaced by
// this CLI's binary. binaryDiffers is asked only when the versions alone
// cannot decide; an error from it (a binary that cannot be read) is not taken
// as a difference, so a guess never asks for an administrator.
func CompareService(serviceVersion, cliVersion string, binaryDiffers func() (bool, error)) ServiceComparison {
	c := ServiceComparison{From: strings.TrimSpace(serviceVersion), To: strings.TrimSpace(cliVersion)}
	if order, ok := CompareVersions(c.From, c.To); ok && order != 0 {
		c.Needed, c.Newer = order < 0, order > 0
		return c
	}
	if binaryDiffers != nil {
		if differs, err := binaryDiffers(); err == nil && differs {
			c.Needed = true
		}
	}
	return c
}

// UpdateLine is the preview line for an update, in the person's words.
func (c ServiceComparison) UpdateLine() string {
	switch {
	case c.From == "":
		return fmt.Sprintf("Update the Contro1 service to %s (the installed copy is a different build)", c.To)
	case c.From == c.To:
		return fmt.Sprintf("Update the Contro1 service (from another %s build to this one)", c.From)
	}
	return fmt.Sprintf("Update the Contro1 service (from %s to %s)", c.From, c.To)
}

// CompareVersions orders two release versions such as 0.2.29 or v0.2.30-rc1.
// ok is false when either is not a release version (a "dev" build): those are
// told apart by their binaries instead.
func CompareVersions(a, b string) (order int, ok bool) {
	pa, okA := parseVersion(a)
	pb, okB := parseVersion(b)
	if !okA || !okB {
		return 0, false
	}
	for i := range pa {
		if pa[i] != pb[i] {
			if pa[i] < pb[i] {
				return -1, true
			}
			return 1, true
		}
	}
	return 0, true
}

func parseVersion(v string) ([3]int, bool) {
	var out [3]int
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

// BinaryDiffers reports whether the installed service binary is not a copy of
// source. Both are readable without elevation: the installed copy is
// read-and-execute for every user on each operating system.
func BinaryDiffers(source, installed string) (bool, error) {
	hs, err := fileHash(source)
	if err != nil {
		return false, err
	}
	hi, err := fileHash(installed)
	if err != nil {
		return false, err
	}
	return hs != hi, nil
}

func fileHash(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

/*
keepPrevious moves an installed binary aside before it is replaced, and
restorePrevious puts it back when a later step of the same install fails.

WHY. The binary step's undo deleted the binary, which was right for a first
install and wrong for an upgrade: connect now updates a running service, and
an update whose start step failed would have rolled back to no service at
all. The previous copy is dropped once the whole install has worked.
*/
func keepPrevious(dest string) error {
	if _, err := os.Stat(dest); err != nil {
		return nil
	}
	return os.Rename(dest, dest+".previous")
}

func restorePrevious(dest string) bool {
	if _, err := os.Stat(dest + ".previous"); err != nil {
		return false
	}
	return os.Rename(dest+".previous", dest) == nil
}

func dropPrevious(dest string) { _ = os.Remove(dest + ".previous") }

// UpdateCommand is the command a person runs to update the service by hand,
// for this operating system. Windows asks for approval itself; on unix the
// command needs root and names the executable, because sudo's PATH often does
// not include where contro1 was installed.
func UpdateCommand(goos, exe string) string {
	if goos == "windows" {
		return "contro1 broker install"
	}
	if strings.TrimSpace(exe) == "" {
		exe = "contro1"
	}
	if strings.ContainsAny(exe, " \t'\"") {
		exe = "'" + strings.ReplaceAll(exe, "'", `'\''`) + "'"
	}
	return "sudo " + exe + " broker install"
}
