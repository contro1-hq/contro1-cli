package brokerpaths

import "testing"

// The well-known SID of NT SERVICE\TrustedInstaller is documented by Microsoft,
// which pins the derivation algorithm.
func TestWindowsServiceSID(t *testing.T) {
	const trustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
	if got := WindowsServiceSID("TrustedInstaller"); got != trustedInstaller {
		t.Fatalf("got %s, want %s", got, trustedInstaller)
	}
	if WindowsServiceSID("contro1broker") != WindowsServiceSID(ServiceName) {
		t.Fatal("service SIDs are case-insensitive")
	}
}

func TestLayouts(t *testing.T) {
	for _, goos := range []string{"windows", "linux", "darwin"} {
		l := Production(goos)
		if l.StateDir == "" || l.ControlEndpoint == "" {
			t.Fatalf("%s layout incomplete: %+v", goos, l)
		}
	}
	if !Development().Foreground {
		t.Fatal("development layout is foreground")
	}
}
