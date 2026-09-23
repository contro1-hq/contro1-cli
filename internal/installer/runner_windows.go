//go:build windows

package installer

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/contro1-hq/contro1-cli/internal/brokerpaths"
)

// IsElevated reports whether this process holds an elevated token.
func IsElevated() bool { return windows.GetCurrentProcessToken().IsElevated() }

// SystemRunner applies a Windows plan with the Service Control Manager.
type SystemRunner struct{}

func (SystemRunner) Steps(plan InstallPlan) ([]Step, error) {
	if !IsElevated() {
		return nil, ErrNeedsElevation
	}
	var steps []Step
	for _, d := range plan.Dirs {
		d := d
		steps = append(steps, Step{
			ID:      "dir:" + d.Path,
			Existed: func() (bool, error) { _, err := os.Stat(d.Path); return err == nil, nil },
			Do: func() error {
				if err := os.MkdirAll(d.Path, 0o700); err != nil {
					return err
				}
				return applySDDL(d.Path, d.SDDL)
			},
			Undo: func() error { return os.RemoveAll(d.Path) },
		})
		// Tighten an existing directory too: a repair never loosens an ACL,
		// and this descriptor is the strictest the service can run with.
		steps = append(steps, Step{ID: "acl:" + d.Path, Do: func() error { return applySDDL(d.Path, d.SDDL) }})
	}
	steps = append(steps, Step{
		ID: "binary",
		Existed: func() (bool, error) {
			return sameFile(plan.Binary.Source, plan.Binary.Dest), nil
		},
		Do: func() error {
			if err := os.MkdirAll(filepath.Dir(plan.Binary.Dest), 0o755); err != nil {
				return err
			}
			return copyFile(plan.Binary.Source, plan.Binary.Dest)
		},
		Undo: func() error { return os.Remove(plan.Binary.Dest) },
	})
	steps = append(steps, Step{
		ID: "service",
		Existed: func() (bool, error) {
			m, err := mgr.Connect()
			if err != nil {
				return false, err
			}
			defer m.Disconnect()
			s, err := m.OpenService(brokerpaths.ServiceName)
			if err != nil {
				return false, nil
			}
			s.Close()
			return true, nil
		},
		Do: func() error {
			m, err := mgr.Connect()
			if err != nil {
				return err
			}
			defer m.Disconnect()
			s, err := m.CreateService(brokerpaths.ServiceName, plan.Binary.Dest, mgr.Config{
				DisplayName:      plan.Service.DisplayName,
				Description:      "Holds Contro1 agent connections on this computer and serves each agent a private local endpoint.",
				StartType:        mgr.StartAutomatic,
				DelayedAutoStart: true,
				ServiceStartName: plan.Service.Account,
				SidType:          windows.SERVICE_SID_TYPE_UNRESTRICTED,
			}, plan.Service.Args...)
			if err != nil {
				return err
			}
			defer s.Close()
			return s.SetRecoveryActions([]mgr.RecoveryAction{
				{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
				{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
				{Type: mgr.ServiceRestart, Delay: 60 * time.Second},
			}, 86400)
		},
		Undo: func() error { return removeService() },
	})
	steps = append(steps, Step{
		ID: "start",
		Existed: func() (bool, error) {
			st, err := serviceState()
			return err == nil && st == svc.Running, nil
		},
		Do: func() error {
			m, err := mgr.Connect()
			if err != nil {
				return err
			}
			defer m.Disconnect()
			s, err := m.OpenService(brokerpaths.ServiceName)
			if err != nil {
				return err
			}
			defer s.Close()
			return s.Start()
		},
	})
	return steps, nil
}

// ErrNeedsElevation: run the phase again elevated (RunElevated).
var ErrNeedsElevation = errors.New("installer: administrator rights are required")

func serviceState() (svc.State, error) {
	m, err := mgr.Connect()
	if err != nil {
		return 0, err
	}
	defer m.Disconnect()
	s, err := m.OpenService(brokerpaths.ServiceName)
	if err != nil {
		return 0, err
	}
	defer s.Close()
	st, err := s.Query()
	return st.State, err
}

func removeService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(brokerpaths.ServiceName)
	if err != nil {
		return nil
	}
	defer s.Close()
	_, _ = s.Control(svc.Stop)
	return s.Delete()
}

// ServiceStatus is used by doctor: installed, running, automatic start.
func ServiceStatus() (installed, running, automatic bool, account string) {
	/*
	 * QUERY RIGHTS ONLY. mgr.Connect asks for SC_MANAGER_ALL_ACCESS, which a
	 * person running `contro1 doctor` unelevated does not have, so the call
	 * failed and doctor reported a running service as "not installed" - and
	 * told the reader to run connect again. Reading status needs connect and
	 * query rights, which every user has.
	 */
	h, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return
	}
	m := &mgr.Mgr{Handle: h}
	defer m.Disconnect()
	name, err := windows.UTF16PtrFromString(brokerpaths.ServiceName)
	if err != nil {
		return
	}
	sh, err := windows.OpenService(h, name, windows.SERVICE_QUERY_STATUS|windows.SERVICE_QUERY_CONFIG)
	if err != nil {
		return
	}
	s := &mgr.Service{Name: brokerpaths.ServiceName, Handle: sh}
	defer s.Close()
	installed = true
	if st, err := s.Query(); err == nil {
		running = st.State == svc.Running
	}
	if cfg, err := s.Config(); err == nil {
		automatic = cfg.StartType == mgr.StartAutomatic
		account = cfg.ServiceStartName
	}
	return
}

func applySDDL(path, sddl string) error {
	if sddl == "" {
		return nil
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

func sameFile(a, b string) bool {
	ha, errA := fileHash(a)
	hb, errB := fileHash(b)
	return errA == nil && errB == nil && ha == hb
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

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".new"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

// ---------------------------------------------------------------------------
// Elevation: one UAC prompt for the privileged phase.
// ---------------------------------------------------------------------------

var (
	modShell32         = windows.NewLazySystemDLL("shell32.dll")
	procShellExecuteEx = modShell32.NewProc("ShellExecuteExW")
)

type shellExecuteInfo struct {
	cbSize       uint32
	fMask        uint32
	hwnd         windows.Handle
	lpVerb       *uint16
	lpFile       *uint16
	lpParameters *uint16
	lpDirectory  *uint16
	nShow        int32
	hInstApp     windows.Handle
	lpIDList     uintptr
	lpClass      *uint16
	hkeyClass    windows.Handle
	dwHotKey     uint32
	hIcon        windows.Handle
	hProcess     windows.Handle
}

const (
	seeMaskNoCloseProcess = 0x00000040
	errorCancelled        = 1223
)

// RunElevated starts this executable with args through the UAC prompt, waits,
// and returns its exit code. A dismissed prompt is ErrElevationDeclined.
func RunElevated(args []string) (int, error) {
	exe, err := os.Executable()
	if err != nil {
		return -1, err
	}
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = windows.EscapeArg(a)
	}
	info := shellExecuteInfo{
		fMask:        seeMaskNoCloseProcess,
		lpVerb:       windows.StringToUTF16Ptr("runas"),
		lpFile:       windows.StringToUTF16Ptr(exe),
		lpParameters: windows.StringToUTF16Ptr(strings.Join(quoted, " ")),
		nShow:        windows.SW_HIDE,
	}
	info.cbSize = uint32(unsafe.Sizeof(info))
	if err := procShellExecuteEx.Find(); err != nil {
		return -1, err
	}
	r, _, callErr := procShellExecuteEx.Call(uintptr(unsafe.Pointer(&info)))
	if r == 0 {
		if errno, ok := callErr.(windows.Errno); ok && errno == errorCancelled {
			return -1, ErrElevationDeclined
		}
		return -1, fmt.Errorf("installer: elevation failed: %w", callErr)
	}
	defer windows.CloseHandle(info.hProcess)
	if _, err := windows.WaitForSingleObject(info.hProcess, windows.INFINITE); err != nil {
		return -1, err
	}
	var code uint32
	if err := windows.GetExitCodeProcess(info.hProcess, &code); err != nil {
		return -1, err
	}
	return int(code), nil
}

// SudoHint is empty on Windows; elevation uses UAC.
func SudoHint(string) string { return "" }
