//go:build windows

package privateconnector

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/contro1-hq/contro1-cli/internal/brokerpaths"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func serviceDirectoryACL(path string) error {
	sid := brokerpaths.WindowsServiceSID(WindowsServiceName)
	sddl := fmt.Sprintf("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;%s)", sid)
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

func InstallService(input SetupInput) error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("administrator rights are required")
	}
	if err := input.Validate(); err != nil {
		return err
	}
	layout := ProductionLayout()
	if err := CheckCapacity(layout.StateDir, input.InstallationID); err != nil {
		return err
	}
	for _, dir := range []string{layout.StateDir, layout.LogDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		if err := serviceDirectoryACL(dir); err != nil {
			return err
		}
	}
	installationDir := InstallationDir(layout.StateDir, input.InstallationID)
	if err := os.MkdirAll(installationDir, 0o700); err != nil {
		return err
	}
	if err := serviceDirectoryACL(installationDir); err != nil {
		return err
	}
	if err := Provision(installationDir, input); err != nil {
		return err
	}
	for _, name := range []string{"config.json", "enrollment-code", "provider-secret"} {
		path := filepath.Join(installationDir, name)
		if _, err := os.Stat(path); err == nil {
			if err := serviceDirectoryACL(path); err != nil {
				return err
			}
		}
	}
	if err := os.MkdirAll(filepath.Dir(layout.BinaryPath), 0o755); err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(WindowsServiceName)
	if err == nil {
		st, err := s.Query()
		if err != nil {
			s.Close()
			return err
		}
		if st.State != svc.Stopped {
			if _, err := s.Control(svc.Stop); err != nil {
				s.Close()
				return err
			}
			for i := 0; i < 30; i++ {
				time.Sleep(time.Second)
				st, err = s.Query()
				if err != nil {
					s.Close()
					return err
				}
				if st.State == svc.Stopped {
					break
				}
			}
			if st.State != svc.Stopped {
				s.Close()
				return errors.New("private connector service did not stop")
			}
		}
		s.Close()
	}
	if err := copyExecutable(layout.BinaryPath); err != nil {
		return err
	}
	s, err = m.OpenService(WindowsServiceName)
	if err != nil {
		s, err = m.CreateService(WindowsServiceName, layout.BinaryPath, mgr.Config{
			DisplayName: "Contro1 Private Connector", Description: "Outbound connector for an on-premises application",
			StartType: mgr.StartAutomatic, DelayedAutoStart: true,
			ServiceStartName: `NT SERVICE\` + WindowsServiceName,
			SidType:          windows.SERVICE_SID_TYPE_UNRESTRICTED,
		}, "private-connector", "serve")
		if err != nil {
			return err
		}
		if err := s.SetRecoveryActions([]mgr.RecoveryAction{
			{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
			{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
			{Type: mgr.ServiceRestart, Delay: 60 * time.Second},
		}, 86400); err != nil {
			s.Close()
			return err
		}
	}
	defer s.Close()
	return s.Start()
}

func copyExecutable(dest string) error {
	source, err := os.Executable()
	if err != nil {
		return err
	}
	if source == dest {
		return nil
	}
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dest + ".new"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	old := dest + ".old"
	_ = os.Remove(old)
	if _, err := os.Stat(dest); err == nil {
		if err := os.Rename(dest, old); err != nil {
			os.Remove(tmp)
			return err
		}
	}
	if err := os.Rename(tmp, dest); err != nil {
		_ = os.Rename(old, dest)
		return err
	}
	_ = os.Remove(old)
	return nil
}

func ServiceRunning() (bool, error) {
	m, err := mgr.Connect()
	if err != nil {
		return false, err
	}
	defer m.Disconnect()
	s, err := m.OpenService(WindowsServiceName)
	if err != nil {
		return false, err
	}
	defer s.Close()
	st, err := s.Query()
	return err == nil && st.State == svc.Running, err
}

// UninstallService removes the auto-start service and binary. Local identity,
// configuration and logs remain so a same-installation reinstall can recover.
func UninstallService() error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("administrator rights are required")
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(WindowsServiceName)
	if err != nil {
		return err
	}
	defer s.Close()
	st, err := s.Query()
	if err != nil {
		return err
	}
	if st.State != svc.Stopped {
		if _, err := s.Control(svc.Stop); err != nil {
			return err
		}
		for i := 0; i < 30; i++ {
			time.Sleep(time.Second)
			st, err = s.Query()
			if err != nil {
				return err
			}
			if st.State == svc.Stopped {
				break
			}
		}
		if st.State != svc.Stopped {
			return errors.New("private connector service did not stop")
		}
	}
	if err := s.Delete(); err != nil {
		return err
	}
	if err := os.Remove(ProductionLayout().BinaryPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
