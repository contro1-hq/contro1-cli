//go:build !windows && !darwin && !linux

package privateconnector

import "errors"

func InstallService(SetupInput) error {
	return errors.New("private connector service installer supports Windows, macOS and Linux (systemd); elsewhere use Docker")
}
func ServiceRunning() (bool, error) { return false, nil }
func UninstallService() error {
	return errors.New("private connector service installer supports Windows, macOS and Linux (systemd); elsewhere use Docker")
}
