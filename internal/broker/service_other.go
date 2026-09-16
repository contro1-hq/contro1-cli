//go:build !windows

package broker

import "context"

// RunUnderServiceManager: systemd and launchd run the broker as an ordinary
// foreground process and stop it with SIGTERM, handled by the caller.
func RunUnderServiceManager(string, func(ctx context.Context) error) (bool, error) {
	return false, nil
}
