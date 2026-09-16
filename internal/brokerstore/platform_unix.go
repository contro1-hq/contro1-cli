//go:build unix

package brokerstore

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

type fileLock struct{ f *os.File }

func acquireLock(path string) (*fileLock, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("brokerstore: lock: %w", err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("brokerstore: lock: %w", err)
	}
	return &fileLock{f: f}, nil
}

func (l *fileLock) release() error {
	_ = unix.Flock(int(l.f.Fd()), unix.LOCK_UN)
	return l.f.Close()
}

func renameWithRetry(from, to string) error { return os.Rename(from, to) }

func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
}

func platformSealers() (func([]byte) ([]byte, error), func([]byte) ([]byte, error)) {
	return nil, nil
}
