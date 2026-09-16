//go:build linux

package localipc

import (
	"net"
	"os"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

func peerIdentity(c *net.UnixConn) (Identity, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return Identity{}, err
	}
	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return Identity{}, err
	}
	if credErr != nil {
		return Identity{}, credErr
	}
	return Identity{PID: int(cred.Pid), User: "uid:" + strconv.Itoa(int(cred.Uid)), Groups: []string{"gid:" + strconv.Itoa(int(cred.Gid))}}, nil
}

func ownedByCurrentUser(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Getuid()
}
