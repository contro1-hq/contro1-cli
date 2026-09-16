//go:build darwin

package localipc

import (
	"net"
	"os"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// UNVERIFIED on macOS: written against LOCAL_PEERCRED, compile-checked only.
func peerIdentity(c *net.UnixConn) (Identity, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return Identity{}, err
	}
	var cred *unix.Xucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return Identity{}, err
	}
	if credErr != nil {
		return Identity{}, credErr
	}
	id := Identity{User: "uid:" + strconv.Itoa(int(cred.Uid))}
	for i := 0; i < int(cred.Ngroups) && i < len(cred.Groups); i++ {
		id.Groups = append(id.Groups, "gid:"+strconv.Itoa(int(cred.Groups[i])))
	}
	return id, nil
}

func ownedByCurrentUser(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Getuid()
}
