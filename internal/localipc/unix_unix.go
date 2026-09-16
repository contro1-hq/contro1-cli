//go:build unix

package localipc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Unix sockets live in a broker-owned 0711 directory (traversable, not
// listable). Each socket is 0660, group-owned by the caller's group, and every
// accepted connection's peer credentials are checked against the allowlist.
// Compile-checked on Windows; exercised on the user's Linux machine.

// CurrentIdentity is the identity of this process.
func CurrentIdentity() (Identity, error) {
	return Identity{PID: os.Getpid(), User: "uid:" + strconv.Itoa(os.Getuid()), Groups: []string{"gid:" + strconv.Itoa(os.Getgid())}}, nil
}

// InvokingIdentity is the person who ran the command. Under sudo that is the
// user sudo was called by, not root: an agent platform runs as that person, so
// recording uid:0 as the only identity allowed to reach its endpoint would lock
// the platform out.
func InvokingIdentity() (Identity, error) {
	if os.Geteuid() == 0 {
		uid, gid := os.Getenv("SUDO_UID"), os.Getenv("SUDO_GID")
		if _, err := strconv.Atoi(uid); err == nil && uid != "0" {
			id := Identity{PID: os.Getpid(), User: "uid:" + uid}
			if _, err := strconv.Atoi(gid); err == nil {
				id.Groups = []string{"gid:" + gid}
			}
			return id, nil
		}
	}
	return CurrentIdentity()
}

// PrimaryGroupOf returns the primary group of a "uid:N" principal, or -1.
func PrimaryGroupOf(principal string) int {
	uid, ok := strings.CutPrefix(principal, "uid:")
	if !ok {
		return -1
	}
	u, err := user.LookupId(uid)
	if err != nil {
		return -1
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return -1
	}
	return gid
}

type unixListener struct {
	*net.UnixListener
	spec ListenSpec
}

func Listen(spec ListenSpec) (net.Listener, error) {
	if spec.Endpoint.Kind != "unix" {
		return nil, fmt.Errorf("localipc: %s endpoints are not supported here", spec.Endpoint.Kind)
	}
	dir := filepath.Dir(spec.Endpoint.Path)
	if err := os.MkdirAll(dir, 0o711); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o711); err != nil {
		return nil, err
	}
	// A stale socket from a crashed broker is removed only if it is a socket
	// owned by us; anything else at that path is refused.
	if info, err := os.Lstat(spec.Endpoint.Path); err == nil {
		if info.Mode()&os.ModeSocket == 0 || !ownedByCurrentUser(info) {
			return nil, fmt.Errorf("localipc: %s exists and is not our socket", spec.Endpoint.Path)
		}
		_ = os.Remove(spec.Endpoint.Path)
	}
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: spec.Endpoint.Path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	l.SetUnlinkOnClose(true)
	if err := os.Chmod(spec.Endpoint.Path, 0o660); err != nil {
		l.Close()
		return nil, err
	}
	if spec.SocketGroup > 0 {
		if err := os.Chown(spec.Endpoint.Path, -1, spec.SocketGroup); err != nil {
			l.Close()
			return nil, err
		}
	}
	return &unixListener{UnixListener: l, spec: spec}, nil
}

func (l *unixListener) Accept() (net.Conn, error) {
	for {
		c, err := l.UnixListener.AcceptUnix()
		if err != nil {
			return nil, err
		}
		id, err := peerIdentity(c)
		if err != nil || !id.Allowed(l.spec.AllowedPrincipals) {
			c.Close()
			continue
		}
		return &unixConn{UnixConn: c, peer: id}, nil
	}
}

type unixConn struct {
	*net.UnixConn
	peer Identity
}

func PeerOf(conn net.Conn) (Identity, bool) {
	if uc, ok := conn.(*unixConn); ok {
		return uc.peer, true
	}
	return Identity{}, false
}

func Dial(ctx context.Context, ep Endpoint, expectServer Principal) (net.Conn, error) {
	if ep.Kind != "unix" {
		return nil, fmt.Errorf("localipc: %s endpoints are not supported here", ep.Kind)
	}
	d := net.Dialer{Timeout: 5 * time.Second}
	c, err := d.DialContext(ctx, "unix", ep.Path)
	if err != nil {
		return nil, fmt.Errorf("localipc: dial %s: %w", ep.Path, err)
	}
	if expectServer != "" {
		uc, ok := c.(*net.UnixConn)
		if !ok {
			c.Close()
			return nil, errors.New("localipc: not a unix connection")
		}
		id, err := peerIdentity(uc)
		if err != nil || !id.Allowed([]Principal{expectServer}) {
			c.Close()
			return nil, fmt.Errorf("%w: server is not the Contro1 service", ErrPeerRejected)
		}
	}
	return c, nil
}
