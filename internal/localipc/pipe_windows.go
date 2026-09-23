//go:build windows

package localipc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	fileFlagFirstPipeInstance = 0x00080000
	pipeRejectRemoteClients   = 0x00000008
	pipeBufferSize            = 64 * 1024
	securitySqosPresent       = 0x00100000
	securityIdentification    = 0x00010000
)

// identityOfPipePeer is swappable so tests can drive the rejection path
// without a second Windows account.
//
// IT NEVER OPENS THE PEER'S PROCESS. It used to, with OpenProcess and
// OpenProcessToken, and that only works when the caller is allowed into the
// other process. The service runs as `NT SERVICE\Contro1Broker`, which may not
// open a person's processes, and a person may not open the service's. So
// every connection in both directions failed identification and was dropped
// without a word: `contro1 connect` read "no process is on the other end of
// the pipe", and the tests passed because they replace this function.
//
// What the pipe itself vouches for is used instead:
//
//	server side  the client's token, by impersonating it at identification
//	             level, which the client grants when it dials (see Dial) and
//	             which can be queried but never used to act.
//	client side  the pipe's owner, which Windows takes from the token of the
//	             process that created it. Setting another identity as owner
//	             needs a privilege an impostor does not have, and
//	             FILE_FLAG_FIRST_PIPE_INSTANCE keeps anyone from joining an
//	             existing pipe of that name.
var identityOfPipePeer = func(h windows.Handle, server bool) (Identity, error) {
	if server {
		return identityOfPipeOwner(h)
	}
	return identityOfPipeClient(h)
}

var procImpersonateNamedPipeClient = windows.NewLazySystemDLL("advapi32.dll").NewProc("ImpersonateNamedPipeClient")

// identityOfPipeClient reads the client's token by impersonating it.
//
// On its own OS thread, because impersonation belongs to a thread and Go moves
// goroutines between threads. If reverting fails, the thread is never unlocked,
// so the runtime discards it when the goroutine ends instead of reusing a
// thread that still wears somebody else's identity.
func identityOfPipeClient(h windows.Handle) (Identity, error) {
	var pid uint32
	_ = windows.GetNamedPipeClientProcessId(h, &pid)
	type result struct {
		id  Identity
		err error
	}
	done := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		if r, _, err := procImpersonateNamedPipeClient.Call(uintptr(h)); r == 0 {
			runtime.UnlockOSThread()
			done <- result{err: fmt.Errorf("localipc: impersonate pipe client: %w", err)}
			return
		}
		var token windows.Token
		openErr := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &token)
		var id Identity
		if openErr == nil {
			id, openErr = identityOfToken(token, int(pid))
			token.Close()
		}
		if err := windows.RevertToSelf(); err != nil {
			done <- result{err: fmt.Errorf("localipc: revert impersonation: %w", err)}
			return
		}
		runtime.UnlockOSThread()
		done <- result{id: id, err: openErr}
	}()
	r := <-done
	return r.id, r.err
}

// identityOfPipeOwner is the identity that created the pipe.
func identityOfPipeOwner(h windows.Handle) (Identity, error) {
	sd, err := windows.GetSecurityInfo(h, windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return Identity{}, fmt.Errorf("localipc: pipe owner: %w", err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return Identity{}, fmt.Errorf("localipc: pipe owner: %w", err)
	}
	var pid uint32
	_ = windows.GetNamedPipeServerProcessId(h, &pid)
	return Identity{PID: int(pid), User: owner.String()}, nil
}

// firstReadTimeout bounds how long an accepted connection may stay silent.
// Impersonation is refused until something has been read from the pipe, so
// the first bytes are read before the peer is identified.
var firstReadTimeout = 5 * time.Second

// notFoundGrace is how long Dial keeps trying a name with no listening
// instance before reporting the service as not running.
var notFoundGrace = 500 * time.Millisecond

// readFirst reads whatever the client sent first. The bytes are handed back to
// the connection, so the reader sees the request unchanged.
func readFirst(h windows.Handle) ([]byte, error) {
	evt, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(evt)
	buf := make([]byte, 4096)
	ov := windows.Overlapped{HEvent: evt}
	var n uint32
	err = windows.ReadFile(h, buf, &n, &ov)
	if err != nil && !errors.Is(err, windows.ERROR_IO_PENDING) && !errors.Is(err, windows.ERROR_MORE_DATA) {
		return nil, err
	}
	if errors.Is(err, windows.ERROR_IO_PENDING) {
		ev, waitErr := windows.WaitForSingleObject(evt, uint32(firstReadTimeout/time.Millisecond))
		if waitErr != nil || ev != windows.WAIT_OBJECT_0 {
			_ = windows.CancelIoEx(h, &ov)
			_ = windows.GetOverlappedResult(h, &ov, &n, true)
			return nil, errors.New("localipc: client sent nothing")
		}
		if err := windows.GetOverlappedResult(h, &ov, &n, false); err != nil && !errors.Is(err, windows.ERROR_MORE_DATA) {
			return nil, err
		}
	}
	if n == 0 {
		return nil, errors.New("localipc: client sent nothing")
	}
	return buf[:n], nil
}

func identityOfProcess(pid uint32) (Identity, error) {
	proc, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return Identity{}, fmt.Errorf("localipc: open peer process: %w", err)
	}
	defer windows.CloseHandle(proc)
	var token windows.Token
	if err := windows.OpenProcessToken(proc, windows.TOKEN_QUERY, &token); err != nil {
		return Identity{}, fmt.Errorf("localipc: open peer token: %w", err)
	}
	defer token.Close()
	return identityOfToken(token, int(pid))
}

func identityOfToken(token windows.Token, pid int) (Identity, error) {
	user, err := token.GetTokenUser()
	if err != nil {
		return Identity{}, err
	}
	id := Identity{PID: pid, User: user.User.Sid.String()}
	groups, err := token.GetTokenGroups()
	if err == nil {
		for _, g := range groups.AllGroups() {
			if g.Attributes&windows.SE_GROUP_ENABLED != 0 && g.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY == 0 {
				id.Groups = append(id.Groups, g.Sid.String())
			}
		}
	}
	return id, nil
}

// CurrentIdentity is the identity of this process.
func CurrentIdentity() (Identity, error) {
	return identityOfToken(windows.GetCurrentProcessToken(), os.Getpid())
}

// InvokingIdentity is the person who ran the command. Elevation on Windows
// happens in a separate process, so this is the current identity.
func InvokingIdentity() (Identity, error) { return CurrentIdentity() }

// PrimaryGroupOf has no meaning for pipes, whose access is a per-SID DACL.
func PrimaryGroupOf(string) int { return -1 }

type pipeListener struct {
	ep       Endpoint
	spec     ListenSpec
	sa       *windows.SecurityAttributes
	mu       sync.Mutex
	next     windows.Handle
	closed   bool
	closeEvt windows.Handle
}

// Listen creates the first pipe instance. If the name already exists, which
// is what a squatting process would have done, Listen fails rather than
// joining someone else's pipe.
func Listen(spec ListenSpec) (net.Listener, error) {
	if spec.Endpoint.Kind != "npipe" {
		return nil, fmt.Errorf("localipc: %s endpoints are not supported on Windows", spec.Endpoint.Kind)
	}
	if spec.SDDL == "" {
		return nil, errors.New("localipc: a pipe needs an explicit security descriptor")
	}
	sd, err := windows.SecurityDescriptorFromString(spec.SDDL)
	if err != nil {
		return nil, fmt.Errorf("localipc: SDDL: %w", err)
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	evt, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, err
	}
	l := &pipeListener{ep: spec.Endpoint, spec: spec, sa: sa, closeEvt: evt}
	h, err := l.create(true)
	if err != nil {
		windows.CloseHandle(evt)
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.ERROR_PIPE_BUSY) {
			return nil, fmt.Errorf("localipc: %s already exists; another process may be squatting on it: %w", spec.Endpoint.Path, err)
		}
		return nil, err
	}
	l.next = h
	return l, nil
}

func (l *pipeListener) create(first bool) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(l.ep.Path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	flags := uint32(windows.PIPE_ACCESS_DUPLEX | windows.FILE_FLAG_OVERLAPPED)
	if first {
		flags |= fileFlagFirstPipeInstance
	}
	mode := uint32(windows.PIPE_TYPE_BYTE | windows.PIPE_READMODE_BYTE | windows.PIPE_WAIT | pipeRejectRemoteClients)
	return windows.CreateNamedPipe(name, flags, mode, windows.PIPE_UNLIMITED_INSTANCES, pipeBufferSize, pipeBufferSize, 0, l.sa)
}

func (l *pipeListener) Accept() (net.Conn, error) {
	for {
		l.mu.Lock()
		if l.closed {
			l.mu.Unlock()
			return nil, net.ErrClosed
		}
		h := l.next
		l.next = 0
		l.mu.Unlock()
		if h == 0 {
			var err error
			if h, err = l.create(false); err != nil {
				return nil, err
			}
		}
		if err := l.waitConnect(h); err != nil {
			windows.CloseHandle(h)
			if errors.Is(err, net.ErrClosed) {
				return nil, err
			}
			continue
		}
		// The next instance exists BEFORE this client is read from. Reading
		// waits for the client to write, and while it did, the name had no
		// listening instance: the next caller got "not running" and gave up
		// instead of queueing.
		l.mu.Lock()
		if !l.closed && l.next == 0 {
			if next, err := l.create(false); err == nil {
				l.next = next
			}
		}
		l.mu.Unlock()
		first, err := readFirst(h)
		if err != nil {
			windows.DisconnectNamedPipe(h)
			windows.CloseHandle(h)
			continue
		}
		id, err := identityOfPipePeer(h, false)
		if err != nil || !id.Allowed(l.spec.AllowedPrincipals) {
			windows.DisconnectNamedPipe(h)
			windows.CloseHandle(h)
			continue
		}
		f := os.NewFile(uintptr(h), l.ep.Path)
		if f == nil {
			windows.CloseHandle(h)
			continue
		}
		return &pipeConn{File: f, ep: l.ep, peer: id, pending: first}, nil
	}
}

func (l *pipeListener) waitConnect(h windows.Handle) error {
	evt, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(evt)
	ov := windows.Overlapped{HEvent: evt}
	err = windows.ConnectNamedPipe(h, &ov)
	if err == nil || errors.Is(err, windows.ERROR_PIPE_CONNECTED) {
		return nil
	}
	if !errors.Is(err, windows.ERROR_IO_PENDING) {
		return err
	}
	r, err := windows.WaitForMultipleObjects([]windows.Handle{evt, l.closeEvt}, false, windows.INFINITE)
	if err != nil {
		return err
	}
	var n uint32
	if r == windows.WAIT_OBJECT_0 {
		return windows.GetOverlappedResult(h, &ov, &n, false)
	}
	_ = windows.CancelIoEx(h, &ov)
	_ = windows.GetOverlappedResult(h, &ov, &n, true)
	return net.ErrClosed
}

func (l *pipeListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	windows.SetEvent(l.closeEvt)
	if l.next != 0 {
		windows.CloseHandle(l.next)
		l.next = 0
	}
	return nil
}

func (l *pipeListener) Addr() net.Addr { return pipeAddr(l.ep.Path) }

type pipeAddr string

func (a pipeAddr) Network() string { return "npipe" }
func (a pipeAddr) String() string  { return string(a) }

type pipeConn struct {
	*os.File
	ep   Endpoint
	peer Identity
	// pending is what was read before the peer could be identified. It is
	// returned first, so the reader sees the stream exactly as sent.
	pending []byte
}

func (c *pipeConn) Read(p []byte) (int, error) {
	if len(c.pending) > 0 {
		n := copy(p, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	return c.File.Read(p)
}

func (c *pipeConn) LocalAddr() net.Addr  { return pipeAddr(c.ep.Path) }
func (c *pipeConn) RemoteAddr() net.Addr { return pipeAddr(c.ep.Path) }

// Peer returns the verified identity of the other side.
func (c *pipeConn) Peer() Identity { return c.peer }

// PeerOf returns the verified identity of a connection accepted by Listen.
func PeerOf(conn net.Conn) (Identity, bool) {
	if pc, ok := conn.(*pipeConn); ok {
		return pc.peer, true
	}
	return Identity{}, false
}

// Dial connects to a pipe. When expectServer is set, the server process must
// run as that identity; a squatter running as anybody else is refused before a
// single byte is written. The client allows identification-level impersonation
// only.
func Dial(ctx context.Context, ep Endpoint, expectServer Principal) (net.Conn, error) {
	if ep.Kind != "npipe" {
		return nil, fmt.Errorf("localipc: %s endpoints are not supported on Windows", ep.Kind)
	}
	name, err := windows.UTF16PtrFromString(ep.Path)
	if err != nil {
		return nil, err
	}
	var notFoundSince time.Time
	for {
		h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING,
			windows.FILE_FLAG_OVERLAPPED|securitySqosPresent|securityIdentification, 0)
		if err == nil {
			if expectServer != "" {
				id, idErr := identityOfPipePeer(h, true)
				if idErr != nil || !id.Allowed([]Principal{expectServer}) {
					windows.CloseHandle(h)
					return nil, fmt.Errorf("%w: server is not the Contro1 service", ErrPeerRejected)
				}
			}
			f := os.NewFile(uintptr(h), ep.Path)
			return &pipeConn{File: f, ep: ep}, nil
		}
		if !errors.Is(err, windows.ERROR_PIPE_BUSY) {
			if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
				// Between one instance being taken and the next being created
				// the name briefly has no listener. Several calls at once can
				// land there, so it is retried for a moment before it is read
				// as "not running".
				if notFoundSince.IsZero() {
					notFoundSince = time.Now()
				}
				if time.Since(notFoundSince) < notFoundGrace {
					select {
					case <-ctx.Done():
						return nil, ctx.Err()
					case <-time.After(20 * time.Millisecond):
					}
					continue
				}
				return nil, fmt.Errorf("localipc: %s is not running: %w", ep.Path, err)
			}
			return nil, fmt.Errorf("localipc: dial %s: %w", ep.Path, err)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
}
