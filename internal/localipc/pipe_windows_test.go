//go:build windows

package localipc

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func testPipe(t *testing.T) (Endpoint, Identity) {
	t.Helper()
	me, err := CurrentIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return PipeEndpoint(fmt.Sprintf("contro1-test-%d", time.Now().UnixNano())), me
}

func TestHTTPOverPipe(t *testing.T) {
	ep, me := testPipe(t)
	l, err := Listen(ListenSpec{Endpoint: ep, AllowedPrincipals: []Principal{Principal(me.User)}, SDDL: DataSDDL(me.User, me.User)})
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hello "+r.URL.Path)
	})}
	go srv.Serve(l)
	defer srv.Close()

	client := HTTPClient(ep, Principal(me.User))
	for i := 0; i < 5; i++ {
		resp, err := client.Get(BaseURL + "/ping")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(body) != "hello /ping" {
			t.Fatalf("body %q", body)
		}
	}

	parsed, err := ParseEndpoint(ep.String())
	if err != nil || parsed != ep {
		t.Fatalf("round trip %v %v", parsed, err)
	}
}

func TestSecondListenerIsRefused(t *testing.T) {
	ep, me := testPipe(t)
	l, err := Listen(ListenSpec{Endpoint: ep, AllowedPrincipals: []Principal{Principal(me.User)}, SDDL: DataSDDL(me.User, me.User)})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if _, err := Listen(ListenSpec{Endpoint: ep, AllowedPrincipals: []Principal{Principal(me.User)}, SDDL: DataSDDL(me.User, me.User)}); err == nil {
		t.Fatal("a second first-instance listener must fail (squatting protection)")
	}
}

func TestServerIdentityIsChecked(t *testing.T) {
	ep, me := testPipe(t)
	l, err := Listen(ListenSpec{Endpoint: ep, AllowedPrincipals: []Principal{Principal(me.User)}, SDDL: DataSDDL(me.User, me.User)})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := Dial(ctx, ep, Principal("S-1-5-18")); err == nil || !strings.Contains(err.Error(), "not the Contro1 service") {
		t.Fatalf("a server running as someone else must be refused, got %v", err)
	}
}

func TestDisallowedClientIsDropped(t *testing.T) {
	ep, me := testPipe(t)
	original := identityOfPipePeer
	identityOfPipePeer = func(h windows.Handle, server bool) (Identity, error) {
		if server {
			return original(h, server)
		}
		return Identity{User: "S-1-5-21-0-0-0-9999"}, nil // somebody else
	}
	defer func() { identityOfPipePeer = original }()

	l, err := Listen(ListenSpec{Endpoint: ep, AllowedPrincipals: []Principal{Principal(me.User)}, SDDL: DataSDDL(me.User, me.User)})
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan struct{}, 1)
	go func() {
		if c, err := l.Accept(); err == nil {
			accepted <- struct{}{}
			c.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := Dial(ctx, ep, "")
	if err == nil {
		buf := make([]byte, 1)
		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		_, readErr := conn.Read(buf)
		if readErr == nil {
			t.Fatal("a disallowed client must not get a working connection")
		}
		conn.Close()
	}
	select {
	case <-accepted:
		t.Fatal("Accept must not return a disallowed client")
	case <-time.After(300 * time.Millisecond):
	}
	l.Close()
}

func TestSDDLHelpers(t *testing.T) {
	if _, err := windows.SecurityDescriptorFromString(ControlSDDL("S-1-5-80-1")); err != nil {
		t.Fatal(err)
	}
	if _, err := windows.SecurityDescriptorFromString(DataSDDL("S-1-5-21-1-2-3-1001", "S-1-5-80-1")); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseEndpoint(`npipe://server/pipe/x`); err == nil {
		t.Fatal("remote pipe hosts must be refused")
	}
}
