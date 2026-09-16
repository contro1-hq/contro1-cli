//go:build unix

package cmd

import (
	"os"
	"strconv"
	"syscall"

	"github.com/contro1-hq/contro1-cli/internal/localipc"
)

// endpointPrincipals: the socket's group, when the group may connect, and any
// "other" access (which is always exposure). The owner is the service.
func endpointPrincipals(ep localipc.Endpoint, _ string) ([]string, error) {
	info, err := os.Stat(ep.Path)
	if err != nil {
		return nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, os.ErrInvalid
	}
	var out []string
	if info.Mode().Perm()&0o060 != 0 {
		out = append(out, "gid:"+strconv.Itoa(int(st.Gid)))
	}
	if info.Mode().Perm()&0o006 != 0 {
		out = append(out, "everyone")
	}
	return out, nil
}
