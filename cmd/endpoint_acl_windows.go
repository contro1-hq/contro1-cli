//go:build windows

package cmd

import (
	"golang.org/x/sys/windows"

	"github.com/contro1-hq/contro1-cli/internal/localipc"
)

// endpointPrincipals lists the identities a pipe's descriptor allows, other
// than SYSTEM and the service itself.
func endpointPrincipals(ep localipc.Endpoint, service string) ([]string, error) {
	sd, err := windows.GetNamedSecurityInfo(ep.Path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return nil, err
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return nil, err
	}
	var out []string
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		sid := (*windows.SID)(unsafePointer(&ace.SidStart)).String()
		if sid == "S-1-5-18" || sid == service {
			continue
		}
		out = append(out, sid)
	}
	return out, nil
}
