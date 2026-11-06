package installer

import (
	"strings"

	"github.com/contro1-hq/contro1-cli/internal/config"
)

/*
ServiceAPIURL is the Contro1 address an install writes into the service
definition.

WHY. The install step rewrites the service definition on Linux and macOS, and
it wrote --api-url only when the command was given one. `sudo contro1 broker
install`, the update command doctor printed, had none: a service that had been
started with the flag, and so never recorded the address in its state, came
back with no address at all, and every credential request failed with nothing
to say why. An install now keeps the address the service already has: the one
it was given (explicit), else the first that recorded() finds (the running
service, its state, its current definition), else the production address.
*/
func ServiceAPIURL(explicit string, recorded ...func() string) string {
	if v := CleanAPIURL(explicit); v != "" {
		return v
	}
	for _, find := range recorded {
		if find == nil {
			continue
		}
		if v := CleanAPIURL(find()); v != "" {
			return v
		}
	}
	return config.DefaultAPIURL
}

// CleanAPIURL is an absolute http(s) address without a trailing slash, or ""
// when s is not one.
func CleanAPIURL(s string) string {
	s = strings.TrimRight(strings.TrimSpace(s), "/")
	if !strings.HasPrefix(s, "https://") && !strings.HasPrefix(s, "http://") {
		return ""
	}
	if len(strings.SplitN(s, "://", 2)[1]) == 0 {
		return ""
	}
	return s
}

// APIURLFromDefinition reads the --api-url argument out of an installed
// service definition: a systemd unit, a launchd plist, or a Windows service
// command line. "" when it has none.
func APIURLFromDefinition(text string) string {
	words := strings.Fields(strings.NewReplacer("<string>", " ", "</string>", " ", `"`, " ", "'", " ").Replace(text))
	for i, w := range words {
		if w == "--api-url" && i+1 < len(words) {
			return CleanAPIURL(words[i+1])
		}
		if v, ok := strings.CutPrefix(w, "--api-url="); ok {
			return CleanAPIURL(v)
		}
	}
	return ""
}
