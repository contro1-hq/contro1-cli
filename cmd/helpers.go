package cmd

import (
	"fmt"
	"io"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/contro1-hq/contro1-cli/internal/config"
)

/*
developmentServerNote is the one line `auth login` and `connect` print when
the active profile points at a server on this computer.

WHY. A clean test of `contro1 connect claude-code` ran against a localhost
profile left over from development, and nothing said so: sign-in, approval
and the connection all "worked", against a server nobody else can reach.
The line goes to stderr, so `--format json` stdout stays one object.
Production URLs print nothing.
*/
func developmentServerNote(cfg *config.Config, current string, apiURL, webURL string) string {
	dev := ""
	for _, u := range []string{apiURL, webURL} {
		if isLocalURL(u) {
			dev = strings.TrimRight(u, "/")
			break
		}
	}
	if dev == "" {
		return ""
	}
	return "Using a development server at " + dev + ". For production: contro1 config profiles use " + productionProfile(cfg, current)
}

// productionProfile names a profile that is not on this computer, preferring
// the usual names; "prod" otherwise, which `profiles use` creates with the
// production URLs.
func productionProfile(cfg *config.Config, current string) string {
	if cfg == nil {
		return "prod"
	}
	names := make([]string, 0, len(cfg.Profiles))
	for n := range cfg.Profiles {
		names = append(names, n)
	}
	sort.Strings(names)
	ordered := append([]string{"prod", "production", "default"}, names...)
	for _, n := range ordered {
		p, ok := cfg.Profiles[n]
		if !ok || p == nil || n == current {
			continue
		}
		if !isLocalURL(orDefault(p.APIURL, config.DefaultAPIURL)) && !isLocalURL(orDefault(p.WebURL, config.DefaultWebURL)) {
			return n
		}
	}
	for _, n := range []string{"prod", "production"} {
		if _, taken := cfg.Profiles[n]; !taken {
			return n
		}
	}
	return "prod"
}

// isLocalURL is true for localhost, a loopback address or 0.0.0.0.
func isLocalURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsLoopback() || ip.IsUnspecified())
}

// printDevelopmentServerNote writes the note for the active profile, if any.
func printDevelopmentServerNote(w io.Writer, apiOverride string) {
	cfg, pr, name, err := loadCtx()
	if err != nil {
		return
	}
	api := pr.APIURL
	if apiOverride != "" {
		api = apiOverride
	}
	if note := developmentServerNote(cfg, name, api, pr.WebURL); note != "" {
		fmt.Fprintln(w, note)
	}
}

// firstNonEmpty returns the first argument whose display string is non-empty.
func firstNonEmpty(vals ...any) any {
	for _, v := range vals {
		if str(v) != "" {
			return v
		}
	}
	return nil
}

// itoa formats an int.
func itoa(n int) string { return strconv.Itoa(n) }

// asMap coerces an arbitrary JSON value to a map.
func asMap(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

// asSlice coerces an arbitrary JSON value to a slice.
func asSlice(v any) []any {
	if s, ok := v.([]any); ok {
		return s
	}
	return nil
}

// str renders a JSON scalar as a compact display string.
func str(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		return fmt.Sprintf("%v", t)
	}
}

// truncate shortens long strings for table cells.
func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}
