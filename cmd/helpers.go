package cmd

import (
	"fmt"
	"strconv"
	"strings"
)

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
