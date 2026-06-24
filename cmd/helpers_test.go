package cmd

import "testing"

func TestStr(t *testing.T) {
	cases := []struct {
		in   any
		want string
	}{
		{nil, ""},
		{"hello", "hello"},
		{true, "true"},
		{float64(5), "5"},
		{float64(2.5), "2.5"},
	}
	for _, c := range cases {
		if got := str(c.in); got != c.want {
			t.Errorf("str(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestFirstNonEmpty(t *testing.T) {
	if got := str(firstNonEmpty(nil, "", "x", "y")); got != "x" {
		t.Errorf("firstNonEmpty = %q, want x", got)
	}
	if firstNonEmpty(nil, "") != nil {
		t.Error("firstNonEmpty of all-empty should be nil")
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("short", 10); got != "short" {
		t.Errorf("truncate short = %q", got)
	}
	if got := truncate("abcdefghij", 5); len([]rune(got)) != 5 {
		t.Errorf("truncate len = %d, want 5 (%q)", len([]rune(got)), got)
	}
	if got := truncate("a\nb", 10); got != "a b" {
		t.Errorf("truncate newline = %q, want 'a b'", got)
	}
}

func TestClassifyDecision(t *testing.T) {
	cases := []struct {
		resp map[string]any
		want string
	}{
		{map[string]any{"response": map[string]any{"approved": true}}, "approved"},
		{map[string]any{"response": map[string]any{"approved": false}}, "denied"},
		{map[string]any{"response": map[string]any{"status": "approved"}}, "approved"},
		{map[string]any{"response": map[string]any{"status": "rejected"}}, "denied"},
		{map[string]any{"response": map[string]any{"text": "fyi"}}, "responded"},
		{map[string]any{}, "responded"},
	}
	for i, c := range cases {
		if got := classifyDecision(c.resp); got != c.want {
			t.Errorf("case %d: classifyDecision = %q, want %q", i, got, c.want)
		}
	}
}
