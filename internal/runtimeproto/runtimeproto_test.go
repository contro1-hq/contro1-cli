package runtimeproto

import "testing"

func TestAllowedRoute(t *testing.T) {
	cases := []struct {
		mode, method, path string
		want               bool
	}{
		{ModeApprovalsOnly, "POST", "/api/centcom/v1/requests", true},
		{ModeApprovalsOnly, "GET", "/api/centcom/v1/requests/abc123", true},
		{ModeApprovalsOnly, "DELETE", "/api/centcom/v1/requests/abc123", true},
		{ModeApprovalsOnly, "GET", "/api/centcom/v1/requests/abc/evidence", false},
		{ModeApprovalsOnly, "POST", "/api/centcom/v1/actions/invoke", false},
		{ModeApplications, "POST", "/api/centcom/v1/actions/invoke", true},
		{ModeApplications, "POST", "/api/centcom/v1/actions/inv_1/cancel", true},
		{ModeApplications, "GET", "/api/centcom/v1/skills/bootstrap", true},
		{ModeApplications, "GET", "/api/centcom/v1/skills/k/versions/2", true},
		{ModeApplications, "GET", "/api/centcom/v1/skills", false},
		{ModeApplications, "POST", "/api/centcom/v1/agents", false},
		{ModeApplications, "GET", "/api/centcom/v1/requests/../agents", false},
		{ModeApplications, "GET", "/api/centcom/v1/requests/a%2Fb", false},
		{ModeApplications, "GET", "/api/centcom//v1/requests", false},
		{ModeApprovalsOnly, "PUT", "/api/centcom/v1/requests", false},
		{ModeApprovalsOnly, "POST", "/api/centcom/v1/runtime/oauth/token", false},
		{ModeApprovalsOnly, "POST", "/mcp", true},
	}
	for _, c := range cases {
		if got := AllowedRoute(c.mode, c.method, c.path); got != c.want {
			t.Errorf("AllowedRoute(%s, %s, %s) = %v, want %v", c.mode, c.method, c.path, got, c.want)
		}
	}
}

func TestMappingLookupFailsClosed(t *testing.T) {
	m := MappingFile{Entries: []MappingEntry{{PlatformSubject: "main", AgentID: "agt_1"}}}
	if _, ok := m.Lookup("main"); !ok {
		t.Fatal("known subject must resolve")
	}
	if _, ok := m.Lookup("other"); ok {
		t.Fatal("unknown subject must not resolve")
	}
	a := MappingDigest([]MappingEntry{{PlatformSubject: "b"}, {PlatformSubject: "a"}})
	b := MappingDigest([]MappingEntry{{PlatformSubject: "a"}, {PlatformSubject: "b"}})
	if a != b {
		t.Fatal("digest must not depend on order")
	}
}
