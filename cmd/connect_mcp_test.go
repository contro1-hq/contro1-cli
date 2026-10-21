package cmd

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/contro1-hq/contro1-cli/internal/platforms"
	"github.com/contro1-hq/contro1-cli/internal/runtimeproto"
)

type countingNano struct {
	platforms.Adapter
	applied int
}

func (c *countingNano) ApplyApplications(context.Context, platforms.LocalConnection, *platforms.Journal) error {
	c.applied++
	return nil
}

func nanoDeps(statusErr error, leaseOK, configOK bool, provisioned *int) *nanoMcpDeps {
	return &nanoMcpDeps{
		status: func(context.Context, platforms.LocalConnection) (runtimeStatus, error) {
			return runtimeStatus{EndpointMode: runtimeproto.ModeApplications}, statusErr
		},
		hasOnecli:    func() bool { return true },
		leaseValid:   func(context.Context, string) bool { return leaseOK },
		configHasURL: func(context.Context, string) bool { return configOK },
		provision: func(context.Context, platforms.LocalConnection, func(string)) error {
			*provisioned++
			return nil
		},
	}
}

// connect reaches the MCP step on every run. A NanoClaw group that already has
// a valid lease and its server keeps both, and is not restarted.
func TestNanoClawMcpStepIsIdempotent(t *testing.T) {
	conn := platforms.LocalConnection{Platform: "nanoclaw", PlatformSubject: "ag-sales"}
	cases := []struct {
		name              string
		leaseOK, configOK bool
		wantProvision     int
		wantApply         int
	}{
		{"both in place", true, true, 0, 0},
		{"lease expired", false, true, 1, 0},
		{"server missing", true, false, 0, 1},
		{"first time", false, false, 1, 1},
	}
	for _, c := range cases {
		provisioned := 0
		adapter := &countingNano{}
		var out platforms.McpOutcome
		if err := installNanoClawMcp(context.Background(), conn, nanoDeps(nil, c.leaseOK, c.configOK, &provisioned), adapter, func(string) {}, &platforms.Journal{}, &out); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if provisioned != c.wantProvision || adapter.applied != c.wantApply {
			t.Fatalf("%s: provisioned %d (want %d), group config written and restarted %d (want %d)", c.name, provisioned, c.wantProvision, adapter.applied, c.wantApply)
		}
	}
}

// Not being able to ask the agent's service is a step to retry, not a failed
// connect.
func TestNanoClawStatusFailureIsAStillToDo(t *testing.T) {
	provisioned := 0
	adapter := &countingNano{}
	var out platforms.McpOutcome
	err := installNanoClawMcp(context.Background(), platforms.LocalConnection{Platform: "nanoclaw", PlatformSubject: "ag-sales"},
		nanoDeps(errors.New("could not reach this agent's Contro1 service"), false, false, &provisioned), adapter, func(string) {}, &platforms.Journal{}, &out)
	if err != nil || len(out.ToDo) != 1 || !strings.Contains(out.ToDo[0], "contro1 apps enable nanoclaw --agent ag-sales") || provisioned != 0 || adapter.applied != 0 {
		t.Fatalf("%+v %v", out, err)
	}
}
