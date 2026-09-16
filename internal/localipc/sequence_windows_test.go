//go:build windows

package localipc

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestSequentialRequestsKeepContext(t *testing.T) {
	ep, me := testPipe(t)
	l, err := Listen(ListenSpec{Endpoint: ep, AllowedPrincipals: []Principal{Principal(me.User)}, SDDL: DataSDDL(me.User, me.User)})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /h", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"a": 1})
	})
	mux.HandleFunc("POST /x", func(w http.ResponseWriter, r *http.Request) {
		var v map[string]any
		json.NewDecoder(r.Body).Decode(&v)
		if r.Context().Err() != nil {
			t.Errorf("request context cancelled at entry: %v", r.Context().Err())
		}
		io.WriteString(w, "ok")
	})
	srv := NewServer(mux)
	go srv.Serve(l)
	defer srv.Close()
	c := HTTPClient(ep, Principal(me.User))
	resp, err := c.Get(BaseURL + "/h")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	json.NewDecoder(resp.Body).Decode(&m)
	resp.Body.Close()
	resp, err = c.Post(BaseURL+"/x", "application/json", strings.NewReader(`{"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}
