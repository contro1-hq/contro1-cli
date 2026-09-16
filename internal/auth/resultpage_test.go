package auth

import (
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestResultPageIsBrandedAndEscaped(t *testing.T) {
	rec := httptest.NewRecorder()
	writeResultPage(rec, "https://contro1.com/", resultPage{OK: true, Title: "You're signed in", Body: "<script>x</script>"})
	body := rec.Body.String()
	for _, want := range []string{"<svg", "Go to dashboard", `href="https://contro1.com/centcom"`, "You&#39;re signed in", "&lt;script&gt;"} {
		if !strings.Contains(body, want) {
			t.Fatalf("result page missing %q", want)
		}
	}
	if strings.Contains(body, "&#9989;") {
		t.Fatal("the emoji check mark is gone for good")
	}
	// A web URL that is not http(s) never becomes a link.
	rec = httptest.NewRecorder()
	writeResultPage(rec, "javascript:alert(1)", resultPage{Title: "x", Body: "y"})
	if strings.Contains(rec.Body.String(), "Go to dashboard") {
		t.Fatal("unsafe dashboard link rendered")
	}
	if dir := os.Getenv("CONTRO1_WRITE_RESULT_PAGE"); dir != "" {
		ok := httptest.NewRecorder()
		writeResultPage(ok, "https://contro1.com", resultPage{OK: true, Title: "You're signed in", Body: "The contro1 CLI on this computer is signed in to your Contro1 organization. Return to your terminal to continue, or open your dashboard."})
		_ = os.WriteFile(dir+"/cli-ok.html", ok.Body.Bytes(), 0o644)
		bad := httptest.NewRecorder()
		writeResultPage(bad, "https://contro1.com", resultPage{Title: "Sign-in was not completed", Body: "The request was declined, so the contro1 CLI on this computer is not signed in. Return to your terminal and run contro1 auth login again when you are ready."})
		_ = os.WriteFile(dir+"/cli-err.html", bad.Body.Bytes(), 0o644)
	}
}
