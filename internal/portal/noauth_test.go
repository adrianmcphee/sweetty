package portal

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sweetty/internal/config"
	"sweetty/internal/event"
)

// TestNoAuthServesDashboardDirectly proves the loopback topology: the portal has
// no application auth, so the root serves the dashboard rather than a login page,
// every data endpoint answers openly with no cookie, and nothing sets a session
// cookie. The SSH tunnel to the loopback bind is the only authenticator.
func TestNoAuthServesDashboardDirectly(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "sweetty.log")
	if err := os.WriteFile(logPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	lg, err := event.New(logPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lg.Close() })

	p := New(config.Config{LogFile: logPath}, lg)
	eng := p.engine()

	wRoot := httptest.NewRecorder()
	eng.ServeHTTP(wRoot, httptest.NewRequest(http.MethodGet, "/", nil))
	if wRoot.Code != http.StatusOK {
		t.Fatalf("GET / status %d, want 200", wRoot.Code)
	}
	body := wRoot.Body.String()
	if !strings.Contains(body, "Live feed") {
		t.Fatal("root did not serve the dashboard")
	}
	if strings.Contains(body, `name="a"`) || strings.Contains(body, `name="b"`) {
		t.Fatal("root served a login page; the portal must have no application auth")
	}
	if len(wRoot.Result().Cookies()) != 0 {
		t.Fatal("the dashboard set a cookie; the portal must be stateless with no session")
	}

	// Every dashboard data route answers directly, with no cookie and no redirect
	// to a login surface.
	for _, path := range []string{
		"/dashboard",
		"/dashboard/log",
		"/dashboard/overview",
		"/dashboard/honeytokens",
		"/dashboard/consoles",
		"/dashboard/recordings",
		"/dashboard/ip/1.2.3.4",
		"/dashboard/session/x",
	} {
		w := httptest.NewRecorder()
		eng.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusOK {
			t.Errorf("GET %s without cookie: status %d, want 200 (no auth)", path, w.Code)
		}
		if loc := w.Header().Get("Location"); loc != "" {
			t.Errorf("GET %s redirected to %q; there must be no login redirect", path, loc)
		}
	}
}
