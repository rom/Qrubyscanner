package scanner

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// recordingServer serves a handler and records every requested path.
func recordingServer(t *testing.T, h http.HandlerFunc) (*httptest.Server, func(string) int, int) {
	t.Helper()
	var mu sync.Mutex
	paths := map[string]int{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths[r.URL.Path]++
		mu.Unlock()
		h(w, r)
	}))
	_, portStr, _ := net.SplitHostPort(strings.TrimPrefix(ts.URL, "http://"))
	port, _ := strconv.Atoi(portStr)
	count := func(p string) int {
		mu.Lock()
		defer mu.Unlock()
		return paths[p]
	}
	return ts, count, port
}

func deepScan(t *testing.T, port int, opts Options) *ScanResult {
	t.Helper()
	opts.Mode = ModeDeep
	opts.TLSMode = TLSOff
	opts.Ports = []int{port}
	if opts.Timeout == 0 {
		opts.Timeout = 3 * time.Second
	}
	res, err := Scan(context.Background(), []string{"127.0.0.1"}, opts)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	return res
}

func TestAdaptiveProbesDiscourseOnlyAfterEvidence(t *testing.T) {
	t.Setenv("NO_PROXY", "*")
	ts, count, port := recordingServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("X-Powered-By", "Ruby/3.2.0")
			_, _ = io.WriteString(w, `<meta name="generator" content="Discourse 3.2.0">`)
			return
		}
		w.WriteHeader(404)
	})
	defer ts.Close()

	deepScan(t, port, Options{})

	// Discourse evidence on the root → its probes are issued.
	if count("/srv/status") == 0 || count("/about.json") == 0 {
		t.Errorf("Discourse probes not issued despite evidence: wp-login=%d wp-json=%d",
			count("/srv/status"), count("/about.json"))
	}
	// No GitLab evidence → its probes are NOT issued.
	if count("/api/v4/version") != 0 || count("/help") != 0 {
		t.Errorf("GitLab probes issued without evidence: api=%d help=%d",
			count("/api/v4/version"), count("/help"))
	}
	// Generic Ruby discovery still runs (Ruby-powered).
	if count("/rails/info/properties") == 0 {
		t.Error("generic Ruby discovery probe not issued on a Ruby host")
	}
}

func TestAdaptiveSkipsGenericOnNonRuby(t *testing.T) {
	t.Setenv("NO_PROXY", "*")
	ts, count, port := recordingServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Kestrel")
		w.Header().Set("X-Powered-By", "ASP.NET")
		if r.URL.Path == "/" {
			_, _ = io.WriteString(w, "<html>home</html>")
			return
		}
		w.WriteHeader(404)
	})
	defer ts.Close()

	deepScan(t, port, Options{})

	if count("/rails/info/properties") != 0 || count("/Gemfile.lock") != 0 || count("/srv/status") != 0 {
		t.Errorf("optional probes issued against a clearly non-Ruby host: phpinfo=%d composer=%d wp=%d",
			count("/rails/info/properties"), count("/Gemfile.lock"), count("/srv/status"))
	}
}

func TestAdaptiveRequestBudget(t *testing.T) {
	t.Setenv("NO_PROXY", "*")
	ts, count, port := recordingServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("X-Powered-By", "Ruby/3.2.0")
		}
		_, _ = io.WriteString(w, "<html></html>")
	})
	defer ts.Close()

	res := deepScan(t, port, Options{RequestBudget: 6})
	svc := res.Targets[0].Services[0]
	if svc.DiscoveryLimited != "budget" {
		t.Errorf("DiscoveryLimited = %q, want budget", svc.DiscoveryLimited)
	}
	// Core (4: 2 easter + favicon + pathinfo) counts, leaving few optional probes.
	if count("/rails/info/properties")+count("/Gemfile.lock")+count("/.env") > 3 {
		t.Errorf("budget not enforced; too many optional probes issued")
	}
}

func TestAdaptiveHonoursRateLimit(t *testing.T) {
	t.Setenv("NO_PROXY", "*")
	ts, count, port := recordingServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "120")
		w.WriteHeader(503)
	})
	defer ts.Close()

	res := deepScan(t, port, Options{})
	svc := res.Targets[0].Services[0]
	if svc.DiscoveryLimited != "rate-limited" {
		t.Errorf("DiscoveryLimited = %q, want rate-limited", svc.DiscoveryLimited)
	}
	if count("/rails/info/properties") != 0 || count("/srv/status") != 0 {
		t.Error("optional probes issued despite a 503 rate-limit")
	}
}
