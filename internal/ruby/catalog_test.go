package ruby

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func ids(vs []Vulnerability) string {
	var out []string
	for _, v := range vs {
		out = append(out, v.ID)
	}
	return strings.Join(out, ",")
}

// TestRuby2ShellRanges pins the affected/fixed versions published in the
// advisory (https://verialabs.com/ruby2shell/).
func TestRuby2ShellRanges(t *testing.T) {
	cases := []struct {
		version string
		vuln    bool
	}{
		{"2.3.8", false}, // loop introduced in 2.4.0
		{"2.4.0", true},
		{"2.7.8", true},
		{"3.0.7", true},
		{"3.1.7", true},
		{"3.2.9", true}, // EOL, no fix
		{"3.3.0", true},
		{"3.3.13", true},
		{"3.3.14", false},
		{"3.3.15", false},
		{"3.4.0", true},
		{"3.4.12", true},
		{"3.4.13", false},
		{"4.0.0", true},
		{"4.0.9", true},
		{"4.0.10", false},
		{"4.1.0", false},
		{"3.3.6p108", true},
		{"ruby 3.4.13", false},
	}
	for _, c := range cases {
		got := strings.Contains(ids(CorrelateVulns("Ruby", c.version)), Ruby2ShellID)
		if got != c.vuln {
			t.Errorf("Ruby %s: Ruby2Shell flagged=%v, want %v", c.version, got, c.vuln)
		}
	}
	for _, v := range CorrelateVulns("", "3.3.1") {
		if v.ID == Ruby2ShellID && v.Severity != "critical" {
			t.Errorf("severity = %q", v.Severity)
		}
	}
}

func TestRuby2ShellBranchAndUnknown(t *testing.T) {
	c := DefaultCatalog()
	for branch, want := range map[string]bool{"2.3": false, "2.4": true, "3.2": true, "3.3": false, "3.4": false, "4.0": false} {
		got := strings.Contains(ids(c.CorrelateRubyBranch("Ruby", branch)), Ruby2ShellID)
		if got != want {
			t.Errorf("branch %s: got %v want %v", branch, got, want)
		}
	}
	if c.CorrelateRubyBranch("Ruby", "x") != nil || c.CorrelateRubyBranch("JRuby", "3.2") != nil {
		t.Error("bad branch / JRuby should yield nothing")
	}
	u := c.UnknownVersionLeads("Ruby", ObservedFacts{Frameworks: map[string]bool{"rails": true}})
	if len(u) != 1 || u[0].ID != Ruby2ShellID || u[0].Severity != "info" || u[0].Applicability != "unverified" {
		t.Fatalf("unknown-version lead: %+v", u)
	}
	if SeverityRank(u[0].Severity) != 0 {
		t.Error("info leads must not trip --fail-on thresholds")
	}
	if c.UnknownVersionLeads("JRuby") != nil {
		t.Error("no unknown-version lead for JRuby")
	}
}

func TestBundledProductLeads(t *testing.T) {
	c := DefaultCatalog()
	for _, tc := range []struct {
		product, version string
		want             bool
	}{
		{"GitLab", "19.6.0", true}, {"GitLab", "19.6.1", false},
		{"Mastodon", "4.7.5", true}, {"Mastodon", "4.7.6", false},
		{"Discourse", "2026.10.1", true}, {"Discourse", "2026.10.2", false},
		{"GitHub Enterprise Server", "3.22.5", true}, {"OpenProject", "17.9.7", true}, {"Chatwoot", "4.20.0", true},
	} {
		got := strings.Contains(ids(c.CorrelateCMS(tc.product, tc.version)), Ruby2ShellID)
		if got != tc.want {
			t.Errorf("%s %s: got %v want %v", tc.product, tc.version, got, tc.want)
		}
	}
}

func TestVersion4(t *testing.T) {
	cmp := []struct {
		a, b string
		want int
	}{
		{"7.0.8.1", "7.0.8", 1}, {"7.0.8.1", "7.0.8.4", -1}, {"2.2.6.4", "2.2.6.4", 0},
		{"2.0.0p594", "2.0.0p353", 1}, {"2.0.0-p594", "2.0.0p594", 0}, {"1.9.3p551", "2.0.0", -1},
		{"7.1.0.rc1", "7.1.0", -1}, {"3.4.0-preview1", "3.4.0", -1}, {"3.3.14", "3.3.9", 1},
		{"v3.2.1", "3.2.1", 0}, {"ruby-3.2.1", "3.2.1", 0},
	}
	for _, c := range cmp {
		if got := compareVersion(c.a, c.b); got != c.want {
			t.Errorf("compare(%s,%s)=%d want %d", c.a, c.b, got, c.want)
		}
	}
	if _, _, _, ok := parseVersion("abc"); ok {
		t.Error("abc parsed")
	}
	if _, _, _, ok := parseVersion(""); ok {
		t.Error("empty parsed")
	}
	if branchOf("3.3.6") != "3.3" || branchOf("x") != "" {
		t.Error("branchOf")
	}
}

func TestRailsFourPartRanges(t *testing.T) {
	c := DefaultCatalog()
	if !strings.Contains(ids(c.CorrelateCMS("Rails", "5.2.2")), "CVE-2019-5418") {
		t.Error("5.2.2 should flag CVE-2019-5418")
	}
	if strings.Contains(ids(c.CorrelateCMS("Rails", "5.2.2.1")), "CVE-2019-5418") {
		t.Error("5.2.2.1 is fixed")
	}
	if !strings.Contains(ids(c.CorrelateCMS("rails", "3.2.10")), "CVE-2013-0156") {
		t.Error("3.2.10 should flag CVE-2013-0156")
	}
	// railties is the same release train as rails.
	if !strings.Contains(ids(c.CorrelatePackage("railties", "5.2.2")), "CVE-2019-5418") {
		t.Error("railties alias")
	}
	if c.CorrelateCMS("Rails", "") != nil || c.CorrelateCMS("nope", "1.0") != nil || c.CorrelatePackage("", "1") != nil || c.CorrelateCMS("Rails", "x") != nil {
		t.Error("empty inputs")
	}
}

func TestPrereqResolution(t *testing.T) {
	c := DefaultCatalog()
	env := func(e string) string {
		for _, v := range c.CorrelateCMS("Rails", "5.2.2", ObservedFacts{Env: e}) {
			if v.ID == "CVE-2019-5420" {
				return v.Applicability
			}
		}
		return "missing"
	}
	if env("development") != "observed" || env("production") != "contradicted" || env("") != "" {
		t.Errorf("env prereq: %q %q %q", env("development"), env("production"), env(""))
	}
	app := func(s string) string {
		for _, v := range c.CorrelateRuby("Ruby", "2.7.1", ObservedFacts{AppServer: s}) {
			if v.ID == "CVE-2020-25613" {
				return v.Applicability
			}
		}
		return "missing"
	}
	if app("WEBrick 1.6") != "observed" || app("Puma 5") != "contradicted" || app("") != "" {
		t.Errorf("app-server prereq: %q %q %q", app("WEBrick 1.6"), app("Puma 5"), app(""))
	}
	for _, p := range []Prereq{{Kind: "framework", Want: "rails|sinatra"}, {Kind: "app-server", Want: "puma"}, {Kind: "os", Want: "linux"},
		{Kind: "gem", Want: "devise"}, {Kind: "env", Want: "development"}, {Kind: "zz", Want: "y"}} {
		if prereqDetail(p) == "" {
			t.Errorf("no detail for %s", p.Kind)
		}
	}
	f := ObservedFacts{System: "x86_64-linux", Gems: map[string]bool{"devise": true}}
	if resolvePrereq(Prereq{Kind: "os", Want: "linux"}, f) != "observed" || resolvePrereq(Prereq{Kind: "os", Want: "windows"}, f) != "contradicted" ||
		resolvePrereq(Prereq{Kind: "gem", Want: "devise"}, f) != "observed" || resolvePrereq(Prereq{Kind: "gem", Want: "x"}, f) != "unknown" ||
		resolvePrereq(Prereq{Kind: "os", Want: "linux"}, ObservedFacts{}) != "unknown" || resolvePrereq(Prereq{Kind: "zz"}, f) != "unknown" {
		t.Error("os/gem prereqs")
	}
	for sys, want := range map[string]string{"x64-mingw-ucrt": "windows", "arm64-darwin23": "darwin", "amd64-freebsd14": "bsd", "weird": ""} {
		if osFamily(sys) != want {
			t.Errorf("osFamily(%s)", sys)
		}
	}
}

func TestEOL(t *testing.T) {
	for v, want := range map[string]bool{"1.8.7": true, "2.7.8": true, "3.1.6": true, "3.2.9": true, "3.3.6": false, "4.0.1": false} {
		eol, detail := evaluateEOL("Ruby", v)
		if eol != want || detail == "" {
			t.Errorf("EOL(%s)=%v %q", v, eol, detail)
		}
	}
	if eol, d := evaluateEOL("JRuby", "3.1.4"); eol || d != "" {
		t.Error("JRuby is not evaluated")
	}
	if eol, d := evaluateEOL("Ruby", "9.9.9"); eol || d != "" {
		t.Error("unknown branch")
	}
}

func TestBuiltinCatalogueIsWellFormed(t *testing.T) {
	check := func(where string, entries []FeedEntry) {
		for _, e := range entries {
			if e.ID == "" || e.Title == "" || e.Reference == "" || SeverityRank(e.Severity) == 0 || len(e.Affected) == 0 {
				t.Errorf("%s: malformed entry %+v", where, e.ID)
			}
			for _, r := range e.Affected {
				if r.empty() {
					t.Errorf("%s %s: empty range", where, e.ID)
				}
				for _, v := range []string{r.Introduced, r.Fixed, r.LessThan, r.Equals} {
					if v != "" {
						if _, ok := parseVersion4(v); !ok {
							t.Errorf("%s %s: bad version %q", where, e.ID, v)
						}
					}
				}
				if r.Introduced != "" && r.Fixed != "" && compareVersion(r.Introduced, r.Fixed) >= 0 {
					t.Errorf("%s %s: inverted range", where, e.ID)
				}
			}
		}
	}
	check("ruby", builtinRuby)
	for k, v := range builtinCMS {
		if k != strings.ToLower(k) {
			t.Errorf("cms key %q must be lower-case", k)
		}
		check(k, v)
	}
	for k, v := range builtinPackages {
		check(k, v)
	}
	r, c := DefaultCatalog().Counts()
	if r < 30 || c < 60 {
		t.Errorf("catalogue unexpectedly small: %d/%d", r, c)
	}
}

func TestFeedMergeAndFormats(t *testing.T) {
	native := `{"schema":"qrubyscanner-vuln-feed/1","ruby":[{"id":"X-1","severity":"high","title":"t","reference":"r","affected":[{"branch":"3.3","lt":"3.3.99"}]}],
	"cms":{"Rails":[{"id":"X-2","severity":"low","title":"t","affected":[{"lt":"99.0.0"}]}]},
	"packages":{"puma":[{"id":"X-3","severity":"low","title":"t","affected":[{"eq":"6.4.2"}]}]},"eol":{"3.3":"2020-01-01"}}`
	f, err := ParseFeed([]byte(native))
	if err != nil {
		t.Fatal(err)
	}
	c := DefaultCatalog()
	c.Merge(f)
	c.Merge(nil)
	if !strings.Contains(ids(c.CorrelateRuby("Ruby", "3.3.20")), "X-1") || !strings.Contains(ids(c.CorrelateCMS("rails", "8.0.0")), "X-2") ||
		!strings.Contains(ids(c.CorrelatePackage("puma", "6.4.2")), "X-3") {
		t.Error("merged entries not correlated")
	}
	if eol, _ := c.EOL("Ruby", "3.3.1"); !eol {
		t.Error("EOL override not applied")
	}
	if _, err := ParseFeed([]byte(`{"schema":"other/9"}`)); err == nil {
		t.Error("foreign schema accepted")
	}
	if _, err := ParseFeed([]byte(`{`)); err == nil {
		t.Error("bad json accepted")
	}

	osv := `{"id":"GHSA-xxxx","aliases":["CVE-2099-0001"],"summary":"puma bug","affected":[{"package":{"ecosystem":"RubyGems","name":"puma"},
	"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"6.4.3"}]}]}],"database_specific":{"severity":"HIGH"}}`
	f, err = ParseFeed([]byte(osv))
	if err != nil {
		t.Fatal(err)
	}
	c = DefaultCatalog()
	c.Merge(f)
	if !strings.Contains(ids(c.CorrelatePackage("puma", "6.4.0")), "CVE-2099-0001") {
		t.Errorf("OSV RubyGems advisory not keyed by gem: %+v", f.CMS)
	}
	if k, isRuby := feedKeyForPackage("", "ruby-lang/ruby"); !isRuby || k != "" {
		t.Error("ruby core package name")
	}
	if k, _ := feedKeyForPackage("RubyGems", "rails/railties"); k != "rails" {
		t.Errorf("railties key = %q", k)
	}
}

func TestLoadFeedFileAndURL(t *testing.T) {
	body := `{"schema":"qrubyscanner-vuln-feed/1","ruby":[]}`
	p := filepath.Join(t.TempDir(), "f.json")
	_ = os.WriteFile(p, []byte(body), 0o644)
	if _, err := LoadFeed(context.Background(), p, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFeed(context.Background(), p+".missing", nil); err == nil {
		t.Error("missing file accepted")
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/bad" {
			w.WriteHeader(500)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	defer ts.Close()
	if _, err := LoadFeed(context.Background(), ts.URL, ts.Client()); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFeed(context.Background(), ts.URL+"/bad", ts.Client()); err == nil {
		t.Error("HTTP 500 accepted")
	}
}

func TestAffectedSummary(t *testing.T) {
	s := affectedSummary([]RangeSpec{rng("2.4.0", "3.3.0"), br("3.3", "3.3.14"), lo("1.0"), {Equals: "2.0"}, {Branch: "3.1"}, {Fixed: "9"}, {Branch: "3.0", Fixed: "3.0.1"}})
	for _, want := range []string{"2.4.0 – 3.3.0", "3.3.x < 3.3.14", "< 1.0", "= 2.0", "3.1.x", "< 9", "3.0.x < 3.0.1"} {
		if !strings.Contains(s, want) {
			t.Errorf("summary %q missing %q", s, want)
		}
	}
}
