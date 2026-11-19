package ruby

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"

	"github.com/rom/qrubyscanner/internal/probe"
)

func resp(status int, hdr map[string]string, body string, cookies ...*http.Cookie) *probe.Response {
	h := http.Header{}
	for k, v := range hdr {
		h.Set(k, v)
	}
	return &probe.Response{Status: status, Header: h, Body: []byte(body), Cookies: cookies, RequestURL: "http://h/", FinalURL: "http://h/"}
}

func hasSignal(d *Detection, sig string) bool {
	for _, e := range d.Evidence {
		if e.Signal == sig {
			return true
		}
	}
	return false
}

func hasStr(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func vulnIDs(d *Detection) []string {
	var ids []string
	for _, v := range d.Vulnerabilities {
		ids = append(ids, v.ID)
	}
	return ids
}

func findVuln(d *Detection, id string) *Vulnerability {
	for i := range d.Vulnerabilities {
		if d.Vulnerabilities[i].ID == id {
			return &d.Vulnerabilities[i]
		}
	}
	return nil
}

func TestAnalyzeNilRoot(t *testing.T) {
	if Analyze(Input{}) != nil {
		t.Fatal("nil root should yield nil detection")
	}
}

func TestWEBrickBannerGivesRubyVersion(t *testing.T) {
	d := Analyze(Input{TargetURL: "http://h/", Deep: true,
		Root: resp(200, map[string]string{"Server": "WEBrick/1.6.0 (Ruby/2.7.1/2020-03-31)"}, "hi")})
	if !d.IsRuby || d.Verdict != VerdictConfirmed {
		t.Fatalf("WEBrick should confirm Ruby: %+v", d)
	}
	if d.Version != "2.7.1" || d.Variant != "Ruby" || d.Branch != "2.7" {
		t.Fatalf("version/variant/branch = %q/%q/%q", d.Version, d.Variant, d.Branch)
	}
	if d.FrameworkVersions["WEBrick"] != "1.6.0" {
		t.Errorf("WEBrick version not captured: %v", d.FrameworkVersions)
	}
	if !strings.HasPrefix(d.AppServer, "WEBrick") {
		t.Errorf("app server = %q", d.AppServer)
	}
	if !d.EndOfLife {
		t.Error("Ruby 2.7 should be end of life")
	}
	// WEBrick-specific leads must be marked as preconditions met.
	v := findVuln(d, "CVE-2020-25613")
	if v == nil || v.Applicability != "observed" {
		t.Errorf("CVE-2020-25613 should be flagged with app-server observed: %+v", v)
	}
	if findVuln(d, Ruby2ShellID) == nil {
		t.Errorf("2.7.1 should flag Ruby2Shell: %v", vulnIDs(d))
	}
}

func TestRailsProductionFingerprint(t *testing.T) {
	root := resp(200, map[string]string{
		"X-Runtime":                         "0.015438",
		"ETag":                              `W/"d156facee3ef5dd0a1838ab02a6c20de"`,
		"Cache-Control":                     "max-age=0, private, must-revalidate",
		"X-Permitted-Cross-Domain-Policies": "none",
		"Referrer-Policy":                   "strict-origin-when-cross-origin",
		"X-XSS-Protection":                  "0",
		"Link":                              "</assets/application-8b441ae0.css>; rel=preload; as=style; nopush",
	}, `<meta name="csrf-param" content="authenticity_token" /><input type="hidden" name="authenticity_token" value="x">`,
		&http.Cookie{Name: "_demo_session", Value: "0e9jNxCOwgeSJTrnzi4dzqtnedf5EclPNiyYLEN4%3D--Csa3Bwa%2Bdq8HuJvj--by1Ey7DCFV7sugGXV%2Fiy6A%3D%3D"})
	d := Analyze(Input{TargetURL: "http://h/", Deep: true, Root: root})
	if d.Verdict != VerdictConfirmed || !hasStr(d.Frameworks, "Rails") {
		t.Fatalf("Rails not confirmed: %s %v", d.Verdict, d.Frameworks)
	}
	for _, sig := range []string{"header.x-runtime", "header.rails-cache-defaults", "header.rails-security-defaults",
		"header.link", "body.rails-csrf-meta", "cookie.rails-session-name", "cookie.rails-encrypted"} {
		if !hasSignal(d, sig) {
			t.Errorf("missing signal %s", sig)
		}
	}
	// The cookie value must never be copied into evidence.
	for _, e := range d.Evidence {
		if strings.Contains(e.Data+e.Snippet, "0e9jNxCO") {
			t.Errorf("cookie value leaked into evidence %s", e.Signal)
		}
	}
	// No version was disclosed: an informational Ruby2Shell lead is expected.
	v := findVuln(d, Ruby2ShellID)
	if v == nil || v.Severity != "info" || v.Applicability != "unverified" {
		t.Fatalf("want info/unverified Ruby2Shell lead, got %+v", v)
	}
}

func TestHelmetHeadersAreNotRails(t *testing.T) {
	d := Analyze(Input{TargetURL: "http://h/", Root: resp(200, map[string]string{
		"X-Powered-By":                      "Express",
		"X-Permitted-Cross-Domain-Policies": "none",
		"X-Download-Options":                "noopen",
		"X-DNS-Prefetch-Control":            "off",
	}, "<html></html>")})
	if d.IsRuby || hasSignal(d, "header.rails-security-defaults") {
		t.Fatalf("helmet (Express) must not look like Rails: %+v", d.Evidence)
	}
}

func TestNonRubyPagesStayNone(t *testing.T) {
	cases := map[string]*probe.Response{
		"php":     resp(200, map[string]string{"X-Powered-By": "PHP/8.3.1", "Server": "Apache"}, `<meta name="generator" content="WordPress 6.4">`, &http.Cookie{Name: "PHPSESSID", Value: "abc"}),
		"nginx":   resp(200, map[string]string{"Server": "nginx"}, "<html><body>Welcome to nginx!</body></html>"),
		"django":  resp(200, map[string]string{"Server": "gunicorn"}, `<input type="hidden" name="csrfmiddlewaretoken">`, &http.Cookie{Name: "csrftoken", Value: "x"}),
		"jekyll":  resp(200, map[string]string{"Server": "GitHub.com"}, `<meta name="generator" content="Jekyll v4.3.2">`),
		"vite":    resp(200, nil, `<script src="/assets/index-Bx9kQ2aZ.js"></script>`),
		"grails":  resp(200, map[string]string{"X-Powered-By": "Grails 5.3", "Server": "Apache-Coyote/1.1"}, "<html></html>", &http.Cookie{Name: "JSESSIONID", Value: "x"}),
		"phoenix": resp(200, nil, `<meta name="csrf-token" content="abc">`, &http.Cookie{Name: "_app_key", Value: "SFMyNTY.g3QAAAA.abc"}),
	}
	for name, r := range cases {
		d := Analyze(Input{TargetURL: "http://h/", Deep: true, Root: r})
		if d.IsRuby || d.Verdict != VerdictNone {
			t.Errorf("%s: want none, got %s (%d) %+v", name, d.Verdict, d.Confidence, d.Evidence)
		}
		if len(d.Vulnerabilities) != 0 {
			t.Errorf("%s: non-Ruby service must not get leads: %v", name, vulnIDs(d))
		}
	}
}

func TestPoweredByRuby(t *testing.T) {
	d := Analyze(Input{TargetURL: "http://h/", Deep: true, Root: resp(200, map[string]string{"X-Powered-By": "Ruby/3.4.13"}, "")})
	if !d.IsRuby || d.Version != "3.4.13" || len(d.Vulnerabilities) != 0 {
		t.Fatalf("patched Ruby should be confirmed with no leads: %+v %v", d.Version, vulnIDs(d))
	}
	d = Analyze(Input{TargetURL: "http://h/", Root: resp(200, map[string]string{"X-Powered-By": "Rails 2.3.5"}, "")})
	if !hasStr(d.Frameworks, "Rails") {
		t.Fatal("X-Powered-By: Rails")
	}
}

func TestJekyllIsNamedButInert(t *testing.T) {
	d := Analyze(Input{TargetURL: "http://h/", Root: resp(200, nil, `<meta name="generator" content="Jekyll v4.3.2">`)})
	if !hasStr(d.Frameworks, "Jekyll (static site generator)") || d.Confidence != 0 {
		t.Fatalf("Jekyll should be named with zero Ruby weight: %v %d", d.Frameworks, d.Confidence)
	}
}

func TestPassengerCountedOnceAndVersioned(t *testing.T) {
	d := Analyze(Input{TargetURL: "http://h/", Deep: true, Root: resp(200, map[string]string{
		"Server":       "nginx/1.18.0 + Phusion Passenger(R) 6.0.22",
		"X-Powered-By": "Phusion Passenger(R) 6.0.22",
	}, "ok")})
	n := 0
	for _, e := range d.Evidence {
		if e.Signal == "stack.passenger" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("passenger should count once, got %d", n)
	}
	// Passenger also hosts Python and Node.js: on its own it is not proof.
	if d.IsRuby {
		t.Errorf("Passenger alone must not confirm Ruby (confidence %d)", d.Confidence)
	}
	if d.FrameworkVersions["Phusion Passenger"] != "6.0.22" {
		t.Errorf("passenger version: %v", d.FrameworkVersions)
	}
}

func TestPassengerVulnWhenRuby(t *testing.T) {
	d := Analyze(Input{TargetURL: "http://h/", Deep: true, Root: resp(200, map[string]string{
		"Server":    "nginx + Phusion Passenger(R) 6.0.22",
		"X-Runtime": "0.001234",
	}, `<meta name="csrf-param" content="authenticity_token" />`)})
	if !d.IsRuby {
		t.Fatalf("expected Ruby: %d", d.Confidence)
	}
	if findVuln(d, "CVE-2025-26803") == nil {
		t.Errorf("Passenger 6.0.22 should flag CVE-2025-26803: %v", vulnIDs(d))
	}
	if !strings.HasPrefix(d.AppServer, "Phusion Passenger") {
		t.Errorf("app server = %q", d.AppServer)
	}
}

func TestMarshalCookie(t *testing.T) {
	d := Analyze(Input{TargetURL: "http://h/", Root: resp(200, nil, "x",
		&http.Cookie{Name: "_old_session", Value: "BAh7B0kiD3Nlc3Npb25faWQGOgZFVEkiJTc%3D--0123456789abcdef0123456789abcdef01234567"})})
	if !hasSignal(d, "cookie.ruby-marshal") || !d.IsRuby {
		t.Fatalf("Marshal cookie not recognised: %+v", d.Evidence)
	}
}

func TestSinatraPages(t *testing.T) {
	nf := resp(404, map[string]string{"X-Cascade": "pass"}, "<h1>Not Found</h1>")
	d := Analyze(Input{TargetURL: "http://h/", Deep: true, Root: resp(200, nil, "hello"), Control: nf})
	if !hasStr(d.Frameworks, "Sinatra") || !hasSignal(d, "behavior.sinatra-not-found") {
		t.Fatalf("Sinatra production 404 not recognised: %v", d.Frameworks)
	}
	dev := resp(404, nil, `<h2>Sinatra doesn’t know this ditty.</h2><img src='http://h/__sinatra__/404.png'>`)
	d = Analyze(Input{TargetURL: "http://h/", Root: resp(200, nil, "hello"), Control: dev})
	if !d.IsRuby || !hasStr(d.Frameworks, "Sinatra") {
		t.Fatalf("Sinatra dev 404 not recognised")
	}
}

func TestParamProbeGatedByBaseline(t *testing.T) {
	root := resp(200, nil, "ok")
	bad := resp(400, nil, "Bad Request")
	d := Analyze(Input{TargetURL: "http://h/", Deep: true, Root: root, ParamProbe: bad})
	if !hasSignal(d, "behavior.rack-param-type") {
		t.Fatal("400 on the param probe should be recorded")
	}
	// A server that answers 400 for the control too is not showing Rack behaviour.
	d = Analyze(Input{TargetURL: "http://h/", Deep: true, Root: root, ParamProbe: bad, Control: resp(400, nil, "Bad Request")})
	if hasSignal(d, "behavior.rack-param-type") {
		t.Fatal("param probe must be suppressed when indistinguishable from the baseline")
	}
	// A failing root means the 400 is not a contrast.
	d = Analyze(Input{TargetURL: "http://h/", Deep: true, Root: resp(403, nil, "no"), ParamProbe: bad})
	if hasSignal(d, "behavior.rack-param-type") {
		t.Fatal("param probe needs a successful plain request")
	}
}

const railsInfoPage = `<table>
<tr><td class="name">Rails version</td><td class="value">7.0.4</td></tr>
<tr><td class="name">Ruby version</td><td class="value">ruby 3.1.2p20 (2022-04-12 revision 4491bb740a) [x86_64-linux]</td></tr>
<tr><td class="name">RubyGems version</td><td class="value">3.3.7</td></tr>
<tr><td class="name">Rack version</td><td class="value">2.2.4</td></tr>
<tr><td class="name">Middleware</td><td class="value"><ul><li>Rack::Cors</li><li>Warden::Manager</li><li>WebConsole::Middleware</li></ul></td></tr>
<tr><td class="name">Application root</td><td class="value">/srv/app</td></tr>
<tr><td class="name">Environment</td><td class="value">development</td></tr>
<tr><td class="name">Database adapter</td><td class="value">postgresql</td></tr>
</table>`

func TestRailsInfoExposure(t *testing.T) {
	d := Analyze(Input{TargetURL: "http://h/", Deep: true, Root: resp(200, nil, "x"),
		Extra: map[string]*probe.Response{"http://h/rails/info/properties": resp(200, nil, railsInfoPage)}})
	if !d.RailsInfoExposed || d.RailsInfo == nil {
		t.Fatal("rails info not detected")
	}
	if d.Version != "3.1.2p20" || d.VersionSource != "/rails/info/properties" {
		t.Errorf("version = %q via %q", d.Version, d.VersionSource)
	}
	if d.FrameworkVersions["Rails"] != "7.0.4" || d.FrameworkVersions["Rack"] != "2.2.4" {
		t.Errorf("component versions: %v", d.FrameworkVersions)
	}
	if d.RailsEnv != "development" || d.RailsInfo.System != "x86_64-linux" {
		t.Errorf("env/system = %q/%q", d.RailsEnv, d.RailsInfo.System)
	}
	if !hasStr(d.Gems, "rack-cors") || !hasStr(d.Gems, "web-console") {
		t.Errorf("middleware gems missing: %v", d.Gems)
	}
	if !d.EndOfLife {
		t.Error("Ruby 3.1 is end of life")
	}
	ids := strings.Join(vulnIDs(d), ",")
	for _, want := range []string{Ruby2ShellID, "CVE-2024-27282", "CVE-2023-22794", "CVE-2023-27530"} {
		if !strings.Contains(ids, want) {
			t.Errorf("missing lead %s in %s", want, ids)
		}
	}
	if v := findVuln(d, Ruby2ShellID); v.Severity != "critical" || v.Applicability != "observed" {
		t.Errorf("Ruby2Shell on Rails should be critical/observed: %+v", v)
	}
	if len(d.RailsInfo.Observations()) == 0 {
		t.Error("observations empty")
	}
}

func TestSecretsAreNeverCopied(t *testing.T) {
	key := "0123456789abcdef0123456789abcdef"
	d := Analyze(Input{TargetURL: "http://h/", Deep: true, Root: resp(200, nil, "x"), Extra: map[string]*probe.Response{
		"http://h/config/master.key":   resp(200, nil, key+"\n"),
		"http://h/config/secrets.yml":  resp(200, nil, "production:\n  secret_key_base: deadbeefcafe\n"),
		"http://h/config/database.yml": resp(200, nil, "production:\n  adapter: postgresql\n  password: hunter2\n"),
		"http://h/.env":                resp(200, nil, "RAILS_ENV=production\nSECRET_KEY_BASE=topsecretvalue\n"),
		"http://h/log/development.log": resp(200, nil, "Started POST \"/login\" for 10.0.0.1 at 2026-01-01 10:00:00\nProcessing by SessionsController#create as HTML\n  Parameters: {\"password\"=>\"logsecret\"}\nActiveRecord::RecordNotFound (x)\n"),
	}})
	for _, sig := range []string{"diag.master-key", "diag.secrets-yml", "diag.database-yml", "diag.dotenv", "diag.rails-log", "body.rails-exception-class"} {
		if !hasSignal(d, sig) {
			t.Errorf("missing %s", sig)
		}
	}
	for _, e := range d.Evidence {
		blob := e.Data + e.Snippet + e.Detail
		for _, secret := range []string{key, "deadbeefcafe", "hunter2", "topsecretvalue", "logsecret", "10.0.0.1"} {
			if strings.Contains(blob, secret) {
				t.Errorf("secret %q leaked into evidence %s", secret, e.Signal)
			}
		}
	}
}

func TestCatchAllDoesNotFakeProjectFiles(t *testing.T) {
	page := "<!DOCTYPE html><html><body>SPA shell</body></html>"
	extra := map[string]*probe.Response{}
	for _, p := range GenericDeepProbePaths() {
		extra["http://h"+p] = resp(200, map[string]string{"Content-Type": "text/html"}, page)
	}
	d := Analyze(Input{TargetURL: "http://h/", Deep: true, Root: resp(200, nil, page), Extra: extra, Control: resp(200, nil, page)})
	if d.Confidence != 0 {
		t.Fatalf("catch-all SPA must score 0, got %d: %+v", d.Confidence, d.Evidence)
	}
}

func TestRubyVersionFiles(t *testing.T) {
	d := Analyze(Input{TargetURL: "http://h/", Deep: true, Root: resp(200, map[string]string{"X-Runtime": "0.001000"}, "x"),
		Extra: map[string]*probe.Response{"http://h/.ruby-version": resp(200, nil, "ruby-3.4.13\n")}})
	if d.Version != "3.4.13" || !d.IsRuby {
		t.Fatalf(".ruby-version not used: %q %v", d.Version, d.IsRuby)
	}
	if findVuln(d, Ruby2ShellID) != nil {
		t.Error("3.4.13 is patched and must not flag Ruby2Shell")
	}
	d = Analyze(Input{TargetURL: "http://h/", Deep: true, Root: resp(200, nil, "x"),
		Extra: map[string]*probe.Response{"http://h/.tool-versions": resp(200, nil, "nodejs 20.1.0\nruby 3.2.2\n")}})
	if d.Version != "3.2.2" {
		t.Fatalf(".tool-versions not used: %q", d.Version)
	}
}

func TestBacktraceLeaksBranchAndGems(t *testing.T) {
	body := `NoMethodError (undefined method 'foo' for nil):
/usr/local/bundle/ruby/3.2.0/gems/actionpack-7.0.8.1/lib/action_controller/metal.rb:227:in 'dispatch'
/usr/local/bundle/ruby/3.2.0/gems/rack-2.2.8/lib/rack/etag.rb:27:in 'call'
/usr/local/bundle/ruby/3.2.0/gems/puma-5.6.5/lib/puma/server.rb:10:in 'run'
/usr/local/bundle/ruby/3.2.0/gems/devise-4.5.0/lib/devise.rb:1:in 'x'`
	d := Analyze(Input{TargetURL: "http://h/", Deep: true, Root: resp(500, nil, body)})
	if d.Version != "" || d.Branch != "3.2" {
		t.Fatalf("want branch-only 3.2, got version %q branch %q", d.Version, d.Branch)
	}
	if !d.EndOfLife {
		t.Error("3.2 is end of life")
	}
	// Every 3.2.x release is affected, so the branch alone is enough.
	v := findVuln(d, Ruby2ShellID)
	if v == nil || v.Severity != "critical" || !strings.Contains(v.MatchBasis, "branch-correlation") {
		t.Fatalf("branch-level Ruby2Shell lead expected: %+v", v)
	}
	if d.FrameworkVersions["Rails"] != "7.0.8.1" || d.FrameworkVersions["Rack"] != "2.2.8" || d.FrameworkVersions["Puma"] != "5.6.5" {
		t.Errorf("gem-path versions: %v", d.FrameworkVersions)
	}
	if findVuln(d, "CVE-2023-40175") == nil {
		t.Errorf("puma 5.6.5 should flag CVE-2023-40175: %v", vulnIDs(d))
	}
	// Rails 7.0.8.1 is past the 7.0.8.1 fix but before 7.0.8.4.
	if findVuln(d, "CVE-2024-26143") != nil {
		t.Error("CVE-2024-26143 is fixed in 7.0.8.1")
	}
	if findVuln(d, "CVE-2024-28103") == nil {
		t.Error("CVE-2024-28103 (fixed 7.0.8.4) should be flagged for 7.0.8.1")
	}
	// devise is not promoted, so its lead lives in the inventory.
	found := false
	for _, g := range d.Bundler.Gems {
		if g.Name == "devise" && g.Class == "observed" {
			for _, v := range g.Vulnerabilities {
				if v.ID == "CVE-2019-5421" {
					found = true
				}
			}
		}
	}
	if !found {
		t.Errorf("devise 4.5.0 should carry CVE-2019-5421 in the inventory: %+v", d.Bundler.Gems)
	}
}

func TestSupportedBranchDoesNotBranchCorrelate(t *testing.T) {
	body := `/usr/local/bundle/ruby/3.4.0/gems/rack-3.1.14/lib/rack.rb:27:in 'call'`
	d := Analyze(Input{TargetURL: "http://h/", Deep: true, Root: resp(500, nil, body)})
	if d.Branch != "3.4" {
		t.Fatalf("branch = %q", d.Branch)
	}
	if v := findVuln(d, Ruby2ShellID); v != nil {
		t.Fatalf("3.4.x has a fixed release; branch alone must not produce a lead: %+v", v)
	}
}

func TestMastodonBundledRuby(t *testing.T) {
	root := resp(200, map[string]string{"Server": "Mastodon"}, `<div id="mastodon"></div>`)
	inst := resp(200, nil, `{"uri":"m.example","title":"M","version":"4.7.5"}`)
	d := Analyze(Input{TargetURL: "http://h/", Deep: true, Root: root,
		Extra: map[string]*probe.Response{"http://h/api/v1/instance": inst}})
	if d.FrameworkVersions["Mastodon"] != "4.7.5" {
		t.Fatalf("mastodon version: %v", d.FrameworkVersions)
	}
	v := findVuln(d, Ruby2ShellID)
	if v == nil || v.Severity != "critical" || !strings.Contains(v.Title, "bundles") {
		t.Fatalf("bundled-Ruby lead expected: %+v", d.Vulnerabilities)
	}
	n := 0
	for _, x := range d.Vulnerabilities {
		if x.ID == Ruby2ShellID {
			n++
		}
	}
	if n != 1 {
		t.Errorf("Ruby2Shell should appear once, got %d", n)
	}
}

func TestPleromaIsNotMastodon(t *testing.T) {
	inst := resp(200, nil, `{"uri":"p.example","version":"2.7.2 (compatible; Pleroma 2.5.0)"}`)
	d := Analyze(Input{TargetURL: "http://h/", Deep: true, Root: resp(200, nil, "x"),
		Extra: map[string]*probe.Response{"http://h/api/v1/instance": inst}})
	if d.IsRuby || hasStr(d.Frameworks, "Mastodon") {
		t.Fatalf("Pleroma must not be reported as Mastodon/Ruby: %v", d.Frameworks)
	}
}

func TestObservedRubySupersedesBundledInference(t *testing.T) {
	root := resp(200, map[string]string{"Server": "Mastodon"}, `<div id="mastodon"></div>`)
	d := Analyze(Input{TargetURL: "http://h/", Deep: true, Root: root, Extra: map[string]*probe.Response{
		"http://h/api/v1/instance": resp(200, nil, `{"uri":"m","version":"4.7.5"}`),
		"http://h/.ruby-version":   resp(200, nil, "4.0.10"),
	}})
	if v := findVuln(d, Ruby2ShellID); v != nil {
		t.Fatalf("an observed patched Ruby must win over the bundled-Ruby inference: %+v", v)
	}
}

func TestGHESHeaderVersion(t *testing.T) {
	d := Analyze(Input{TargetURL: "http://h/", Deep: true, Root: resp(200, map[string]string{
		"X-GitHub-Enterprise-Version": "3.20.1", "X-GitHub-Request-Id": "A:B"}, "x",
		&http.Cookie{Name: "_gh_sess", Value: "x"})})
	if d.FrameworkVersions["GitHub Enterprise Server"] != "3.20.1" || findVuln(d, Ruby2ShellID) == nil {
		t.Fatalf("GHES bundled lead missing: %v %v", d.FrameworkVersions, vulnIDs(d))
	}
}

func TestJRubySkipsCoreCVEs(t *testing.T) {
	d := Analyze(Input{TargetURL: "http://h/", Deep: true, Root: resp(200, map[string]string{
		"Server": "TorqueBox/3.1", "X-Powered-By": "JRuby/9.4.5.0"}, "x")})
	if d.Variant != "JRuby" || !d.IsRuby {
		t.Fatalf("variant = %q", d.Variant)
	}
	if len(d.Vulnerabilities) != 0 {
		t.Fatalf("C-core advisories must not be correlated against JRuby: %v", vulnIDs(d))
	}
}

func TestDetectModeHasNoVulns(t *testing.T) {
	d := Analyze(Input{TargetURL: "http://h/", Root: resp(200, map[string]string{"Server": "WEBrick/1.6.1 (Ruby/2.7.2/2020-10-01)"}, "")})
	if len(d.Vulnerabilities) != 0 || d.EOLDetail != "" {
		t.Fatal("detect mode must not correlate vulnerabilities")
	}
}

func TestRailsWelcomePageVersions(t *testing.T) {
	body := `<title>Ruby on Rails 7.1.3</title><ul><li><strong>Rails version:</strong> 7.1.3</li><li><strong>Ruby version:</strong> ruby 3.3.0 (2023-12-25 revision 5124f9ac75) [arm64-darwin23]</li></ul>`
	d := Analyze(Input{TargetURL: "http://h/", Deep: true, Root: resp(200, nil, body)})
	if d.Version != "3.3.0" || d.FrameworkVersions["Rails"] != "7.1.3" {
		t.Fatalf("welcome page versions: %q %v", d.Version, d.FrameworkVersions)
	}
}

func TestVersionConflict(t *testing.T) {
	d := Analyze(Input{TargetURL: "http://h/", Deep: true,
		Root:  resp(200, map[string]string{"Server": "WEBrick/1.8.1 (Ruby/3.2.2/2023-03-30)"}, "x"),
		Extra: map[string]*probe.Response{"http://h/.ruby-version": resp(200, nil, "3.3.5")}})
	if !d.VersionConflict || d.Version != "3.2.2" {
		t.Fatalf("running version should win and conflict be flagged: %q %v", d.Version, d.VersionConflict)
	}
}

func TestURLExtensionAndHelpers(t *testing.T) {
	d := Analyze(Input{TargetURL: "http://h/cgi-bin/app.rbx?x=1", Root: resp(200, nil, "")})
	if !hasSignal(d, "url.ruby-extension") {
		t.Fatal("ruby extension not noticed")
	}
	if hasRubyExtension("http://h/a.php") {
		t.Error(".php is not ruby")
	}
	if pathOf("http://h/a/b?x=1") != "/a/b" {
		t.Error("pathOf")
	}
	if w, h := provenanceDefaults("zzz"); w == "" || h == "" {
		t.Error("default provenance")
	}
}

func TestProbeCatalogue(t *testing.T) {
	all := DeepProbePaths()
	if len(all) <= len(GenericDeepProbePaths()) {
		t.Fatal("conditional groups missing")
	}
	d := &Detection{Frameworks: []string{"Rails"}}
	fired := 0
	for _, g := range ConditionalProbeGroups() {
		if g.Trigger(d) {
			fired++
		}
		if g.Trigger(nil) {
			t.Errorf("group %s fires on nil", g.Name)
		}
	}
	if fired != 1 {
		t.Errorf("only the rails group should fire, got %d", fired)
	}
	if !strings.HasPrefix(ParamTypeProbe, "/?") {
		t.Error("param probe must be a query on /")
	}
}

func TestFaviconCatalog(t *testing.T) {
	RegisterFavicons([]FaviconEntry{{Hash: faviconHash([]byte("icon")), Product: "TestApp", Framework: "TestApp", Ruby: true}})
	fav := resp(200, nil, "icon")
	d := Analyze(Input{TargetURL: "http://h/", Deep: true, Root: resp(200, nil, ""), Favicon: fav})
	if d.FaviconHash == "" || !hasSignal(d, "favicon.catalog") || !hasStr(d.Frameworks, "TestApp") {
		t.Fatalf("favicon match missing: %+v", d)
	}
	if FaviconCatalogCount() < 2 {
		t.Error("catalog count")
	}
	if _, err := ParseFaviconCatalog([]byte(`{"schema":"nope","favicons":[]}`)); err == nil {
		t.Error("bad schema accepted")
	}
}

func sha256Prefix(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:32]
}
