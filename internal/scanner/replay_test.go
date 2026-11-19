package scanner

import (
	"bytes"
	"io"
	"net/http"
	"testing"

	"github.com/rom/qrubyscanner/internal/corpus"
)

// TestRecordThenReplayReproducesDetection records a live scan's detection
// inputs and shows that replaying the corpus offline reproduces the same Ruby
// verdict and version — the regression-harness guarantee.
func TestRecordThenReplayReproducesDetection(t *testing.T) {
	t.Setenv("NO_PROXY", "*")
	ts, _, port := recordingServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "Ruby/3.2.0")
		w.Header().Set("Set-Cookie", "_app_session=secretvalue123; Path=/; HttpOnly")
		if r.URL.Path == "/" {
			_, _ = io.WriteString(w, `<meta name="generator" content="Discourse 3.2.0">`)
			return
		}
		w.WriteHeader(404)
	})
	defer ts.Close()

	rec := corpus.NewRecorder()
	live := deepScan(t, port, Options{Corpus: rec})
	svcLive := live.Targets[0].Services[0]
	if svcLive.Ruby == nil || !svcLive.Ruby.IsRuby {
		t.Fatalf("live scan did not detect Ruby: %+v", svcLive.Ruby)
	}

	c := rec.Corpus("qrubyscanner", "test")
	if len(c.Services) == 0 {
		t.Fatal("corpus recorded no services")
	}

	// The session-cookie secret must not be in the corpus; the cookie name,
	// a detection signal, must survive.
	var buf bytes.Buffer
	if err := corpus.Write(&buf, c); err != nil {
		t.Fatalf("write corpus: %v", err)
	}
	if bytes.Contains(buf.Bytes(), []byte("secretvalue123")) {
		t.Error("session-cookie secret leaked into the corpus")
	}
	if !bytes.Contains(buf.Bytes(), []byte("_app_session")) {
		t.Error("cookie name (a detection signal) should be kept in the corpus")
	}

	replay := Replay(c, Options{})
	if len(replay.Targets) == 0 || len(replay.Targets[0].Services) == 0 {
		t.Fatal("replay produced no services")
	}
	svcReplay := replay.Targets[0].Services[0]
	if svcReplay.Ruby == nil {
		t.Fatal("replay produced no Ruby detection")
	}
	if svcReplay.Ruby.Verdict != svcLive.Ruby.Verdict {
		t.Errorf("verdict changed on replay: live %q vs replay %q", svcLive.Ruby.Verdict, svcReplay.Ruby.Verdict)
	}
	if svcReplay.Ruby.Version != svcLive.Ruby.Version {
		t.Errorf("version changed on replay: live %q vs replay %q", svcLive.Ruby.Version, svcReplay.Ruby.Version)
	}
	if !hasFrameworkStr(svcReplay.Ruby.Frameworks, "Discourse") {
		t.Errorf("replay lost the Discourse framework: %v", svcReplay.Ruby.Frameworks)
	}
	// Replay reproduces the HTTP summary and keeps target identity.
	if svcReplay.URL != svcLive.URL || svcReplay.Port != svcLive.Port || svcReplay.Scheme != "http" {
		t.Errorf("replay target identity wrong: %+v", svcReplay)
	}
	if svcReplay.HTTP == nil || svcReplay.HTTP.Status != 200 {
		t.Errorf("replay HTTP summary missing: %+v", svcReplay.HTTP)
	}
	// Replay reflects the current catalogue in provenance.
	if replay.Meta.CatalogRuby == 0 {
		t.Error("replay Meta should carry catalogue counts")
	}
}

func hasFrameworkStr(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// TestReplayEmptyCorpus is a boundary check: an empty corpus replays to an
// empty-but-valid result.
func TestReplayEmptyCorpus(t *testing.T) {
	res := Replay(&corpus.Corpus{Schema: corpus.Schema}, Options{})
	if res == nil || len(res.Targets) != 0 {
		t.Fatalf("empty corpus should give an empty result: %+v", res)
	}
	if res.Summary.ServicesProbed != 0 {
		t.Errorf("summary should be zero: %+v", res.Summary)
	}
}
