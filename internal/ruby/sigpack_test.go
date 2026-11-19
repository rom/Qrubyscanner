package ruby

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestSignaturePack(t *testing.T) {
	pack := `{"schema":"qrubyscanner-signature-pack/1","id":"test-pack","version":"1",
	"headers":[{"header":"X-Acme-Ruby","ruby":true,"weight":60,"framework":"AcmeApp","detail":"acme"}],
	"cookies":[{"name":"_acme_","match":"prefix","weight":40,"framework":"AcmeApp"}],
	"bodies":[{"id":"body.acme","regex":"acme-ruby-marker","ruby":true,"weight":50}]}`
	p, err := ParseSignaturePack([]byte(pack))
	if err != nil {
		t.Fatal(err)
	}
	if err := RegisterSignaturePack(p); err != nil {
		t.Fatal(err)
	}
	d := Analyze(Input{TargetURL: "http://h/", Root: resp(200, map[string]string{"X-Acme-Ruby": "1"}, "acme-ruby-marker")})
	if !d.IsRuby || !hasStr(d.Frameworks, "AcmeApp") || !hasSignal(d, "body.acme") {
		t.Fatalf("pack signatures not applied: %+v", d)
	}
	if len(SignaturePacks()) == 0 {
		t.Error("pack not listed")
	}
	for _, bad := range []string{
		`{"id":""}`, `{"schema":"x","id":"a"}`, `{"id":"a","bodies":[{"id":"b","regex":"("}]}`,
		`{"id":"a","cookies":[{"name":"c","match":"glob"}]}`, `{"id":"a","headers":[{"header":""}]}`, `{`,
	} {
		if _, err := ParseSignaturePack([]byte(bad)); err == nil {
			t.Errorf("bad pack accepted: %s", bad)
		}
	}
	f := filepath.Join(t.TempDir(), "p.json")
	_ = os.WriteFile(f, []byte(`{"id":"file-pack","headers":[{"header":"X-File-Pack","weight":999}]}`), 0o644)
	if _, err := LoadSignaturePack(context.Background(), f, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSignaturePack(context.Background(), f+".nope", nil); err == nil {
		t.Error("missing pack accepted")
	}
}
