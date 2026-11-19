package report

import (
	"encoding/json"
	"io"

	"github.com/rom/qrubyscanner/internal/scanner"
)

func writeJSON(w io.Writer, res *scanner.ScanResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(res)
}
