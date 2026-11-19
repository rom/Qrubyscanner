package report

import (
	"encoding/csv"
	"fmt"
	"io"
	"strings"

	"github.com/rom/qrubyscanner/internal/scanner"
)

func writeCSV(w io.Writer, res *scanner.ScanResult) error {
	cw := csv.NewWriter(w)
	header := []string{
		"host", "port", "scheme", "url", "port_open", "banner",
		"http_status", "server", "powered_by",
		"ruby_verdict", "ruby_confidence", "ruby_variant", "ruby_version",
		"end_of_life", "frameworks", "vuln_count", "vuln_ids", "max_severity",
		"security_txt", "server_product", "server_version", "behind_proxy", "cdn", "waf",
	}
	if err := cw.Write(header); err != nil {
		return err
	}
	for _, t := range res.Targets {
		for _, s := range t.Services {
			row := []string{
				s.Host, fmt.Sprintf("%d", s.Port), s.Scheme, s.URL,
				fmt.Sprintf("%t", s.PortOpen), s.Banner,
			}
			if s.HTTP != nil {
				row = append(row, fmt.Sprintf("%d", s.HTTP.Status), s.HTTP.Server, s.HTTP.PoweredBy)
			} else {
				row = append(row, "", "", "")
			}
			if s.Ruby != nil {
				maxSev := ""
				for _, v := range s.Ruby.Vulnerabilities {
					maxSev = worseSeverity(maxSev, v.Severity)
				}
				ids := make([]string, 0, len(s.Ruby.Vulnerabilities))
				for _, v := range s.Ruby.Vulnerabilities {
					ids = append(ids, v.ID)
				}
				row = append(row,
					string(s.Ruby.Verdict), fmt.Sprintf("%d", s.Ruby.Confidence),
					s.Ruby.Variant, s.Ruby.Version, fmt.Sprintf("%t", s.Ruby.EndOfLife),
					strings.Join(s.Ruby.Frameworks, "|"),
					fmt.Sprintf("%d", len(s.Ruby.Vulnerabilities)),
					strings.Join(ids, "|"), maxSev,
				)
			} else {
				row = append(row, "", "", "", "", "", "", "0", "", "")
			}
			row = append(row, fmt.Sprintf("%t", s.SecurityTxt != nil && s.SecurityTxt.Present))

			serverProduct, serverVersion := "", ""
			if s.Server != nil {
				serverProduct, serverVersion = s.Server.Product, s.Server.Version
			}
			behindProxy, cdn, waf := "false", "", ""
			if s.Proxy != nil && s.Proxy.Present {
				behindProxy = "true"
				cdn = strings.Join(s.Proxy.CDN, "|")
				waf = strings.Join(s.Proxy.WAF, "|")
			}
			row = append(row, serverProduct, serverVersion, behindProxy, cdn, waf)

			if err := cw.Write(row); err != nil {
				return err
			}
		}
	}
	cw.Flush()
	return cw.Error()
}
