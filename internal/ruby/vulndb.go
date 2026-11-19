package ruby

// Built-in, curated vulnerability data. This is a non-exhaustive catalogue of
// high-signal, version-correlatable issues. Matches are informational leads
// derived from a detected version — not confirmed, exploited findings. Extend
// or override it at runtime with external feeds (see catalog.go / --vuln-feed).

// br is an affected range limited to a major.minor branch, below `lt`.
func br(branch, lt string) RangeSpec { return RangeSpec{Branch: branch, LessThan: lt} }

// lo is an open-ended "less than" range across all branches.
func lo(v string) RangeSpec { return RangeSpec{LessThan: v} }

// rng is a half-open [introduced, fixed) range.
func rng(introduced, fixed string) RangeSpec { return RangeSpec{Introduced: introduced, Fixed: fixed} }

const (
	nvd       = "https://nvd.nist.gov/vuln/detail/"
	ruby2Ref  = "https://verialabs.com/ruby2shell/"
	ruby2ID   = "GHSA-34m4-m9fh-gqp5"
	ruby2Name = "Ruby2Shell"
)

// Ruby2ShellID is the advisory identifier of the Ruby2Shell vulnerability.
const Ruby2ShellID = ruby2ID

// ruby2Bundled builds the Ruby2Shell lead for a self-hosted product that ships
// its own Ruby. `through` is the newest release the advisory lists as still
// bundling a vulnerable interpreter; no fixed vendor release was published
// when this catalogue was written, so everything up to it is flagged.
func ruby2Bundled(product, through, bundledRuby, lt string) FeedEntry {
	return FeedEntry{
		ID: ruby2ID, Severity: "critical",
		Title: product + " bundles a Ruby affected by " + ruby2Name,
		Description: product + " ships its own Ruby interpreter. The " + ruby2Name + " advisory lists " +
			product + " " + through + " (bundled Ruby " + bundledRuby + ") as affected by the case-conversion " +
			"heap overflow, reachable without authentication in Rails applications. Install the vendor's fixed release.",
		Reference: ruby2Ref,
		Note: "inferred from the product version, not from an observed Ruby version; no fixed " + product +
			" release was listed in the advisory as of 2026-11-19 — confirm against the vendor advisory",
		Affected: []RangeSpec{lo(lt)},
	}
}

// builtinRuby is the curated Ruby-core (CRuby/MRI) advisory catalogue.
var builtinRuby = []FeedEntry{
	// ---- "Ruby2Shell" (November 2026) ----
	// One-byte heap overflow in the single-byte-encoding case-conversion loop
	// (upcasing ß writes "SS" but only one output byte is bounds-checked).
	// Present since Ruby 2.4.0. Affected/fixed versions are taken from the
	// public advisory; correlation here is an informational, version-based lead.
	{
		ID: ruby2ID, Severity: "critical",
		Title: "Ruby case-conversion heap overflow (\"" + ruby2Name + "\")",
		Description: "One-byte heap buffer overflow in Ruby's case conversion for single-byte encodings " +
			"(ISO-8859-x / Windows-125x), reached through String#upcase, #swapcase, #downcase(:fold) and " +
			"#casecmp?. Rails and classic-style Sinatra are exposed in their default configuration, without " +
			"authentication; other Rack applications are exposed if they case-convert input received in a " +
			"legacy encoding. Upgrade Ruby to 3.3.14, 3.4.13 or 4.0.10; Ruby 3.2 and older are end-of-life " +
			"and receive no fix.",
		Reference: ruby2Ref,
		Note:      "CRuby 2.4.0 and later; fixed in 3.3.14 / 3.4.13 / 4.0.10; 3.2 and older unpatched (EOL); no CVE assigned at the time of writing",
		Affected:  []RangeSpec{rng("2.4.0", "3.3.0"), br("3.3", "3.3.14"), br("3.4", "3.4.13"), br("4.0", "4.0.10")},
		Prereqs: []Prereq{{Kind: "framework", Want: "rails|sinatra",
			Detail: "reachable by default in Rails and classic-style Sinatra (other Rack apps only if they case-convert legacy-encoded input)"}},
		AlertUnknownVersion: true,
	},

	// ---- 3.x era ----
	{
		ID: "CVE-2025-27219", Severity: "medium",
		Title:       "Denial of service in CGI::Cookie.parse",
		Description: "CGI::Cookie.parse takes super-linear time on crafted cookie strings (bundled cgi gem).",
		Reference:   nvd + "CVE-2025-27219", Note: "bundled cgi gem; fix versions provisional — confirm at ruby-lang.org",
		Affected: []RangeSpec{br("3.1", "3.1.7"), br("3.2", "3.2.8"), br("3.3", "3.3.8")},
	},
	{
		ID: "CVE-2025-27221", Severity: "low",
		Title:       "URI userinfo leak in URI#join / #merge / #+",
		Description: "The bundled uri gem can retain credentials of the original URI when joining to a different host.",
		Reference:   nvd + "CVE-2025-27221", Note: "bundled uri gem; fix versions provisional — confirm at ruby-lang.org",
		Affected: []RangeSpec{br("3.1", "3.1.7"), br("3.2", "3.2.8"), br("3.3", "3.3.8")},
	},
	{
		ID: "CVE-2024-27282", Severity: "high",
		Title:       "Arbitrary memory address read in Regexp search",
		Description: "Attacker-supplied data passed to the regex compiler can be used to read arbitrary heap data relative to the start of the text.",
		Reference:   nvd + "CVE-2024-27282",
		Affected:    []RangeSpec{br("3.0", "3.0.7"), br("3.1", "3.1.5"), br("3.2", "3.2.4"), br("3.3", "3.3.1")},
	},
	{
		ID: "CVE-2024-27281", Severity: "medium",
		Title:       "RCE via .rdoc_options in RDoc",
		Description: "Parsing an untrusted .rdoc_options file (or documentation cache) as YAML can lead to object injection and code execution.",
		Reference:   nvd + "CVE-2024-27281", Note: "requires processing attacker-supplied RDoc files (not remotely reachable in a web app)",
		Affected: []RangeSpec{br("3.0", "3.0.7"), br("3.1", "3.1.5"), br("3.2", "3.2.4"), br("3.3", "3.3.1")},
	},
	{
		ID: "CVE-2024-27280", Severity: "high",
		Title:       "Buffer over-read in StringIO",
		Description: "StringIO#ungetbyte / #ungetc can read past the end of a string, disclosing adjacent heap memory.",
		Reference:   nvd + "CVE-2024-27280",
		Affected:    []RangeSpec{br("3.0", "3.0.7"), br("3.1", "3.1.5")},
	},
	{
		ID: "CVE-2023-28755", Severity: "high",
		Title:       "ReDoS in URI",
		Description: "The URI parser mishandles invalid URLs with specific characters, causing catastrophic backtracking.",
		Reference:   nvd + "CVE-2023-28755",
		Affected:    []RangeSpec{br("2.7", "2.7.8"), br("3.0", "3.0.6"), br("3.1", "3.1.4"), br("3.2", "3.2.2")},
	},
	{
		ID: "CVE-2023-28756", Severity: "medium",
		Title:       "ReDoS in Time",
		Description: "The Time parser mishandles invalid strings with specific characters, causing catastrophic backtracking.",
		Reference:   nvd + "CVE-2023-28756",
		Affected:    []RangeSpec{br("2.7", "2.7.8"), br("3.0", "3.0.6"), br("3.1", "3.1.4"), br("3.2", "3.2.2")},
	},
	{
		ID: "CVE-2021-33621", Severity: "high",
		Title:       "HTTP response splitting in CGI",
		Description: "The bundled cgi gem does not sanitise header values, allowing response splitting when untrusted input reaches CGI::Cookie / headers.",
		Reference:   nvd + "CVE-2021-33621",
		Affected:    []RangeSpec{br("2.7", "2.7.7"), br("3.0", "3.0.5"), br("3.1", "3.1.3")},
	},
	{
		ID: "CVE-2022-28738", Severity: "critical",
		Title:       "Double free in Regexp compilation",
		Description: "Compiling a crafted, attacker-supplied source string as a Regexp can write to a freed address.",
		Reference:   nvd + "CVE-2022-28738",
		Affected:    []RangeSpec{br("3.0", "3.0.4"), br("3.1", "3.1.2")},
	},
	{
		ID: "CVE-2022-28739", Severity: "high",
		Title:       "Buffer over-read in String-to-Float conversion",
		Description: "Kernel#Float and String#to_f can read past a buffer on crafted input, disclosing memory.",
		Reference:   nvd + "CVE-2022-28739",
		Affected:    []RangeSpec{lo("2.6.10"), br("2.7", "2.7.6"), br("3.0", "3.0.4"), br("3.1", "3.1.2")},
	},
	{
		ID: "CVE-2021-41817", Severity: "high",
		Title:       "ReDoS in Date.parse",
		Description: "Date parsing methods take super-linear time on crafted input (bundled date gem).",
		Reference:   nvd + "CVE-2021-41817",
		Affected:    []RangeSpec{lo("2.6.9"), br("2.7", "2.7.5"), br("3.0", "3.0.3")},
	},
	{
		ID: "CVE-2021-41819", Severity: "high",
		Title:       "Cookie prefix spoofing in CGI::Cookie.parse",
		Description: "Cookie names are URL-decoded, letting an attacker spoof __Host-/__Secure- prefixed cookies.",
		Reference:   nvd + "CVE-2021-41819",
		Affected:    []RangeSpec{lo("2.6.9"), br("2.7", "2.7.5"), br("3.0", "3.0.3")},
	},
	{
		ID: "CVE-2021-41816", Severity: "critical",
		Title:       "Buffer overrun in CGI.escape_html",
		Description: "CGI.escape_html overflows a buffer on very large inputs on platforms where long is 32-bit (e.g. Windows).",
		Reference:   nvd + "CVE-2021-41816", Note: "requires a ~700 MB string and a platform with 32-bit long",
		Affected: []RangeSpec{br("2.7", "2.7.5"), br("3.0", "3.0.3")},
	},
	{
		ID: "CVE-2021-31810", Severity: "medium",
		Title:       "Trusting FTP PASV responses in Net::FTP",
		Description: "A malicious FTP server can make Net::FTP connect to an arbitrary address and port, exposing internal services.",
		Reference:   nvd + "CVE-2021-31810",
		Affected:    []RangeSpec{lo("2.6.8"), br("2.7", "2.7.4"), br("3.0", "3.0.2")},
	},
	{
		ID: "CVE-2021-32066", Severity: "high",
		Title:       "StartTLS stripping in Net::IMAP",
		Description: "Net::IMAP does not raise when StartTLS fails with an unknown response, enabling a man-in-the-middle downgrade.",
		Reference:   nvd + "CVE-2021-32066",
		Affected:    []RangeSpec{lo("2.6.8"), br("2.7", "2.7.4"), br("3.0", "3.0.2")},
	},
	{
		ID: "CVE-2021-28965", Severity: "high",
		Title:       "XML round-trip vulnerability in REXML",
		Description: "REXML can produce a different document when parsing and re-serialising crafted XML, undermining signature checks.",
		Reference:   nvd + "CVE-2021-28965",
		Affected:    []RangeSpec{lo("2.5.9"), br("2.6", "2.6.7"), br("2.7", "2.7.3"), br("3.0", "3.0.1")},
	},

	// ---- 2.x era ----
	{
		ID: "CVE-2020-25613", Severity: "high",
		Title:       "HTTP request smuggling in WEBrick",
		Description: "WEBrick does not rigorously validate the Transfer-Encoding header, enabling request smuggling behind some reverse proxies.",
		Reference:   nvd + "CVE-2020-25613",
		Affected:    []RangeSpec{lo("2.5.9"), br("2.6", "2.6.7"), br("2.7", "2.7.2")},
		Prereqs:     []Prereq{{Kind: "app-server", Want: "webrick"}},
	},
	{
		ID: "CVE-2020-10663", Severity: "high",
		Title:       "Unsafe object creation in JSON",
		Description: "The bundled json gem can be coerced into creating arbitrary objects when parsing crafted documents.",
		Reference:   nvd + "CVE-2020-10663",
		Affected:    []RangeSpec{lo("2.4.10"), br("2.5", "2.5.8"), br("2.6", "2.6.6"), br("2.7", "2.7.1")},
	},
	{
		ID: "CVE-2020-10933", Severity: "medium",
		Title:       "Heap exposure in BasicSocket#read_nonblock / UDPSocket#recvfrom_nonblock",
		Description: "Non-blocking socket reads with a size and buffer argument can expose uninitialised heap memory.",
		Reference:   nvd + "CVE-2020-10933",
		Affected:    []RangeSpec{br("2.5", "2.5.8"), br("2.6", "2.6.6"), br("2.7", "2.7.1")},
	},
	{
		ID: "CVE-2019-16255", Severity: "high",
		Title:       "Code injection in Shell#[] and Shell#test",
		Description: "Passing untrusted data as the first argument of Shell#[] / Shell#test allows calling an arbitrary Ruby method.",
		Reference:   nvd + "CVE-2019-16255",
		Affected:    []RangeSpec{lo("2.4.8"), br("2.5", "2.5.7"), br("2.6", "2.6.5")},
	},
	{
		ID: "CVE-2019-16254", Severity: "medium",
		Title:       "HTTP response splitting in WEBrick (incomplete fix)",
		Description: "WEBrick allows response splitting when untrusted input reaches a response header.",
		Reference:   nvd + "CVE-2019-16254",
		Affected:    []RangeSpec{lo("2.4.8"), br("2.5", "2.5.7"), br("2.6", "2.6.5")},
		Prereqs:     []Prereq{{Kind: "app-server", Want: "webrick"}},
	},
	{
		ID: "CVE-2019-16201", Severity: "high",
		Title:       "ReDoS in WEBrick Digest authentication",
		Description: "WEBrick's Digest access authentication is vulnerable to regular-expression denial of service.",
		Reference:   nvd + "CVE-2019-16201",
		Affected:    []RangeSpec{lo("2.4.8"), br("2.5", "2.5.7"), br("2.6", "2.6.5")},
		Prereqs:     []Prereq{{Kind: "app-server", Want: "webrick"}},
	},
	{
		ID: "CVE-2019-15845", Severity: "medium",
		Title:       "NUL injection in File.fnmatch and File.fnmatch?",
		Description: "A NUL byte in a path pattern can make fnmatch match unintended paths.",
		Reference:   nvd + "CVE-2019-15845",
		Affected:    []RangeSpec{lo("2.4.8"), br("2.5", "2.5.7"), br("2.6", "2.6.5")},
	},
	{
		ID: "CVE-2018-16395", Severity: "critical",
		Title:       "OpenSSL::X509::Name equality check does not work correctly",
		Description: "Two X509 names can compare equal when one is a prefix of the other, which can let a crafted certificate pass a name check.",
		Reference:   nvd + "CVE-2018-16395",
		Affected:    []RangeSpec{lo("2.3.8"), br("2.4", "2.4.5"), br("2.5", "2.5.2")},
	},
	{
		ID: "CVE-2018-8780", Severity: "critical",
		Title:       "Unintentional directory traversal by poisoned NUL byte in Dir",
		Description: "Dir.open, Dir.new, Dir.entries and Dir.empty? accept a path containing NUL, allowing traversal outside the intended directory.",
		Reference:   nvd + "CVE-2018-8780",
		Affected:    []RangeSpec{lo("2.2.10"), br("2.3", "2.3.7"), br("2.4", "2.4.4"), br("2.5", "2.5.1")},
	},
	{
		ID: "CVE-2018-8778", Severity: "high",
		Title:       "Buffer under-read in String#unpack",
		Description: "A crafted format string can make String#unpack read before the start of a buffer, disclosing heap memory.",
		Reference:   nvd + "CVE-2018-8778",
		Affected:    []RangeSpec{lo("2.2.10"), br("2.3", "2.3.7"), br("2.4", "2.4.4"), br("2.5", "2.5.1")},
	},
	{
		ID: "CVE-2018-8777", Severity: "high",
		Title:       "Denial of service by large request in WEBrick",
		Description: "A very large request header can exhaust memory in WEBrick.",
		Reference:   nvd + "CVE-2018-8777",
		Affected:    []RangeSpec{lo("2.2.10"), br("2.3", "2.3.7"), br("2.4", "2.4.4"), br("2.5", "2.5.1")},
		Prereqs:     []Prereq{{Kind: "app-server", Want: "webrick"}},
	},
	{
		ID: "CVE-2017-17742", Severity: "medium",
		Title:       "HTTP response splitting in WEBrick",
		Description: "WEBrick allows response splitting when a script accepts external input and outputs it unmodified in a response header.",
		Reference:   nvd + "CVE-2017-17742",
		Affected:    []RangeSpec{lo("2.2.10"), br("2.3", "2.3.7"), br("2.4", "2.4.4"), br("2.5", "2.5.1")},
		Prereqs:     []Prereq{{Kind: "app-server", Want: "webrick"}},
	},
	{
		ID: "CVE-2017-17405", Severity: "high",
		Title:       "Command injection in Net::FTP",
		Description: "Net::FTP passes a pipe-prefixed local file name to Kernel#open, allowing command execution via a malicious server.",
		Reference:   nvd + "CVE-2017-17405",
		Affected:    []RangeSpec{lo("2.2.9"), br("2.3", "2.3.6"), br("2.4", "2.4.3")},
	},
	{
		ID: "CVE-2017-14064", Severity: "critical",
		Title:       "Heap exposure in JSON.generate",
		Description: "A crafted call to JSON.generate with a space/indent string containing NUL can expose arbitrary heap memory.",
		Reference:   nvd + "CVE-2017-14064",
		Affected:    []RangeSpec{lo("2.2.8"), br("2.3", "2.3.5"), br("2.4", "2.4.2")},
	},
	{
		ID: "CVE-2017-10784", Severity: "high",
		Title:       "Escape sequence injection in WEBrick Basic authentication",
		Description: "A crafted user name is written unescaped to the WEBrick log, injecting terminal escape sequences.",
		Reference:   nvd + "CVE-2017-10784",
		Affected:    []RangeSpec{lo("2.2.8"), br("2.3", "2.3.5"), br("2.4", "2.4.2")},
		Prereqs:     []Prereq{{Kind: "app-server", Want: "webrick"}},
	},
	{
		ID: "CVE-2017-0898", Severity: "critical",
		Title:       "Buffer underrun in Kernel.sprintf",
		Description: "A malicious format string with a precision specifier (*) and a huge negative value can cause heap corruption or information disclosure.",
		Reference:   nvd + "CVE-2017-0898",
		Affected:    []RangeSpec{lo("2.2.8"), br("2.3", "2.3.5"), br("2.4", "2.4.2")},
	},
	{
		ID: "CVE-2015-1855", Severity: "medium",
		Title:       "OpenSSL extension hostname verification is too permissive",
		Description: "Ruby's OpenSSL hostname matching violates RFC 6125 for wildcard certificates.",
		Reference:   nvd + "CVE-2015-1855",
		Affected:    []RangeSpec{lo("2.0.0p645"), br("2.1", "2.1.6"), br("2.2", "2.2.2")},
	},
	{
		ID: "CVE-2014-8080", Severity: "medium",
		Title:       "Denial of service by XML entity expansion in REXML",
		Description: "REXML can be forced to allocate extremely large strings via parameter-entity expansion.",
		Reference:   nvd + "CVE-2014-8080",
		Affected:    []RangeSpec{lo("1.9.3p550"), br("2.0", "2.0.0p594"), br("2.1", "2.1.4")},
	},
	{
		ID: "CVE-2013-4164", Severity: "critical",
		Title:       "Heap overflow in floating point parsing",
		Description: "Converting a crafted string to a floating point value overflows the heap, giving denial of service and possibly code execution.",
		Reference:   nvd + "CVE-2013-4164",
		Affected:    []RangeSpec{lo("1.9.3p484"), br("2.0", "2.0.0p353")},
	},
}

// builtinCMS is the curated catalogue for frameworks, applications and
// versioned stack components, keyed by lower-case name.
var builtinCMS = map[string][]FeedEntry{
	"rails": {
		{
			ID: "CVE-2025-24293", Severity: "critical",
			Title:       "Active Storage allows unsafe image transformation methods",
			Description: "Active Storage passed a set of transformation methods to the image processor that allow command injection when user input reaches variant transformations.",
			Reference:   nvd + "CVE-2025-24293", Note: "requires Active Storage variants with attacker-influenced transformation arguments",
			Affected: []RangeSpec{rng("5.2.0", "7.1.5.2"), br("7.2", "7.2.2.2"), br("8.0", "8.0.2.1")},
		},
		{
			ID: "CVE-2024-54133", Severity: "low",
			Title:       "Possible Content-Security-Policy bypass in Action Dispatch",
			Description: "Applications that set CSP directives dynamically from untrusted input can have the policy bypassed.",
			Reference:   nvd + "CVE-2024-54133",
			Affected:    []RangeSpec{rng("5.2.0", "7.0.8.7"), br("7.1", "7.1.5.1"), br("7.2", "7.2.2.1"), br("8.0", "8.0.0.1")},
		},
		{
			ID: "CVE-2024-47887", Severity: "medium",
			Title:       "ReDoS in Action Controller HTTP Token authentication (and related October 2024 ReDoS fixes)",
			Description: "Crafted headers cause super-linear regex matching in HTTP Token authentication, query-parameter filtering, block_format and plain_text_for_blockquote_node (CVE-2024-41128, CVE-2024-47888, CVE-2024-47889).",
			Reference:   nvd + "CVE-2024-47887", Note: "Ruby 3.2+ mitigates most ReDoS via regex timeouts/memoisation",
			Affected: []RangeSpec{lo("6.1.7.9"), br("7.0", "7.0.8.5"), br("7.1", "7.1.4.1"), br("7.2", "7.2.1.1")},
		},
		{
			ID: "CVE-2024-28103", Severity: "medium",
			Title:       "Permissions-Policy is only served on HTML responses",
			Description: "The configured Permissions-Policy header is applied only to responses with an HTML content type.",
			Reference:   nvd + "CVE-2024-28103",
			Affected:    []RangeSpec{br("6.1", "6.1.7.8"), br("7.0", "7.0.8.4"), br("7.1", "7.1.3.4")},
		},
		{
			ID: "CVE-2024-26144", Severity: "medium",
			Title:       "Possible sensitive session information leak in Active Storage",
			Description: "Active Storage sends a Set-Cookie header together with a public Cache-Control header, so a caching proxy may serve one user's session cookie to others.",
			Reference:   nvd + "CVE-2024-26144",
			Affected:    []RangeSpec{rng("5.2.0", "6.1.7.7"), br("7.0", "7.0.8.1")},
		},
		{
			ID: "CVE-2024-26143", Severity: "medium",
			Title:       "Possible XSS in Action Controller translation helpers",
			Description: "Translation keys ending in _html combined with untrusted default values can inject HTML.",
			Reference:   nvd + "CVE-2024-26143",
			Affected:    []RangeSpec{br("7.0", "7.0.8.1"), br("7.1", "7.1.3.1")},
		},
		{
			ID: "CVE-2023-28362", Severity: "medium",
			Title:       "Possible XSS via user-supplied values to redirect_to",
			Description: "redirect_to permits characters that are illegal in a Location header, which some browsers treat as a body, enabling XSS.",
			Reference:   nvd + "CVE-2023-28362",
			Affected:    []RangeSpec{lo("6.1.7.4"), br("7.0", "7.0.5.1")},
		},
		{
			ID: "CVE-2023-22795", Severity: "high",
			Title:       "ReDoS in Action Dispatch If-None-Match handling",
			Description: "A crafted If-None-Match header causes catastrophic backtracking in Action Dispatch.",
			Reference:   nvd + "CVE-2023-22795", Note: "Ruby 3.2+ is not affected (regex memoisation)",
			Affected: []RangeSpec{lo("6.1.7.1"), br("7.0", "7.0.4.1")},
		},
		{
			ID: "CVE-2023-22794", Severity: "high",
			Title:       "SQL injection in Active Record query comments",
			Description: "Unsanitised input passed to annotate, optimizer_hints or the QueryLogs interface can break out of the SQL comment.",
			Reference:   nvd + "CVE-2023-22794",
			Affected:    []RangeSpec{br("6.0", "6.0.6.1"), br("6.1", "6.1.7.1"), br("7.0", "7.0.4.1")},
		},
		{
			ID: "CVE-2022-32224", Severity: "critical",
			Title:       "Possible RCE via YAML-serialised columns in Active Record",
			Description: "An attacker who can manipulate data in a YAML-serialised column can escalate to remote code execution through unsafe YAML loading.",
			Reference:   nvd + "CVE-2022-32224", Note: "requires write access to a serialised column (e.g. via SQL injection)",
			Affected: []RangeSpec{lo("5.2.8.1"), br("6.0", "6.0.5.1"), br("6.1", "6.1.6.1"), br("7.0", "7.0.3.1")},
		},
		{
			ID: "CVE-2022-21831", Severity: "critical",
			Title:       "Possible code injection in Active Storage image processing",
			Description: "Active Storage variant transformations could pass attacker-controlled method names to image_processing.",
			Reference:   nvd + "CVE-2022-21831",
			Affected:    []RangeSpec{br("5.2", "5.2.6.3"), br("6.0", "6.0.4.7"), br("6.1", "6.1.4.7"), br("7.0", "7.0.2.3")},
		},
		{
			ID: "CVE-2022-23633", Severity: "high",
			Title:       "Possible exposure of information between requests in Action Pack",
			Description: "Under certain conditions response bodies are not closed, so thread-local state can leak into the next request served by that thread.",
			Reference:   nvd + "CVE-2022-23633",
			Affected:    []RangeSpec{br("5.2", "5.2.6.2"), br("6.0", "6.0.4.6"), br("6.1", "6.1.4.6"), br("7.0", "7.0.2.2")},
		},
		{
			ID: "CVE-2022-22577", Severity: "medium",
			Title:       "Possible XSS via missing CSP headers on non-HTML responses",
			Description: "Action Pack does not send CSP headers for non-HTML responses, which can be abused for XSS.",
			Reference:   nvd + "CVE-2022-22577",
			Affected:    []RangeSpec{br("5.2", "5.2.7.1"), br("6.0", "6.0.4.8"), br("6.1", "6.1.5.1"), br("7.0", "7.0.2.4")},
		},
		{
			ID: "CVE-2021-22885", Severity: "high",
			Title:       "Possible information disclosure / unintended method execution in Action Pack",
			Description: "Untrusted input passed to redirect_to or polymorphic_url can call unintended methods.",
			Reference:   nvd + "CVE-2021-22885",
			Affected:    []RangeSpec{lo("5.2.4.6"), br("6.0", "6.0.3.7"), br("6.1", "6.1.3.2")},
		},
		{
			ID: "CVE-2021-22904", Severity: "high",
			Title:       "Denial of service in Action Controller token authentication",
			Description: "A crafted Authorization header causes super-linear matching in authenticate_or_request_with_http_token.",
			Reference:   nvd + "CVE-2021-22904",
			Affected:    []RangeSpec{lo("5.2.4.6"), br("6.0", "6.0.3.7"), br("6.1", "6.1.3.2")},
		},
		{
			ID: "CVE-2020-8165", Severity: "critical",
			Title:       "Unintended unmarshalling of user-provided objects in MemCacheStore / RedisCacheStore",
			Description: "Untrusted values written with the raw option can be unmarshalled as Ruby objects, leading to remote code execution.",
			Reference:   nvd + "CVE-2020-8165",
			Affected:    []RangeSpec{lo("5.2.4.3"), br("6.0", "6.0.3.1")},
		},
		{
			ID: "CVE-2020-8164", Severity: "high",
			Title:       "Possible strong parameters bypass in Action Pack",
			Description: "Calling each / each_value / each_pair on ActionController::Parameters can return untrusted, unfiltered hashes.",
			Reference:   nvd + "CVE-2020-8164",
			Affected:    []RangeSpec{lo("5.2.4.3"), br("6.0", "6.0.3.1")},
		},
		{
			ID: "CVE-2020-8163", Severity: "high",
			Title:       "Code injection via the locals argument of render",
			Description: "User-controlled local-variable names passed to render can execute arbitrary code.",
			Reference:   nvd + "CVE-2020-8163",
			Affected:    []RangeSpec{lo("4.2.11.2")},
		},
		{
			ID: "CVE-2019-5420", Severity: "critical",
			Title:       "Development-mode secret_key_base is guessable (RCE)",
			Description: "In development mode the secret_key_base is derived from the application name, so signed/encrypted values can be forged, leading to remote code execution.",
			Reference:   nvd + "CVE-2019-5420",
			Affected:    []RangeSpec{br("5.2", "5.2.2.1")},
			Prereqs:     []Prereq{{Kind: "env", Want: "development", Detail: "only when the application runs in the development environment"}},
		},
		{
			ID: "CVE-2019-5418", Severity: "high",
			Title:       "File content disclosure in Action View",
			Description: "A crafted Accept header combined with render file: lets an attacker read arbitrary files on the server.",
			Reference:   nvd + "CVE-2019-5418",
			Affected:    []RangeSpec{lo("4.2.11.1"), br("5.0", "5.0.7.2"), br("5.1", "5.1.6.2"), br("5.2", "5.2.2.1")},
		},
		{
			ID: "CVE-2016-2098", Severity: "critical",
			Title:       "Remote code execution via render with user input",
			Description: "Passing unsanitised user input to render (e.g. render params[:id]) allows rendering inline templates and executing code.",
			Reference:   nvd + "CVE-2016-2098",
			Affected:    []RangeSpec{lo("3.2.22.2"), rng("4.0.0", "4.1.14.2"), br("4.2", "4.2.5.2")},
		},
		{
			ID: "CVE-2016-0752", Severity: "high",
			Title:       "Directory traversal / information leak in Action View",
			Description: "Applications that pass unverified user input to render can be made to render arbitrary files.",
			Reference:   nvd + "CVE-2016-0752",
			Affected:    []RangeSpec{lo("3.2.22.1"), rng("4.0.0", "4.1.14.1"), br("4.2", "4.2.5.1")},
		},
		{
			ID: "CVE-2014-0130", Severity: "high",
			Title:       "Directory traversal with implicit render and globbing routes",
			Description: "Certain route globbing configurations with implicit render let an attacker read files outside the view path.",
			Reference:   nvd + "CVE-2014-0130",
			Affected:    []RangeSpec{lo("3.2.18"), br("4.0", "4.0.5"), br("4.1", "4.1.1")},
		},
		{
			ID: "CVE-2013-0333", Severity: "critical",
			Title:       "JSON parser YAML conversion allows remote code execution",
			Description: "The JSON backend in Rails 2.3 / 3.0 converts JSON to YAML, allowing object injection and remote code execution.",
			Reference:   nvd + "CVE-2013-0333",
			Affected:    []RangeSpec{lo("2.3.16"), br("3.0", "3.0.20")},
		},
		{
			ID: "CVE-2013-0156", Severity: "critical",
			Title:       "XML parameter parsing allows YAML/Symbol injection (remote code execution)",
			Description: "The XML parameter parser decodes embedded YAML and Symbol types, allowing object injection and remote code execution. Widely exploited.",
			Reference:   nvd + "CVE-2013-0156",
			Affected:    []RangeSpec{lo("2.3.15"), br("3.0", "3.0.19"), br("3.1", "3.1.10"), br("3.2", "3.2.11")},
		},
	},
	"rack": {
		{
			ID: "CVE-2025-46727", Severity: "high",
			Title:       "Unbounded parameter parsing in Rack::QueryParser",
			Description: "Rack::QueryParser places no limit on the number of parameters, so a request with very many parameters exhausts memory/CPU.",
			Reference:   nvd + "CVE-2025-46727",
			Affected:    []RangeSpec{lo("2.2.14"), br("3.0", "3.0.16"), br("3.1", "3.1.14")},
		},
		{
			ID: "CVE-2025-27610", Severity: "high",
			Title:       "Local file inclusion in Rack::Static",
			Description: "Rack::Static does not sanitise encoded path traversal sequences, exposing files under the configured root outside the intended static prefixes.",
			Reference:   nvd + "CVE-2025-27610", Note: "requires Rack::Static with a :root that contains sensitive files",
			Affected: []RangeSpec{lo("2.2.13"), br("3.0", "3.0.14"), br("3.1", "3.1.12")},
		},
		{
			ID: "CVE-2025-27111", Severity: "medium",
			Title:       "Log injection in Rack::Sendfile",
			Description: "Rack::Sendfile logs header values without escaping, allowing forged log entries.",
			Reference:   nvd + "CVE-2025-27111",
			Affected:    []RangeSpec{lo("2.2.12"), br("3.0", "3.0.13"), br("3.1", "3.1.11")},
		},
		{
			ID: "CVE-2024-26146", Severity: "medium",
			Title:       "ReDoS / DoS in Rack header parsing (February 2024 fixes)",
			Description: "Crafted Accept, Range and Content-Type headers cause excessive work in Rack's header and media-type parsers (CVE-2024-26146, CVE-2024-26141, CVE-2024-25126).",
			Reference:   nvd + "CVE-2024-26146",
			Affected:    []RangeSpec{lo("2.2.8.1"), br("3.0", "3.0.9.1")},
		},
		{
			ID: "CVE-2023-27539", Severity: "medium",
			Title:       "Denial of service in Rack header parsing",
			Description: "Crafted header values make Rack's header parser take longer than expected.",
			Reference:   nvd + "CVE-2023-27539",
			Affected:    []RangeSpec{lo("2.2.6.4"), br("3.0", "3.0.6.1")},
		},
		{
			ID: "CVE-2023-27530", Severity: "high",
			Title:       "Denial of service in Rack multipart parsing",
			Description: "The multipart parser does not limit the number of parts, so a crafted body exhausts resources.",
			Reference:   nvd + "CVE-2023-27530",
			Affected:    []RangeSpec{lo("2.0.9.3"), br("2.1", "2.1.4.3"), br("2.2", "2.2.6.3"), br("3.0", "3.0.4.2")},
		},
		{
			ID: "CVE-2022-44570", Severity: "high",
			Title:       "ReDoS in Rack Range / Content-Disposition / multipart parsing (January 2023 fixes)",
			Description: "Crafted Range and Content-Disposition headers and multipart bodies cause catastrophic backtracking (CVE-2022-44570, CVE-2022-44571, CVE-2022-44572).",
			Reference:   nvd + "CVE-2022-44570",
			Affected:    []RangeSpec{lo("2.0.9.2"), br("2.1", "2.1.4.2"), br("2.2", "2.2.6.1"), br("3.0", "3.0.4.1")},
		},
		{
			ID: "CVE-2022-30123", Severity: "critical",
			Title:       "Shell escape sequence injection in Rack::Lint / Rack::CommonLogger",
			Description: "Crafted requests inject terminal escape sequences into log output written by Rack::Lint and Rack::CommonLogger.",
			Reference:   nvd + "CVE-2022-30123",
			Affected:    []RangeSpec{lo("2.0.9.1"), br("2.1", "2.1.4.1"), br("2.2", "2.2.3.1")},
		},
		{
			ID: "CVE-2022-30122", Severity: "high",
			Title:       "Denial of service in Rack multipart parsing",
			Description: "Crafted multipart POST requests cause super-linear parsing time.",
			Reference:   nvd + "CVE-2022-30122",
			Affected:    []RangeSpec{lo("2.0.9.1"), br("2.1", "2.1.4.1"), br("2.2", "2.2.3.1")},
		},
		{
			ID: "CVE-2020-8184", Severity: "high",
			Title:       "Cookie prefix spoofing via percent-decoded cookie names",
			Description: "Rack percent-decodes cookie names, letting an attacker forge __Host-/__Secure- prefixed cookies.",
			Reference:   nvd + "CVE-2020-8184",
			Affected:    []RangeSpec{lo("2.1.4"), br("2.2", "2.2.3")},
		},
		{
			ID: "CVE-2020-8161", Severity: "high",
			Title:       "Directory traversal in Rack::Directory",
			Description: "Rack::Directory can be made to list and serve files outside its configured root.",
			Reference:   nvd + "CVE-2020-8161", Note: "requires the Rack::Directory app",
			Affected: []RangeSpec{lo("2.1.3")},
		},
		{
			ID: "CVE-2019-16782", Severity: "medium",
			Title:       "Session hijacking via timing attack on session id lookup",
			Description: "Session ids are looked up by direct comparison in the store, enabling a timing attack to recover a valid id.",
			Reference:   nvd + "CVE-2019-16782",
			Affected:    []RangeSpec{lo("1.6.12"), br("2.0", "2.0.8")},
		},
	},
	"sinatra": {
		{
			ID: "CVE-2024-21510", Severity: "medium",
			Title:       "Open redirect via X-Forwarded-Host",
			Description: "Sinatra trusts X-Forwarded-Host when building redirect URLs, enabling open redirects and cache poisoning.",
			Reference:   nvd + "CVE-2024-21510",
			Affected:    []RangeSpec{lo("4.1.0")},
		},
		{
			ID: "CVE-2022-45442", Severity: "high",
			Title:       "Reflected file download via Content-Disposition",
			Description: "User-supplied filenames are not escaped in the Content-Disposition header set by send_file / attachment.",
			Reference:   nvd + "CVE-2022-45442",
			Affected:    []RangeSpec{rng("2.0.0", "2.2.3"), br("3.0", "3.0.4")},
		},
		{
			ID: "CVE-2022-29970", Severity: "high",
			Title:       "Path traversal when serving static files",
			Description: "Sinatra does not validate that the expanded static file path stays inside the public directory.",
			Reference:   nvd + "CVE-2022-29970",
			Affected:    []RangeSpec{lo("2.2.0")},
		},
		{
			ID: "CVE-2018-11627", Severity: "medium",
			Title:       "XSS via the 400 Bad Request page",
			Description: "Invalid parameter values are reflected unescaped in the default 400 page.",
			Reference:   nvd + "CVE-2018-11627",
			Affected:    []RangeSpec{lo("2.0.2")},
		},
	},
	"passenger": {
		{
			ID: "CVE-2025-26803", Severity: "high",
			Title:       "Denial of service in the Phusion Passenger HTTP parser",
			Description: "A malformed HTTP request can crash or hang the Passenger agent.",
			Reference:   nvd + "CVE-2025-26803",
			Affected:    []RangeSpec{rng("6.0.21", "6.0.26")},
		},
		{
			ID: "CVE-2018-12029", Severity: "high",
			Title:       "Local privilege escalation / information disclosure in Phusion Passenger (June 2018 fixes)",
			Description: "A set of issues (CVE-2018-12026 … CVE-2018-12029) let a malicious application on the same host escalate privileges or read other applications' data.",
			Reference:   nvd + "CVE-2018-12029", Note: "local attacker / shared hosting",
			Affected: []RangeSpec{lo("5.3.2")},
		},
		{
			ID: "CVE-2015-7519", Severity: "low",
			Title:       "Header spoofing via underscore/dash confusion",
			Description: "Passenger normalises dashes to underscores in header names, letting a client overwrite headers set by a front proxy.",
			Reference:   nvd + "CVE-2015-7519",
			Affected:    []RangeSpec{lo("4.0.60"), br("5.0", "5.0.22")},
		},
	},

	// ---- Applications ----
	"gitlab": {
		ruby2Bundled("GitLab", "19.6.0", "3.3.13", "19.6.1"),
		{
			ID: "CVE-2023-7028", Severity: "critical",
			Title:       "Account takeover via password reset to an unverified e-mail address",
			Description: "Password reset e-mails can be delivered to an attacker-supplied address, allowing account takeover without interaction.",
			Reference:   nvd + "CVE-2023-7028",
			Affected: []RangeSpec{br("16.1", "16.1.6"), br("16.2", "16.2.9"), br("16.3", "16.3.7"), br("16.4", "16.4.5"),
				br("16.5", "16.5.6"), br("16.6", "16.6.4"), br("16.7", "16.7.2")},
		},
		{
			ID: "CVE-2024-45409", Severity: "critical",
			Title:       "SAML authentication bypass (ruby-saml signature verification)",
			Description: "GitLab instances with SAML authentication can be logged into as any user: the bundled ruby-saml library does not properly verify the signature of the SAML response.",
			Reference:   nvd + "CVE-2024-45409", Note: "only instances with SAML sign-in configured",
			Affected: []RangeSpec{lo("16.11.10"), br("17.0", "17.0.8"), br("17.1", "17.1.8"), br("17.2", "17.2.7"), br("17.3", "17.3.3")},
		},
		{
			ID: "CVE-2024-6385", Severity: "critical",
			Title:       "Pipelines can be run as an arbitrary user",
			Description: "An attacker can trigger a pipeline as another user under certain circumstances.",
			Reference:   nvd + "CVE-2024-6385",
			Affected:    []RangeSpec{rng("15.8.0", "16.11.6"), br("17.0", "17.0.4"), br("17.1", "17.1.2")},
		},
		{
			ID: "CVE-2024-5655", Severity: "critical",
			Title:       "Pipelines can be run as another user",
			Description: "An attacker can trigger a pipeline as another user under certain circumstances.",
			Reference:   nvd + "CVE-2024-5655",
			Affected:    []RangeSpec{rng("15.8.0", "16.11.5"), br("17.0", "17.0.3"), br("17.1", "17.1.1")},
		},
		{
			ID: "CVE-2023-5009", Severity: "critical",
			Title:       "Scan execution policies can run pipelines as an arbitrary user",
			Description: "An attacker can run pipelines as an arbitrary user through scheduled security scan policies (a bypass of CVE-2023-3932).",
			Reference:   nvd + "CVE-2023-5009", Note: "GitLab Enterprise Edition",
			Affected: []RangeSpec{rng("13.12.0", "16.2.7"), br("16.3", "16.3.4")},
		},
		{
			ID: "CVE-2023-2825", Severity: "critical",
			Title:       "Unauthenticated path traversal — arbitrary file read",
			Description: "An unauthenticated user can read arbitrary files on the server when an attachment exists in a public project nested within at least five groups.",
			Reference:   nvd + "CVE-2023-2825",
			Affected:    []RangeSpec{{Equals: "16.0.0"}},
		},
		{
			ID: "CVE-2022-2884", Severity: "critical",
			Title:       "Remote command execution via GitHub import",
			Description: "An authenticated user can achieve remote code execution through the Import from GitHub API endpoint.",
			Reference:   nvd + "CVE-2022-2884", Note: "requires an authenticated user",
			Affected: []RangeSpec{rng("11.3.4", "15.1.5"), br("15.2", "15.2.3"), br("15.3", "15.3.1")},
		},
		{
			ID: "CVE-2021-22214", Severity: "high",
			Title:       "Unauthenticated SSRF through the CI Lint API",
			Description: "When requests to the internal network for webhooks are enabled, an unauthenticated attacker can make the server send requests through the CI Lint API.",
			Reference:   nvd + "CVE-2021-22214",
			Affected:    []RangeSpec{rng("10.5.0", "13.10.5"), br("13.11", "13.11.5"), br("13.12", "13.12.2")},
		},
		{
			ID: "CVE-2021-22205", Severity: "critical",
			Title:       "Unauthenticated remote code execution via image upload (ExifTool)",
			Description: "Uploaded image files are passed to ExifTool without proper validation, allowing unauthenticated remote command execution. Exploited in the wild.",
			Reference:   nvd + "CVE-2021-22205",
			Affected:    []RangeSpec{rng("11.9.0", "13.8.8"), br("13.9", "13.9.6"), br("13.10", "13.10.3")},
		},
	},
	"mastodon": {
		ruby2Bundled("Mastodon", "4.7.5", "4.0.9", "4.7.6"),
		{
			ID: "CVE-2024-23832", Severity: "critical",
			Title:       "Remote account impersonation and takeover",
			Description: "Insufficient origin validation lets an attacker impersonate and take over any remote account.",
			Reference:   nvd + "CVE-2024-23832",
			Affected:    []RangeSpec{lo("3.5.17"), br("4.0", "4.0.13"), br("4.1", "4.1.13"), br("4.2", "4.2.5")},
		},
		{
			ID: "CVE-2024-25623", Severity: "high",
			Title:       "Insufficient Content-Type validation when fetching remote statuses",
			Description: "Mastodon does not check that a fetched remote resource is served with an ActivityPub media type, which lets an attacker who can upload files to a remote server impersonate its accounts.",
			Reference:   nvd + "CVE-2024-25623",
			Affected:    []RangeSpec{lo("3.5.19"), br("4.0", "4.0.15"), br("4.1", "4.1.15"), br("4.2", "4.2.7")},
		},
		{
			ID: "CVE-2023-36459", Severity: "critical",
			Title:       "XSS through oEmbed preview cards",
			Description: "Crafted oEmbed data bypasses HTML sanitisation in preview cards, allowing arbitrary HTML to be injected into pages viewed by other users.",
			Reference:   nvd + "CVE-2023-36459",
			Affected:    []RangeSpec{rng("1.3.0", "3.5.9"), br("4.0", "4.0.5"), br("4.1", "4.1.3")},
		},
		{
			ID: "CVE-2023-36460", Severity: "critical",
			Title:       "Arbitrary file creation through media attachments",
			Description: "Crafted media files make the media-processing code create files at arbitrary locations, leading to denial of service or remote code execution.",
			Reference:   nvd + "CVE-2023-36460",
			Affected:    []RangeSpec{rng("3.5.0", "3.5.9"), br("4.0", "4.0.5"), br("4.1", "4.1.3")},
		},
	},
	"discourse": {
		ruby2Bundled("Discourse", "2026.10.1", "3.4.7", "2026.10.2"),
		{
			ID: "CVE-2021-41163", Severity: "critical",
			Title:       "Remote code execution via crafted SNS subscription payload",
			Description: "A maliciously crafted request to the AWS SNS webhook endpoint leads to remote code execution, due to missing validation of subscribe_url.",
			Reference:   nvd + "CVE-2021-41163",
			Affected:    []RangeSpec{lo("2.7.9")},
		},
	},
	"github enterprise server": {
		ruby2Bundled("GitHub Enterprise Server", "3.22.5", "4.0.9", "3.22.6"),
		{
			ID: "CVE-2024-9487", Severity: "critical",
			Title:       "SAML SSO authentication bypass",
			Description: "Improper verification of cryptographic signatures lets an attacker bypass SAML single sign-on when the encrypted assertions feature is enabled.",
			Reference:   nvd + "CVE-2024-9487", Note: "requires SAML SSO with encrypted assertions, network access and a signed SAML response or metadata document",
			Affected: []RangeSpec{lo("3.11.16"), br("3.12", "3.12.10"), br("3.13", "3.13.5"), br("3.14", "3.14.2")},
		},
		{
			ID: "CVE-2024-4985", Severity: "critical",
			Title:       "SAML SSO authentication bypass via forged response",
			Description: "With SAML single sign-on and the optional encrypted assertions feature, an attacker can forge a SAML response to provision or gain access to a user with site administrator privileges.",
			Reference:   nvd + "CVE-2024-4985", Note: "requires SAML SSO with encrypted assertions enabled",
			Affected: []RangeSpec{lo("3.9.15"), br("3.10", "3.10.12"), br("3.11", "3.11.10"), br("3.12", "3.12.4")},
		},
	},
	"openproject": {
		ruby2Bundled("OpenProject", "17.9.7", "4.0.9", "17.9.8"),
	},
	"chatwoot": {
		ruby2Bundled("Chatwoot", "4.20.0", "3.4.4", "4.20.1"),
	},
}

// builtinPackages is the curated catalogue for gems, keyed by gem name. It is
// matched against a Gemfile.lock inventory and against gem versions leaked in
// backtrace paths or server banners.
var builtinPackages = map[string][]FeedEntry{
	"puma": {
		{
			ID: "CVE-2024-45614", Severity: "medium",
			Title:       "Proxy-set headers can be clobbered via underscore variants",
			Description: "Clients can override headers set by a front proxy (e.g. X-Forwarded-For) by sending the underscore form.",
			Reference:   nvd + "CVE-2024-45614",
			Affected:    []RangeSpec{lo("5.6.9"), rng("6.0.0", "6.4.3")},
		},
		{
			ID: "CVE-2024-21647", Severity: "high",
			Title:       "HTTP request smuggling / DoS via chunked extensions",
			Description: "Puma does not bound the size of chunk extensions, allowing resource exhaustion and smuggling behind some proxies.",
			Reference:   nvd + "CVE-2024-21647",
			Affected:    []RangeSpec{lo("5.6.8"), rng("6.0.0", "6.4.2")},
		},
		{
			ID: "CVE-2023-40175", Severity: "critical",
			Title:       "HTTP request smuggling via chunked bodies and zero-length Content-Length",
			Description: "Incorrect parsing of chunked transfer encoding and Content-Length headers allows HTTP request smuggling.",
			Reference:   nvd + "CVE-2023-40175",
			Affected:    []RangeSpec{lo("5.6.7"), rng("6.0.0", "6.3.1")},
		},
		{
			ID: "CVE-2022-24790", Severity: "critical",
			Title:       "HTTP request smuggling behind non-RFC-compliant proxies",
			Description: "Puma's lenient HTTP parsing allows request smuggling when deployed behind a proxy that forwards malformed requests.",
			Reference:   nvd + "CVE-2022-24790",
			Affected:    []RangeSpec{lo("4.3.12"), rng("5.0.0", "5.6.4")},
		},
	},
	"webrick": {
		{
			ID: "CVE-2024-47220", Severity: "high",
			Title:       "HTTP request smuggling in WEBrick",
			Description: "WEBrick accepts requests carrying both Content-Length and Transfer-Encoding, enabling request smuggling.",
			Reference:   nvd + "CVE-2024-47220",
			Affected:    []RangeSpec{lo("1.8.2")},
		},
	},
	"sidekiq": {
		{
			ID: "CVE-2024-32887", Severity: "medium",
			Title:       "Reflected XSS in the Sidekiq Web UI",
			Description: "The substr parameter of the Web UI filter is reflected without escaping.",
			Reference:   nvd + "CVE-2024-32887",
			Affected:    []RangeSpec{rng("7.2.0", "7.2.4")},
		},
		{
			ID: "CVE-2022-23837", Severity: "high",
			Title:       "Denial of service in the Sidekiq Web UI",
			Description: "The dashboard's graph API accepts an unbounded number of days, letting an attacker exhaust the server.",
			Reference:   nvd + "CVE-2022-23837",
			Affected:    []RangeSpec{lo("5.2.10"), rng("6.0.0", "6.4.0")},
		},
	},
	"devise": {
		{
			ID: "CVE-2019-5421", Severity: "critical",
			Title:       "Lockable module race condition allows unlimited password attempts",
			Description: "Concurrent requests bypass the failed-attempts counter of the lockable module, enabling brute force.",
			Reference:   nvd + "CVE-2019-5421",
			Affected:    []RangeSpec{lo("4.6.0")},
		},
	},
	"ruby-saml": {
		{
			ID: "CVE-2025-25291", Severity: "critical",
			Title:       "SAML authentication bypass via parser differential",
			Description: "ReXML and Nokogiri parse a crafted SAML response differently, enabling signature wrapping and authentication bypass (also CVE-2025-25292).",
			Reference:   nvd + "CVE-2025-25291",
			Affected:    []RangeSpec{lo("1.12.4"), rng("1.13.0", "1.18.0")},
		},
		{
			ID: "CVE-2024-45409", Severity: "critical",
			Title:       "SAML signature verification bypass",
			Description: "ruby-saml does not properly verify the signature of the SAML response, letting an unauthenticated attacker forge an assertion and log in as any user.",
			Reference:   nvd + "CVE-2024-45409",
			Affected:    []RangeSpec{lo("1.12.3"), rng("1.13.0", "1.17.0")},
		},
	},
	"omniauth": {
		{
			ID: "CVE-2015-9284", Severity: "high",
			Title:       "CSRF in the OmniAuth request phase",
			Description: "The request phase is reachable with GET and lacks CSRF protection, enabling login CSRF / account linking attacks.",
			Reference:   nvd + "CVE-2015-9284",
			Affected:    []RangeSpec{lo("2.0.0")},
		},
	},
	"rexml": {
		{
			ID: "CVE-2024-49761", Severity: "high",
			Title:       "ReDoS in REXML",
			Description: "Parsing XML with many digits between &# and x…; in a hex character reference causes catastrophic backtracking.",
			Reference:   nvd + "CVE-2024-49761", Note: "Ruby 3.2+ is not affected",
			Affected: []RangeSpec{lo("3.3.9")},
		},
		{
			ID: "CVE-2024-35176", Severity: "medium",
			Title:       "Denial of service in REXML",
			Description: "XML with many < characters in an attribute value takes excessive time to parse.",
			Reference:   nvd + "CVE-2024-35176",
			Affected:    []RangeSpec{lo("3.2.7")},
		},
	},
	"json": {
		{
			ID: "CVE-2020-10663", Severity: "high",
			Title:       "Unsafe object creation in JSON",
			Description: "The json gem can be coerced into creating arbitrary objects when parsing crafted documents.",
			Reference:   nvd + "CVE-2020-10663",
			Affected:    []RangeSpec{lo("2.3.0")},
		},
	},
	"carrierwave": {
		{
			ID: "CVE-2021-21305", Severity: "high",
			Title:       "Code injection through image manipulation arguments",
			Description: "User-controlled arguments passed to CarrierWave::RMagick#manipulate! are evaluated, allowing code execution.",
			Reference:   nvd + "CVE-2021-21305",
			Affected:    []RangeSpec{lo("1.3.2"), rng("2.0.0", "2.1.1")},
		},
		{
			ID: "CVE-2021-21288", Severity: "medium",
			Title:       "Server-side request forgery in the remote download feature",
			Description: "The download feature can be pointed at internal addresses.",
			Reference:   nvd + "CVE-2021-21288",
			Affected:    []RangeSpec{lo("1.3.2"), rng("2.0.0", "2.1.1")},
		},
	},
	"paperclip": {
		{
			ID: "CVE-2017-0889", Severity: "critical",
			Title:       "Server-side request forgery in Paperclip URI adapters",
			Description: "Attachments fetched from user-supplied URLs can target internal services.",
			Reference:   nvd + "CVE-2017-0889",
			Affected:    []RangeSpec{lo("5.2.0")},
		},
	},
	"image_processing": {
		{
			ID: "CVE-2022-24720", Severity: "critical",
			Title:       "Remote shell execution via #apply",
			Description: "Passing user input to ImageProcessing's #apply (as Active Storage variants did) allows calling arbitrary methods, including shell execution.",
			Reference:   nvd + "CVE-2022-24720",
			Affected:    []RangeSpec{lo("1.12.2")},
		},
	},
	"mini_magick": {
		{
			ID: "CVE-2019-13574", Severity: "high",
			Title:       "Remote command execution via crafted image URL",
			Description: "MiniMagick::Image.open passes a remote file name to Kernel#open, so a URL beginning with a pipe executes a command.",
			Reference:   nvd + "CVE-2019-13574",
			Affected:    []RangeSpec{lo("4.9.4")},
		},
	},
	"rubyzip": {
		{
			ID: "CVE-2018-1000544", Severity: "critical",
			Title:       "Directory traversal (Zip Slip) on extraction",
			Description: "Entries with absolute or traversing paths are written outside the extraction directory.",
			Reference:   nvd + "CVE-2018-1000544",
			Affected:    []RangeSpec{lo("1.2.2")},
		},
	},
	"rails-html-sanitizer": {
		{
			ID: "CVE-2022-32209", Severity: "medium",
			Title:       "Possible XSS with certain allowed-tag configurations",
			Description: "Allowing both select and style elements lets crafted input bypass the sanitizer.",
			Reference:   nvd + "CVE-2022-32209",
			Affected:    []RangeSpec{lo("1.4.3")},
		},
	},
	"kaminari": {
		{
			ID: "CVE-2020-11082", Severity: "medium",
			Title:       "XSS via the original_script_name parameter",
			Description: "Pagination links honour an attacker-supplied original_script_name parameter, allowing a malicious host to be injected.",
			Reference:   nvd + "CVE-2020-11082",
			Affected:    []RangeSpec{lo("1.2.1")},
		},
	},
	"rack-cors": {
		{
			ID: "CVE-2019-18978", Severity: "medium",
			Title:       "CORS restriction bypass via path traversal",
			Description: "Unnormalised request paths let a request match a more permissive CORS resource rule.",
			Reference:   nvd + "CVE-2019-18978",
			Affected:    []RangeSpec{lo("1.0.4")},
		},
	},
	"administrate": {
		{
			ID: "CVE-2020-5257", Severity: "medium",
			Title:       "SQL injection through the sort direction parameter",
			Description: "The direction parameter of dashboard sorting is interpolated into the ORDER BY clause.",
			Reference:   nvd + "CVE-2020-5257",
			Affected:    []RangeSpec{lo("0.13.0")},
		},
	},
}

// builtinEOL maps a Ruby release branch to the date its security maintenance
// ended (or is scheduled to end). Source: ruby-lang.org maintenance branches.
var builtinEOL = map[string]string{
	"2.0": "2016-02-24",
	"2.1": "2017-03-31",
	"2.2": "2018-03-31",
	"2.3": "2019-03-31",
	"2.4": "2020-03-31",
	"2.5": "2021-04-05",
	"2.6": "2022-04-12",
	"2.7": "2023-03-31",
	"3.0": "2024-04-23",
	"3.1": "2025-03-26",
	"3.2": "2026-03-31",
	"3.3": "2027-03-31",
	"3.4": "2028-03-31",
	"4.0": "2029-03-31",
}
