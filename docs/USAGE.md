# qrubyscanner — Usage

`qrubyscanner` detects whether network services are backed by Ruby, collects the
evidence behind each verdict, and produces reports. It runs as a one-shot CLI
or as a local web GUI.

> **Authorised use only.** Only scan hosts and networks you own or are
> explicitly permitted to test.

## Contents

- [Synopsis](#synopsis)
- [Targets](#targets)
- [Ports](#ports)
- [TLS](#tls)
- [Scan depth](#scan-depth-detect-vs-deep)
- [Output formats](#output-formats)
- [Report formats](#report-formats)
- [Configuration file](#configuration-file)
- [Web GUI](#web-gui)
- [Resume](#resume)
- [Audit trail (PCAP and session log)](#audit-trail-pcap-and-session-log)
- [Exit status](#exit-status)
- [Examples](#examples)
- [Interpreting results](#interpreting-results)

## Synopsis

```
qrubyscanner [options] <target> [target ...]
qrubyscanner --web [--listen host:port]
qrubyscanner --config scan.yaml
```

Run `qrubyscanner --help` for the full flag list.

## Targets

Targets are given as positional arguments (or in the config file / web form).
Each target may be any of:

| Form | Example |
| --- | --- |
| URL | `https://example.com/` |
| IPv4 literal | `203.0.113.10` |
| IPv6 literal | `2001:db8::1` or `[2001:db8::1]` |
| IPv4 CIDR | `10.0.0.0/24` |
| IPv6 CIDR | `2001:db8::/120` |
| Dashed range (last octet) | `192.168.1.10-20` |
| Dashed range (full) | `10.0.0.1-10.0.0.50`, `2001:db8::1-2001:db8::ff` |
| Wildcard | `192.168.1.*`, `10.0.*.*`, `2001:db8::*` (IPv6 trailing group) |
| DNS wildcard | `*.example.com` |
| Hostname | `example.com` |

Targets may also be read from a file or stdin with `--targets-file FILE`
(alias `-iL`), one per line; blank lines and `#` comments are ignored. Use `-`
to read from stdin. File targets are added to any given on the command line.

When a target is a **URL**, its scheme, port and path are honoured: that exact
endpoint is scanned (and `--ports` is ignored for it). All other target forms
are scanned across the selected port set.

A **DNS wildcard** (`*.example.com`) is expanded by querying Certificate
Transparency logs (crt.sh) for names issued under the domain; the discovered
hosts are then scanned across the selected ports. Quote it in a shell
(`'*.example.com'`) so the shell does not glob it. Disable this with
`--no-dns-enum`. If the lookup fails (e.g. the CT service is unreachable), the
spec is skipped with a progress message and the rest of the scan continues.

A single spec is capped at `--max-hosts` (default 65 536) expanded hosts to
guard against an accidental huge range.

## Ports

`--ports` accepts single ports, comma-separated lists, inclusive ranges, and
any mixture:

```
--ports 80
--ports 80,443,8080
--ports 8000-8100
--ports 80,443,8000-8010,9000
```

With no `--ports`, a built-in common-web-port set is used:
`80, 443, 8000, 8008, 8080, 8443, 8888, 3000, 5000, 9000`.

## TLS

`--tls` controls whether services are probed over HTTPS:

- `auto` (default) — infer from the port (443/8443/9443/4443/10443 ⇒ HTTPS),
  and fall back to the other scheme if the first attempt yields no HTTP
  response.
- `on` — force HTTPS.
- `off` — force HTTP.

A URL target's own scheme always wins. Use `--insecure` to probe hosts with
self-signed or otherwise invalid certificates.

## Scan depth: detect vs deep

- `--mode detect` — decide **whether** each service is Ruby and record
  the evidence. Fast; one request per service (plus security.txt).
- `--mode deep` (default) — additionally fetch a small set of read-only probe paths
  (`/rails/info/properties`, `/up`, the Rails static error pages,
  `/Gemfile.lock`, `/.ruby-version`, `/config.ru`, …), a guaranteed-404 and
  three behavioural probes (Rack's query parser, `X-Request-Id` sanitisation,
  an unknown HTTP method), to fingerprint the **Ruby
  version**, **variant** (CRuby / JRuby / TruffleRuby), **frameworks**,
  **gems**, **app server**, end-of-life status, and to correlate **known
  version-based vulnerabilities** — including
  [Ruby2Shell](#ruby2shell-ghsa-34m4-m9fh-gqp5).

All probes are body-less, read-only requests (GET, one `OPTIONS`, and one with
the made-up method `QRUBYSCAN`); nothing is submitted and nothing is exploited.

The behavioural probes, each gated against the soft-404 baseline:

| Probe | Ruby behaviour | Signal |
| --- | --- | --- |
| `/?p[]=1&p[k]=1` | Rack rejects a parameter declared as array *and* hash; Rails/Sinatra answer 400 | `behavior.rack-param-type` |
| `X-Request-Id: qruby.scan!1-@probe_x` | Rails echoes it as `qrubyscan1-@probe_x` (only word characters, `-`, `@` kept) | `behavior.rails-request-id` |
| `QRUBYSCAN /` | Puma answers a bare `501` with an empty body | `behavior.puma-unknown-method` |

Deep discovery is **adaptive**: after the base and core responses, an
application's probe paths (Rails dashboards, GitLab, Mastodon, Discourse,
Chatwoot, GitHub Enterprise, Foreman) are requested only once that application
is indicated, and generic Ruby discovery is skipped against a clearly non-Ruby
runtime. `--request-budget N`
caps the optional probes per service (0 = no cap), and a host returning
`429`/`503` makes the optional probes back off entirely. When discovery stops
early the result's `discovery_limited` field records why (`budget` or
`rate-limited`).

## Output formats

`--format` selects the machine-readable scan output, written to stdout or to
`--out FILE`:

- `text` (default) — the same layout as the text report.
- `json` — a structured document (see `docs/DESIGN.md` for the schema).
- `xml` — the same data as XML, rooted at `<scan>`.
- `csv` — one row per service, for spreadsheets and quick triage.
- `sarif` — SARIF 2.1.0, for CI and security-tooling ingestion.
- `ndjson` — one JSON object per service (a leading meta line), for streaming.

If `--out` ends in `.json`/`.xml`/`.txt` the format is inferred from the
extension (unless `--format` is given explicitly).

`--oA BASE` writes every machine output plus an HTML report at once:
`BASE.json`, `BASE.xml`, `BASE.csv`, `BASE.sarif`, `BASE.txt` and `BASE.html`.

## Report formats

A report is a human-readable write-up (summary, per-host sections, evidence,
vulnerability leads, security.txt). Produce one with `--report` and/or
`--report-out`:

- `--report text` — write to stdout (or to `--report-out`).
- `--report rtf --report-out report.rtf` — Rich Text, opens in Word/LibreOffice.
- `--report pdf --report-out report.pdf` — PDF.
- `--report html --report-out report.html` — self-contained HTML.

`rtf`, `pdf` and `html` require `--report-out`. If only `--report-out` is
given, the format is inferred from the file extension.

The scan output (`--format`) and the report (`--report`) are independent — you
can request both in one run.

## Progress and verbosity

By default qrubyscanner shows live progress on **stderr** (so it never mixes
with machine output on stdout):

- On a terminal, a single counter line is redrawn in place:
  `scanning… 128/2560 (open 12, ruby 4)`.
- When stderr is redirected, the counter is emitted as occasional full lines
  instead.
- Subdomain-enumeration steps are printed as `[*] …` lines.

`--verbose` (or `-v`) replaces the counter with one line per service — open
ports, Ruby verdicts and versions, and closed/filtered ports — plus the
enumeration steps:

```
[*] enumerating subdomains for example.com via certificate transparency…
[*] found 37 host(s) for example.com
[+] www.example.com:443 open http ruby=confirmed 3.3.6
[+] api.example.com:80 open http
[-] legacy.example.com:80 closed/filtered
```

`--quiet` (or `-q`) suppresses progress entirely. A one-line summary is always
printed to stderr when the scan finishes.

## Configuration file

`--config FILE` loads settings from a small YAML file. It has **full parity**
with the command line: every option — politeness (including
`host_concurrency`), enrichment, auth/headers (a list or a map), vulnerability
feeds, favicon catalogues, the audit trail (`pcap`/`log`) and `web.auth` — is
settable from the config. See
[`../config.example.yaml`](../config.example.yaml) for the full annotated
schema. Precedence, highest first:

1. Explicit command-line flags.
2. Values in the config file.
3. Built-in defaults.

Positional CLI targets override the config's `targets` list.

## Web GUI

```
qrubyscanner --web                       # http://127.0.0.1:8088/
qrubyscanner --web --listen 0.0.0.0:9000 # bind elsewhere (use with care)
```

The GUI offers a form (targets, ports, depth, TLS, timeout, concurrency and
toggles), shows a **progress bar and live feed** while scanning (with a
**Cancel** button that aborts the run), renders per-service result cards with
colour-coded Ruby verdicts, evidence and vulnerability leads, and keeps
**previous scans below the current one as collapsible, server-persisted
entries** — each with its own download links. Downloads cover JSON, XML, CSV,
SARIF, text, HTML, RTF and PDF, named uniquely with the scan's timestamp.

The targets box supports **bulk loading from a file** ("Load from file…"):
one or more local lists are read in the browser (nothing is uploaded) and
their lines appended, with `#` comments and blanks skipped. An **Allow / block
lists** section lets you override the target list (keep only matching hosts,
or drop matching hosts). The results area is **resizable**, and each result
card shows the **DNS name** and any resolved **A/PTR** records at its top.

The GUI has four tabs:

- **Scan** — configure and run a scan, watch progress, browse results and the
  previous-scan history. Results stream in live and are split into three
  sub-tabs with live counts: **Results** (services that answered), **Ruby**
  (only services classified as Ruby), and **Failures** (closed or filtered
  ports, connection errors, timeouts, open non-HTTP ports). If a scan errors,
  times out or is **cancelled**, whatever was collected so far stays on
  screen — it is never wiped — and a banner explains what happened. A **sort**
  control orders the Results and Ruby tabs by scan order, with Ruby services
  (highest confidence first) on top, or with the most critical vulnerability
  leads on top; on the Failures tab it instead groups by failure type (i/o
  timeouts first, then other errors). Most controls have **mouse-over help**.
- **Compare** — pick any two retained scans (or an older one against the
  latest), **or load a previously saved scan file (JSON or XML)** as the
  baseline, and see added/removed services and per-service verdict, version
  and vulnerability changes.
- **Statistics** — figures aggregated across all retained scans, with **pie
  and bar charts**: vulnerability-lead severities and Ruby verdicts as pies;
  top vulnerabilities, top applications and top networks as bars; plus
  highest severity, oldest Ruby/application version and average scan time.
- **Info** — a findings explorer: every framework, addon/tool and
  vulnerability as a tag; click one to list the scan items that carry it.

Protect the GUI with `--web-auth user:pass` (HTTP Basic auth). It is bound to
localhost by default; exposing it to a network makes a scan trigger available
to anyone who can reach it, so do so only on trusted networks and with auth.

### HTTP API

The GUI is backed by a tiny JSON API you can script against:

- `POST /api/scan` — body is a JSON object with the same fields as the form
  (`targets` array or `targets_text`, `ports`, `mode`, `tls`,
  `timeout_seconds`, `concurrency`, `follow_redirects`, `insecure`,
  `security_txt`, `include_closed`, `no_dns_enum`). The response is a stream of
  newline-delimited JSON (`application/x-ndjson`): zero or more
  `{"type":"progress","event":{…}}` lines followed by a final
  `{"type":"result","result":{…}}` (or `{"type":"error","error":"…"}`).
- `GET /api/download?format=json|xml|csv|sarif|text|html|rtf|pdf[&scan=<id>]` —
  renders the most recent scan result, or a specific one by `scan` id.
- `GET /api/history` — lists retained scans (newest first) with summaries and
  ids.

## Authentication & request shaping

To scan applications behind auth or virtual hosts:

- `--header "Name: value"` — add a request header (repeatable).
- `--cookie "sid=…"` — send a Cookie header.
- `--bearer TOKEN` — send `Authorization: Bearer TOKEN`.
- `--basic user:pass` — HTTP Basic auth.
- `--vhost HOST` — override the Host header on the initial request (name-based
  virtual hosts on a shared IP). It is not carried across redirects.
- `--proxy URL` — route all requests through an `http(s)://` or
  `socks5://[user:pass@]host:port` proxy.

Cookies and Basic/Bearer credentials are scoped to the original target host:
they are not re-sent if a redirect leads to a different host.

## Connection pinning (IP / Host / SNI)

Control the connection target independently of the URL — useful for reaching an
origin that sits behind a CDN:

- `--resolve HOST:PORT:ADDR` — dial `ADDR` whenever a request would go to
  `HOST:PORT`, like `curl --resolve`. The URL host is preserved for the Host
  header and TLS SNI, so a correct origin certificate still verifies. Repeatable.
- `--sni NAME` — override the TLS SNI server name, independent of the Host
  header. A name that does not match the presented certificate fails
  verification unless `--insecure` is set.

In the web GUI these live under **Connection overrides** on the Scan tab, and
the **Compare** tab has an **Origin check** that scans a target through its
public edge and again pinned to an operator-supplied origin address, then shows
what the origin reveals (Ruby version, apps, headers, exposed diagnostics).

Example — compare a Cloudflare-fronted site against its origin:

    qrubyscanner --mode deep example.com                       # public edge
    qrubyscanner --mode deep --resolve example.com:443:203.0.113.10 \
                --sni example.com example.com                 # origin

## Politeness & rate limiting

- `--rate N` — cap outbound HTTP requests to N per second across the whole scan.
- `--per-host-concurrency N` — at most N concurrent probes against one host.
- `--jitter DUR` — sleep a random time up to DUR before each service probe.
- `--retries N` — retry transient network failures N times with backoff.

## Enrichment

- `--resolve-dns` — record forward addresses and reverse (PTR) names per host.
- `--banners` — for open ports that do not speak HTTP, read a short service
  banner (SSH/FTP/SMTP announce themselves) so the port is labelled.

Every HTTP service is also checked for a **web server** (product/version/OS/
modules) and for a **reverse proxy / CDN / WAF / load balancer** in front.
When a front layer is found the result is flagged as *concealed* — the real
origin reply may be hidden, cached, filtered or challenged — with a note
explaining the implication. Front-layer detection works from response headers
and cookies even in `detect` mode; **deep** mode adds active identification
probes (an `OPTIONS` request, a guaranteed-404 to harvest error-page
signatures and WAF block pages, and status endpoints such as `/server-status`
and `/nginx_status`). Every signal carries a confidence tier (low/medium/high).

## Vulnerability feeds

Deep mode correlates versions against the built-in catalogue. Merge extra data
with `--vuln-feed FILE|URL` (repeatable); feeds override EOL dates by branch.
Three formats are auto-detected:

- the native `qrubyscanner-vuln-feed/1` schema (see
  [`vuln-feed.example.json`](vuln-feed.example.json)),
- **OSV** records (a single object or a JSON array) — e.g. osv.dev / GitHub
  advisory exports for RubyGems packages,
- **CSAF 2.0** advisories — vendor security documents.

Ruby-core advisories feed the Ruby correlation; everything else is keyed by a
normalised framework / application / gem name (rails, rack, puma, gitlab, …).
Versions may carry four components (`7.0.8.1`) or a Ruby patch level
(`2.0.0p594`).

Leads are **qualified, never dropped**. Detection keeps every version
observation with its source and flags a *version conflict* when sources
disagree at the major.minor level (possible multiple backends, a cache or two
apps); distro/backport suffixes are kept verbatim. A lead may carry
**prerequisites** (required framework / app server / OS / gem / environment)
which are resolved against the scan's own evidence to *observed*,
*contradicted* or *unknown*: a contradicted precondition marks the lead
"likely N/A here" (for example a WEBrick-only CVE on a service observed to run
Puma, or a development-mode-only Rails CVE where the environment was observed
to be production). This qualifies
the lead's applicability — it is not an assertion that the service is safe.

## Favicon catalogue

In deep mode the site favicon's mmh3 hash is matched against a built-in
product catalogue and, on a hit, attributes the product and adds evidence.
Extend or override it with `--favicon-catalog FILE|URL` (repeatable); the file
is `{"schema":"qrubyscanner-favicon-catalog/1","favicons":[{"hash":"…",
"product":"…","framework":"…","ruby":true}]}`. An unknown hash is simply inert.

## Signature packs

The built-in detection catalogues (response-header, cookie-name and
response-body matchers) can be extended at run time with a **signature pack** —
a versioned JSON document of the `qrubyscanner-signature-pack/1` schema (see
[`signature-pack.example.json`](signature-pack.example.json)):

    qrubyscanner --mode deep --signature-pack my-stack.json example.com

`--signature-pack FILE|URL` is repeatable (config key `signature_packs`). A pack
has an `id`, an optional `version`, and any of three matcher lists:

- `headers` — `{header, contains?, framework?, ruby?, variant?, weight, detail?}`;
  `contains` is a case-insensitive substring (omit it to match the header's mere
  presence).
- `cookies` — `{name, match?, framework?, weight, detail?}`; `match` is `exact`
  (default) or `prefix`.
- `bodies` — `{id, regex, framework?, ruby?, weight, detail?}`; `regex` is a
  Go/RE2 regular expression.

Packs are **bounded and validated** on load: an unknown schema, a missing `id`,
an unparseable or over-length (> 512-byte) body regex, an unknown cookie `match`
kind, or more than 500 entries in a category rejects the whole pack rather than
loading it partially. Weights are clamped to 0–100 so no pack can swamp the
evidence score, and RE2 runs in linear time (no catastrophic backtracking). The
active packs (`id@version`) are recorded in the scan's provenance metadata, so a
[diff](#diffing-scans) attributes a detection change to a loaded pack rather
than to the target. A pack passed to `--web` at start-up applies to every scan
the GUI runs.

## Ruby2Shell (GHSA-34m4-m9fh-gqp5)

[Ruby2Shell](https://verialabs.com/ruby2shell/) is a one-byte heap overflow in
CRuby's case conversion for single-byte encodings, present since Ruby 2.4.0 and
reachable without authentication in Rails and classic-style Sinatra
applications. `qrubyscanner` never sends anything resembling a trigger — it
decides exposure **from the version alone**:

| Ruby series | Affected | Fixed in |
| --- | --- | --- |
| 4.0 | 4.0.0 – 4.0.9 | 4.0.10 |
| 3.4 | 3.4.0 – 3.4.12 | 3.4.13 |
| 3.3 | 3.3.0 – 3.3.13 | 3.3.14 |
| 3.2 and older | every release back to 2.4.0 | no fix (end of life) |

Deep mode reports one of four outcomes for a Ruby service:

- **critical lead, version-correlation** — a Ruby version was learned (see
  below) and it is in an affected range. The lead's precondition is marked
  *observed* when Rails or Sinatra was also detected.
- **critical lead, branch-correlation** — only the release branch was learned
  (a RubyGems ABI directory such as `…/ruby/3.2.0/gems/…` in a backtrace) and
  *every* release of that branch is affected (3.2 and older).
- **critical lead, bundled Ruby** — a self-hosted product that ships its own
  interpreter was identified at a release the advisory lists as affected
  (GitLab ≤ 19.6.0, GitHub Enterprise Server ≤ 3.22.5, Mastodon ≤ 4.7.5,
  OpenProject ≤ 17.9.7, Discourse ≤ 2026.10.1, Chatwoot ≤ 4.20.0). This is an
  inference from the product version; a Ruby version that was actually
  observed always supersedes it. No fixed vendor releases were listed when the
  catalogue was written — extend it with `--vuln-feed` as they appear.
- **info lead, "version not disclosed"** — Ruby was detected but nothing
  revealed its version, so the issue can be neither confirmed nor ruled out
  remotely. It carries severity `info`, never trips `--fail-on`, and tells you
  to check `ruby -v` on the host.

A patched version (3.3.14+, 3.4.13+, 4.0.10+) produces no lead. JRuby and
TruffleRuby reimplement the core and are not correlated against C-core
advisories.

### Where a Ruby version comes from

Ruby rarely advertises its version, so every available source is used and each
observation is kept with its provenance (`version_observations`):

| Source | Example | Trust |
| --- | --- | --- |
| `/rails/info/properties` | `ruby 3.3.6 (2024-11-05 …) [x86_64-linux]` | running process |
| WEBrick `Server` banner / error-page footer | `WEBrick/1.9.2 (Ruby/3.3.6/2024-11-05)` | running process |
| Rails welcome page, `ruby -v` string in an error page | `Ruby version: ruby 3.3.0 …` | running process |
| `X-Powered-By` / `Server` product token | `Ruby/3.2.2` | running process |
| `/.ruby-version`, `/.tool-versions` | `3.4.13` | declared by the project |
| `Gemfile.lock` `RUBY VERSION`, `Gemfile` `ruby "x.y.z"` | `ruby 3.1.2p20` | declared (lock time) |
| version-manager path in a backtrace | `/.rbenv/versions/3.2.2/…` | declared |
| RubyGems ABI directory in a backtrace | `/bundle/ruby/3.2.0/gems/…` | **branch only** |

When sources disagree at the major.minor level the result is flagged
`version_conflict`. If you already hold the project's lockfile, pass it with
`--gemfile Gemfile.lock` and its recorded Ruby version is used.

## Bundler dependency inventory

In deep mode, an exposed `Gemfile` / `Gemfile.lock` is parsed into a
**dependency inventory** (a partial SBOM). Each gem is classified as *required*
(a constraint from the `Gemfile`), *locked* (`Gemfile.lock` — the concrete
resolved version) or *observed* (a gem directory leaked in a backtrace of the
running application, e.g. `…/gems/actionpack-7.0.8.1/…`). Concrete versions are
correlated against **gem advisories** (built-in, plus a `packages:` map in
`--vuln-feed` data). Rails, Rack, Sinatra and the app server are promoted to
top-level components and correlated there, so they are not double-counted.

For a project whose Bundler files are not web-exposed, supply them directly:

    qrubyscanner --mode deep --gemfile Gemfile.lock --gemfile Gemfile example.com

`--gemfile` is repeatable (config key `bundler_files`); the file kind is
sniffed from its content. The web GUI has an equivalent uploader (read
client-side) under **Gemfile / Gemfile.lock**.

## Exposed secrets

Deep mode also notices project files that should never be web-readable —
`config/master.key`, `config/secrets.yml`, `config/database.yml`, `.env`, Rails
log files — and development tooling left reachable (`/rails/info/routes`,
web-console, better_errors, mailer previews). They are reported as evidence;
**secret values are never copied** into results, reports or the session log.

## Host and service concurrency

`--concurrency` caps total in-flight service probes; `--per-host-concurrency`
caps probes against one host; `--host-concurrency` caps how many distinct hosts
are worked at once (0 = no host cap). Combine them to sweep large target sets
politely — e.g. `--host-concurrency 10 --per-host-concurrency 2`.

## Shell completions

`--completion bash|zsh|fish` prints a completion script generated from the live
flag set:

```sh
# bash
source <(qrubyscanner --completion bash)
# zsh (into a directory on $fpath)
qrubyscanner --completion zsh > ~/.zfunc/_qrubyscanner
# fish
qrubyscanner --completion fish > ~/.config/fish/completions/qrubyscanner.fish
```

## Diffing scans

`--diff baseline.json` compares the current scan against a previously saved
JSON result and prints what changed (new/gone services, version and verdict
changes, new/resolved vulnerability leads). `--diff-format` is `text` (default)
or `json`. With `--diff`, scan output is written only to an explicit `--out`.

The diff is **coverage-aware**: an endpoint that the newer scan did not actually
re-check — a timeout, a WAF challenge, an auth requirement, or a host/port it
never covered — is reported as *not reassessed*, and findings that are merely
absent there are **not** claimed as resolved. A finding only counts as resolved
when its endpoint responded (or was reassessed and found closed). The diff also
emits **provenance notes** when the two scans were run under different settings
(mode, ports, TLS, timeout, auth, connection pinning, or vulnerability-catalogue
size), so a result change caused by the scanner's configuration is not mistaken
for a change on the site. Scans saved before this (no provenance metadata) still
diff cleanly, without provenance notes.

## Resume

`--resume FILE` records each completed service to FILE as it finishes. Re-run
the same command with the same `--resume FILE` to skip already-scanned
services and continue — useful for large or interrupted sweeps.

## Audit trail (PCAP and session log)

For engagements that must be fully auditable, two optional outputs record
exactly what the tool did and why.

`--pcap FILE` writes a **libpcap capture** of every HTTP exchange the scan
performs. Each request/response is reconstructed as a complete TCP conversation
(SYN / SYN-ACK / ACK handshake, PSH/ACK data segments, graceful teardown) with
valid IPv4/TCP checksums, so the file opens directly in Wireshark, tcpdump or
tshark:

```sh
qrubyscanner --mode deep --pcap scan.pcap example.com
tcpdump -nr scan.pcap        # or: wireshark scan.pcap
```

Because probing is passive and HTTPS is terminated locally, the capture holds
the plaintext HTTP that was exchanged (for TLS targets too); packet timing is
approximate and link type is `RAW` (IPv4). Hostnames that are not IP literals
are mapped to stable addresses in `10.0.0.0/8` so the capture stays valid.

`--log FILE` writes a **human-readable session log**. It records each request
and its response headers as they happen, then, per service, a `DECISION` block
that states the web server, any reverse proxy, the Ruby verdict and version, and
— evidence by evidence — *where* each signal was found, *how* it matched, the
probe that produced it, the literal matcher and the matched snippet:

```
DECISION  192.0.2.10:443  https://192.0.2.10:443/
  web server: WEBrick 1.9.2
  Ruby verdict: CONFIRMED (confidence 100/100)
  version: 3.3.6 — learned via Server header (WEBrick banner)
  reasoning — 6 evidence item(s), highest-weighted first:
    • [high w85] header.server — WEBrick, Ruby's standard-library web server
        where: response header 'Server'
        how:   header substring match
        probe: https://192.0.2.10:443/
        matcher: webrick
        match: Server: WEBrick/1.9.2 (Ruby/3.3.6/2024-11-05)
```

Both flags can be combined, and work with any scan mode and target type.

## Record & replay (offline regression harness)

A scan can be captured once and replayed many times with no network, so a real
target becomes a repeatable test case:

```sh
qrubyscanner --mode deep --record-corpus site.corpus.json example.com   # capture
qrubyscanner --replay-corpus site.corpus.json --format json             # re-run offline
```

`--record-corpus FILE` writes a JSON **corpus** (schema
`qrubyscanner-replay-corpus/1`) holding, per service, the exact responses that
were fed to analysis (root, the favicon and Rack parameter probes, the
soft-404 control and every deep-discovery probe). `--replay-corpus FILE` loads
it and runs those responses back through the detection pipeline — no network,
no targets — emitting a scan result exactly as a live run would, so the Ruby
verdict, version, evidence and vulnerability leads are reproduced. It honours
`--vuln-feed`, `--signature-pack`, `--format`/`--report`, `--diff` and
`--fail-on`, so you can confirm a detection or catalogue change behaves the same
against a fixed input, or diff two builds against one corpus.

The corpus is **sanitised on capture**: `Set-Cookie` values, parsed cookie
values (only their *format* — `payload--hmac`, `data--iv--tag` — is kept, as
filler, because that format is itself a Rails/Rack signal) and credential headers (`Authorization`, `Proxy-Authorization`,
`X-Api-Key`, `X-Auth-Token`) are redacted, while the cookie *names* and
attributes that detection keys on are kept. Response bodies are stored verbatim
— they are the fingerprinting material — and round-trip byte-exact (base64), so
binary signals such as the favicon hash replay faithfully; review a corpus
before sharing it. Replay reproduces the Ruby detection and the HTTP summary;
network-only facets of a live scan (port state, service banners, security.txt,
web-server/reverse-proxy identification) are not part of the corpus.

## Exit status

- `0` — the scan completed (regardless of what was found).
- `1` — a fatal error (bad target/port spec, unreadable config/feed, I/O error).
- `2` — the scan completed but a `--fail-on` gate matched (see below).

`--fail-on LEVEL` makes the process exit `2` when a finding meets a threshold:
`low`, `medium`, `high`, `critical` (a vulnerability lead at least that severe)
or `eol` (any end-of-life Ruby branch). Output and reports are still written.
This is for CI gating:

```sh
qrubyscanner --mode deep --fail-on high --format sarif --out scan.sarif example.com || echo "findings!"
```

A one-line summary is printed to stderr after each scan.

## Examples

```sh
# Minimal: is it Ruby?
qrubyscanner --mode detect example.com

# Deep scan with a PDF report
qrubyscanner --mode deep --report-out audit.pdf https://example.com

# Subnet sweep, HTTPS only, JSON to file, no closed-port noise
qrubyscanner --tls on --format json --out results.json 10.0.0.0/24

# Specific ports and a range, text report to stdout
qrubyscanner --ports 80,443,8000-8010 --report text example.com

# IPv6 host, deep, ignore cert errors
qrubyscanner --mode deep --insecure https://[2001:db8::1]:8443/

# Drive everything from a config file
qrubyscanner --config scan.yaml

# Full audit trail: PCAP capture + decision log
qrubyscanner --mode deep --pcap scan.pcap --log scan.log example.com

# Web GUI
qrubyscanner --web
```

## Interpreting results

Each service gets a **verdict** derived from a weighted confidence score
(0–100):

| Verdict | Score | Meaning |
| --- | --- | --- |
| `confirmed` | ≥ 70 | strong, usually unambiguous Ruby evidence |
| `likely` | 50–69 | multiple corroborating signals |
| `possible` | 25–49 | weak/circumstantial signals |
| `none` | < 25 | no meaningful Ruby evidence |

Every contributing signal is listed as **evidence** with its weight, confidence
tier and full provenance — *where* it was found, *how* it matched, the literal
matcher, the matched snippet (with the body line number where applicable) and
the exact probe (method + URL) that produced it — so you can audit *why* a
verdict was reached down to the byte. The same reasoning is written to the
`--log` session log, and every exchange behind it to the `--pcap` capture.

**Vulnerability leads** are correlated from detected versions alone (Ruby, frameworks, gems, bundled products). They
indicate issues that *affect that version*, not that the host is exploitable —
many require a specific framework, app server or configuration (noted in `match_basis`). Always
confirm against the live service before acting.
