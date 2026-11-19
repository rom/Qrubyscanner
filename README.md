# qrubyscanner

A command-line and web tool, written in Go, that scans network ports and
HTTP(S) services to determine whether they are **built on Ruby** (Rails,
Sinatra, any Rack application), collects the supporting **evidence**, and
produces **reports**. In **deep** mode (the default) it also fingerprints the Ruby version,
frameworks, gems and app server, flags end-of-life branches, and correlates
**known version-based vulnerabilities** — including
[**Ruby2Shell**](https://verialabs.com/ruby2shell/) (GHSA-34m4-m9fh-gqp5).

It is the Ruby counterpart of [qphpscanner](https://github.com/rom/qphpscanner)
and shares its architecture, output formats and web GUI. Like its sibling it is
a passive fingerprinting and reporting tool in the spirit of WhatWeb /
Wappalyzer / httpx: it reads banners, headers, cookies and response bodies and
reasons about them. It never attempts to exploit anything.

> **Authorised use only.** Scan only hosts and networks you own or have
> explicit permission to test. Port scanning and service fingerprinting may be
> regulated where you operate.

## Ruby2Shell at a glance

Ruby2Shell is a heap overflow in CRuby's case conversion, present since Ruby
2.4.0 and reachable without authentication in Rails and classic-style Sinatra.
`qrubyscanner` (deep mode, the default) decides exposure **from versions only** — it sends
nothing resembling a trigger:

| Ruby series | Affected | Fixed in |
| --- | --- | --- |
| 4.0 | 4.0.0 – 4.0.9 | 4.0.10 |
| 3.4 | 3.4.0 – 3.4.12 | 3.4.13 |
| 3.3 | 3.3.0 – 3.3.13 | 3.3.14 |
| 3.2 and older | every release back to 2.4.0 | no fix (end of life) |

| What the scan learned | What it reports |
| --- | --- |
| A Ruby version in an affected range | `critical` lead (precondition *observed* when Rails/Sinatra is detected) |
| Only the branch, and the whole branch is affected (≤ 3.2) | `critical` lead, branch-correlation |
| A product that bundles a vulnerable Ruby (GitLab, GitHub Enterprise Server, Mastodon, OpenProject, Discourse, Chatwoot) | `critical` lead, inferred from the product version |
| Ruby, but no version anywhere | `info` lead: *could not be ruled out — check `ruby -v`* |
| A patched Ruby (3.3.14+, 3.4.13+, 4.0.10+) | nothing |

Ruby seldom advertises its version, so the tool looks everywhere it can leak:
`/rails/info/properties`, WEBrick banners and error pages, the Rails welcome
page, `ruby -v` strings and install paths in backtraces, and exposed
`.ruby-version`, `.tool-versions` and `Gemfile.lock` files. If you hold the
project's lockfile, pass it with `--gemfile Gemfile.lock`. See
[`docs/USAGE.md`](docs/USAGE.md#ruby2shell-ghsa-34m4-m9fh-gqp5) for details.

## Features

- **Ruby detection** from many independent signals:
  - **application servers** — WEBrick (whose banner embeds the Ruby version),
    Puma, Thin, Unicorn, Mongrel, Falcon, TorqueBox/Trinidad (JRuby), and
    Phusion Passenger (counted once and only as a medium signal, since it also
    hosts Python and Node.js);
  - **Rack / Rails headers** — `X-Runtime` in Rack::Runtime's exact format,
    `X-Rack-Cache`, `X-Cascade`, the Rack::ETag + Rails `Cache-Control` pair,
    the Rails default security-header set (told apart from Express' helmet),
    asset-pipeline `Link` preloads;
  - **cookies** — `rack.session`, `_<app>_session`, application cookies, and the
    *wire format* of Rails/Rack session cookies (AES-GCM `data--iv--tag`,
    signed `payload--hmac`, Marshal `BAh…`) — the value itself is never stored;
  - **bodies** — Ruby backtraces and exception messages, the Rails exception,
    welcome and static error pages, `authenticity_token`, Sprockets/Propshaft
    digests, Active Storage URLs, Sinatra's "doesn't know this ditty", Rack
    errors, leaked ERB/Ruby source, RubyGems and rbenv/RVM paths;
  - **behaviour** — three harmless probes, gated against a soft-404 baseline:
    Rack's query parser (a parameter declared as both array and hash is
    rejected with 400 by Rails/Sinatra and accepted by everything else);
    `X-Request-Id` sanitisation (Rails echoes a supplied id with everything
    but word characters, `-` and `@` stripped); and an unknown HTTP method
    (Puma answers a bare, empty 501 — which also names the app server of a
    hardened production Rails app);
  - **generator defaults and middleware traces** — Rails' default `icon.svg`
    and `406-unsupported-browser.html`, `Server-Timing` event names, Rack 3
    cookie-attribute casing, Sinatra's default header set, web-console
    headers, Rails JSON/XML error bodies, the "Blocked host" page, Devise and
    I18n messages, Rack::Files / Rack::Attack replies.
- **Rails conventions in ordinary pages** — form-helper output
  (`accept-charset` + hidden Rails fields, `name="commit"`, `button_to`,
  `new_user`/`edit_post_1` ids), `field_with_errors`, `data-method` /
  `data-remote`, the 7.2+ default icon links, Kaminari / will_paginate / Pagy
  markup, Paperclip / Dragonfly / Active Storage URLs, Devise links and flash
  messages, Active Model validation messages, HTTP-auth failure bodies and
  realm, the `redirect_to` body (including on redirect hops), view annotations.
- **Ruby values leaking into output** — `#<User:0x…>` inspect strings,
  hash-rocket `{:a=>1}` dumps, `nil:NilClass`, arity and syntax errors, JRuby
  stack frames, template-engine and database-driver exception classes.
- **More deep-mode probes** — the not-found path again with
  `Accept: application/json` (Rails answers `{"status":404,"error":"Not
  Found"}`), a missing `/assets/` file (the Sprockets/Propshaft server's bare
  "Not found"), `/cable` (Action Cable's "Page not found"), the Propshaft,
  Webpacker and Vite manifests, the default PWA manifest and service worker,
  Sinatra's built-in error image, and up to two JavaScript bundles referenced
  by the page (rails-ujs, Action Cable and Active Storage client code).
- **More project files** — `Dockerfile` (which also yields the Ruby version),
  `Procfile`, `.rubocop.yml` (Ruby branch), `.bundle/config`, `db/schema.rb`,
  `config/application.rb`, `config/routes.rb`, `config/puma.rb`,
  `config/credentials.yml.enc`, the generator's `README.md`.
- **Rails version hint** — when no exact version is disclosed, a range is
  estimated from generation-specific defaults (e.g. "7.2 or later (from
  default icon.svg)"). It is labelled a hint and never used for vulnerability
  correlation.
- **Frameworks and applications**: Rails, Sinatra, Rack, Hanami, Padrino, Roda,
  Grape; GitLab, GitHub Enterprise Server, Discourse, Mastodon, Redmine,
  OpenProject, Chatwoot, diaspora\*, Spree/Solidus, Canvas LMS, Foreman,
  Zammad, Decidim and more — with versions where the product discloses one.
  Static-site generators (Jekyll, Middleman, …) are named but add no weight:
  Ruby ran at build time, not on the server.
- **Version, variant, gems, app server** (deep mode): CRuby vs JRuby vs
  TruffleRuby; Ruby version with provenance and conflict detection; Rails,
  Rack, Puma, Passenger and gem versions from `/rails/info/properties`,
  banners, the lockfile and gem paths leaked in backtraces; Rails environment;
  end-of-life evaluation; a Shodan-style **favicon mmh3 hash**.
- **Vulnerability leads** (deep mode): a curated, version-correlated catalogue —
  Ruby2Shell, ~35 Ruby-core advisories, Rails (CVE-2013-0156, CVE-2019-5418,
  CVE-2020-8165, CVE-2022-32224, CVE-2025-24293, …), Rack, Sinatra, Passenger,
  GitLab (CVE-2021-22205, CVE-2023-7028), Mastodon, Discourse and gems (puma,
  webrick, sidekiq, devise, ruby-saml, …) — with four-component and patch-level
  version ranges and resolved **prerequisites**. Extensible with external
  feeds (`--vuln-feed file|URL`) in the native schema **or OSV and CSAF 2.0**.
  Leads are informational — correlated from versions, not confirmed by
  exploitation.
- **Bundler inventory**: an exposed or supplied `Gemfile` / `Gemfile.lock`
  becomes a gem inventory (a partial SBOM) correlated with gem advisories.
- **Exposure checks**: `/rails/info/properties` and `/rails/info/routes`,
  web-console, better_errors, mailer previews, Sidekiq Web, and readable
  `config/master.key`, `secrets.yml`, `database.yml`, `.env` and logs. Secret
  values are never copied into results.
- **Confidence tiers and evidence provenance**: every evidence item records
  *where* it was found, *how* it matched, the literal matcher, the matched
  snippet, the exact probe and its HTTP status — in every output and report.
- **Reverse proxy / CDN / WAF detection**, **web-server identification**,
  **HTTP/2 + ALPN awareness**, **security.txt** (RFC 9116).
- **Flexible targets and ports**: URLs, IPv4/IPv6, CIDR, dashed ranges,
  wildcards, `*.example.com` via Certificate Transparency, target files;
  `80,443,8000-8100`.
- **Request shaping and politeness**: custom headers, Basic/Bearer/cookie auth,
  vhost scanning, http(s)/SOCKS5 proxy, rate limiting, per-host and host-level
  concurrency, jitter, retries, an adaptive request budget.
- **Resume**, **scan diffing** (`--diff`), **severity exit codes**
  (`--fail-on`), **record & replay** corpora for offline regression testing.
- **Audit trail**: a libpcap capture of every exchange (`--pcap`) and a
  human-readable session log explaining each verdict (`--log`).
- **Output formats**: text, JSON, XML, CSV, SARIF, NDJSON (`--oA` writes them
  all). **Report formats**: text, RTF, PDF, HTML.
- **YAML config** with full CLI parity, **shell completions**, **signature
  packs** and a **favicon catalogue** loadable at run time.
- **CLI *and* a web GUI** with live progress, history, downloads, a Compare
  tab, a Statistics tab and an Info tab.
- **Zero external dependencies** — everything builds from the Go standard
  library.

## Install

```sh
# from source (Go 1.24+)
git clone https://github.com/rom/qrubyscanner
cd qrubyscanner
make build          # produces bin/qrubyscanner
# or install system-wide (binary + man page):
sudo make install
```

## Quick start

```sh
# Full fingerprint (deep is the default): Ruby version, Rails, gems, Ruby2Shell
qrubyscanner example.com

# Only answer "is this service Ruby?" — two requests per service:
qrubyscanner --mode detect example.com

# A few ports, with the project's lockfile, a PDF report, and a CI gate:
qrubyscanner --ports 80,443,3000 --gemfile Gemfile.lock --fail-on critical \
             --report-out report.pdf example.com

# Scan a subnet, force HTTPS, emit JSON to a file:
qrubyscanner --tls on --format json --out scan.json 10.0.0.0/28

# Launch the web GUI:
qrubyscanner --web           # then open http://127.0.0.1:8088/
```

Example (against a WEBrick-served Sinatra app):

```
» http://203.0.113.10:4567/  (port 4567, http)
Ruby verdict        : CONFIRMED (confidence 100/100)
Variant             : Ruby
Version             : 3.3.6 via Server header (WEBrick banner)
Lifecycle           : Ruby 3.3 receives security support until 2027-03-31
App server (guess)  : WEBrick 1.9.2
Frameworks          : Rack, Sinatra
Version-correlated vulnerability leads (3):
  - GHSA-34m4-m9fh-gqp5 [CRITICAL] Ruby case-conversion heap overflow
    ("Ruby2Shell") (preconditions met)
  - affects 2.4.0 – 3.3.0, 3.3.x < 3.3.14, 3.4.x < 3.4.13, 4.0.x < 4.0.10
```

## Usage overview

```
qrubyscanner [options] <target> [target ...]
qrubyscanner --web [--listen host:port]
qrubyscanner --config scan.yaml
```

| Option | Description |
| --- | --- |
| `--mode deep\|detect` | scan depth (default `deep`) |
| `--ports SPEC` | `80` · `80,443` · `8000-8100` · mixed (default: common web ports) |
| `--tls auto\|on\|off` | TLS handling (default `auto`) |
| `--format text\|json\|xml\|csv\|sarif\|ndjson` | scan output format (default `text`) |
| `--out FILE` | write scan output to a file |
| `--report text\|rtf\|pdf\|html` / `--report-out FILE` | also produce a report |
| `--gemfile FILE` | supply a `Gemfile` / `Gemfile.lock` to inventory and correlate (repeatable) |
| `--vuln-feed FILE\|URL` | merge a native, OSV or CSAF vulnerability feed (repeatable) |
| `--signature-pack FILE\|URL` | merge extra detection signatures (repeatable) |
| `--favicon-catalog FILE\|URL` | merge a favicon-hash → product catalogue (repeatable) |
| `--fail-on LEVEL` | exit non-zero on `low\|medium\|high\|critical\|eol` |
| `--oA BASE` | write json/xml/csv/sarif/txt + HTML report to `BASE.*` |
| `--diff FILE` | diff against a prior JSON scan |
| `--timeout DUR` / `--concurrency N` | per-connection timeout / max concurrent probes |
| `--rate N` / `--jitter DUR` / `--retries N` | politeness controls |
| `--per-host-concurrency N` / `--host-concurrency N` | per-host and host-level caps |
| `--request-budget N` | cap optional deep-discovery probes per service |
| `--header "K: V"` / `--cookie` / `--bearer` / `--basic u:p` | request shaping and auth |
| `--vhost HOST` / `--proxy URL` | virtual-host scan / http(s) or socks5 proxy |
| `--targets-file` / `-iL` | read targets from a file (`-` for stdin) |
| `--resolve-dns` / `--banners` | add DNS names / grab non-HTTP banners |
| `--resume FILE` | checkpoint/resume a scan |
| `--pcap FILE` / `--log FILE` | audit trail: packet capture / decision log |
| `--record-corpus FILE` / `--replay-corpus FILE` | offline regression harness |
| `--verbose` / `--quiet` | progress detail |
| `--completion SHELL` | print a bash/zsh/fish completion script |
| `--config FILE` | load a YAML config (full CLI parity) |
| `--web` / `--listen` / `--web-auth u:p` | run the web GUI / address / Basic auth |
| `--version` | print version |

See [`docs/USAGE.md`](docs/USAGE.md) for the full reference and
[`docs/DESIGN.md`](docs/DESIGN.md) for architecture and detection internals.
A man page is in [`docs/qrubyscanner.1`](docs/qrubyscanner.1), and release notes
are in [`docs/CHANGELOG.md`](docs/CHANGELOG.md).

## What deep mode requests

Deep mode issues a bounded number of plain **GET** requests per service (plus
one `OPTIONS` and one request with a made-up method): the page itself, a
guaranteed-404 (twice — once asking for JSON), the favicon, the Rack parameter
probe (which also carries the `X-Request-Id` test), a missing asset, up to two
JavaScript bundles the page references, a few server-status paths, and — when the service plausibly
runs Ruby — a fixed list of diagnostic and project paths
(about 40: `/rails/info/properties`, `/up`, `/cable`, `/404.html`,
`/Gemfile.lock`, `/.ruby-version`, `/Dockerfile`, `/config/master.key`, …). Application-specific paths are
requested only once that application is indicated. Nothing is submitted,
nothing is brute-forced, and no exploit or crash trigger is ever sent.
`--request-budget` caps the optional part, and `--mode detect` reduces a scan
to two requests per service: the page and one path that cannot exist.

## Why the not-found page matters

Many real Ruby deployments show nothing on their front page: it is served by a
CDN, a static marketing site or a JavaScript front end. The application only
becomes visible on a path it routes itself, so every mode also requests one
URL that cannot exist and analyses that reply (`X-Runtime`, Rails' default
headers, the framework's 404 page). Checked against about 130 public sites,
this is what separated sites such as Strava, Dribbble, Instacart and gitlab.com
from a plain "no evidence" result. Deep mode additionally requests
`/users/sign_in` and `/session/new`, which the application always renders.

The same survey drove the false-positive guards: Phoenix (Elixir) copies
Rails' default headers and asset-digest style and is recognised and excluded;
class and error names quoted on documentation or blog pages do not count;
short asset digests, GitHub Pages hosting and marketing pages that merely
mention a product are not treated as evidence.

## Limits

- A site whose every reachable response comes from a CDN or WAF (a block page,
  a cached static front) gives no Ruby evidence; that is reported as `none`,
  not guessed.

- A hardened production Rails app behind a proxy usually reveals that it *is*
  Rails but not which Ruby it runs. That is reported honestly as "version not
  disclosed" rather than guessed.
- A version from `Gemfile.lock` or `.ruby-version` is what the project
  *declares*; the running interpreter can differ. Its source is always shown.
- Distributions backport fixes without changing the version string; a
  version-based lead on a distro-packaged Ruby should be checked against the
  vendor's advisory.
- The built-in catalogue is curated, not exhaustive, and a few recent
  advisories are marked *provisional*. Load current data with `--vuln-feed`.

## Development

```sh
make check      # gofmt check + go vet + tests
make test-race  # tests under the race detector
make dist       # cross-compile release binaries into dist/
```

## License

MIT — see [LICENSE](LICENSE).
