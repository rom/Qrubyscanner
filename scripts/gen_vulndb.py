#!/usr/bin/env python3
"""Generate internal/ruby/vulndb_rubysec.go from the RubySec advisory database.

    git clone https://github.com/rubysec/ruby-advisory-db
    python3 scripts/gen_vulndb.py ruby-advisory-db > internal/ruby/vulndb_rubysec.go
    gofmt -w internal/ruby/vulndb_rubysec.go

The database (https://github.com/rubysec/ruby-advisory-db) describes each
advisory by the versions that are *patched* or *unaffected*. This script turns
that into the scanner's model — explicit affected ranges — by taking the
complement on the version line. It is a maintainer tool: the scanner itself
needs only the generated Go file. Requires PyYAML.
"""
import datetime
import glob
import os
import re
import subprocess
import sys

import yaml

# Gems released in lock-step with Rails: their advisories are keyed under the
# "rails" component so a detected Rails version is checked against all of them.
RAILS_GEMS = ["rails", "actionpack", "activerecord", "activesupport", "actionview", "activestorage",
              "actiontext", "actionmailer", "actionmailbox", "actioncable", "activejob", "activemodel",
              "activeresource", "railties"]

# Corrections for upstream data errors, keyed by (gem or engine, advisory file).
# Each maps a constraint string as written upstream to the intended one.
OVERRIDES = {
    # "< 5.20" is a typo for "< 5.2.0" (Active Storage first shipped in 5.2).
    ("activestorage", "CVE-2025-24293.yml"): {"< 5.20": "< 5.2.0"},
}

INF = (10**9,)
NEG = (-10**9,)


def parse(v):
    """Version string -> comparable tuple (4 components, like the Go side)."""
    v = v.strip().lstrip("vV")
    out = []
    for i, seg in enumerate(re.split(r"[.-]", v)[:4]):
        m = re.match(r"^(\d+)(.*)$", seg)
        if m and not m.group(2):
            out.append(int(m.group(1)))
        elif m and i == 2 and re.match(r"^p\d+$", m.group(2)):
            out.append(int(m.group(1)))
            out.append(int(m.group(2)[1:]))
            break
        else:
            # pre-release tag (rc1, beta2, preview1, pre): sorts before release
            if m:
                out.append(int(m.group(1)))
            out.append(-1)
            break
    while len(out) < 4:
        out.append(0)
    return tuple(out[:4])


def fmt(t):
    if t == NEG or t == INF:
        return ""
    parts = list(t)
    if -1 in parts:
        i = parts.index(-1)
        return ".".join(str(p) for p in parts[:i]) + ".rc0" if i == 3 else ".".join(str(p) for p in parts[:i]) + ".0.rc0"
    while len(parts) > 3 and parts[-1] == 0:
        parts.pop()
    return ".".join(str(p) for p in parts)


def bump_last(v):
    segs = [s for s in re.split(r"\.", v.strip()) if s != ""]
    nums = []
    for s in segs:
        m = re.match(r"^\d+", s)
        if not m:
            break
        nums.append(int(m.group(0)))
    nums = nums[:4]
    while len(nums) < 3:
        nums.append(0)
    nums[-1] += 1
    return tuple(nums + [0] * (4 - len(nums)))


def pessimistic_upper(v):
    segs = []
    for s in v.strip().split("."):
        m = re.match(r"^\d+$", s)
        if not m:
            break
        segs.append(int(s))
    if len(segs) <= 1:
        return INF
    up = segs[:-1]
    up[-1] += 1
    return tuple(up + [0] * (4 - len(up)))


def interval(expr):
    """One constraint item ("~> 7.0.8, >= 7.0.8.5") -> [lo, hi)."""
    lo, hi = NEG, INF
    for part in expr.split(","):
        m = re.match(r"^\s*(~>|>=|<=|>|<|=)?\s*([0-9][\w.-]*)\s*$", part)
        if not m:
            raise ValueError("unparsed constraint %r" % expr)
        op, ver = m.group(1) or "=", m.group(2)
        if op == "~>":
            lo, hi = max(lo, parse(ver)), min(hi, pessimistic_upper(ver))
        elif op == ">=":
            lo = max(lo, parse(ver))
        elif op == ">":
            lo = max(lo, bump_last(ver))
        elif op == "<":
            hi = min(hi, parse(ver))
        elif op == "<=":
            hi = min(hi, bump_last(ver))
        elif op == "=":
            lo, hi = max(lo, parse(ver)), min(hi, bump_last(ver))
    return lo, hi


def affected(adv, fixes=None):
    safe = []
    for key in ("patched_versions", "unaffected_versions"):
        for item in adv.get(key) or []:
            lo, hi = interval((fixes or {}).get(str(item), str(item)))
            if lo < hi:
                safe.append((lo, hi))
    safe.sort()
    out, cur = [], NEG
    for lo, hi in safe:
        if lo > cur:
            out.append((cur, lo))
        cur = max(cur, hi)
    if cur < INF:
        out.append((cur, INF))
    return out


def severity(adv):
    for key in ("cvss_v3", "cvss_v4", "cvss_v2"):
        s = adv.get(key)
        if isinstance(s, (int, float)):
            if s >= 9:
                return "critical", True
            if s >= 7:
                return "high", True
            if s >= 4:
                return "medium", True
            if s > 0:
                return "low", True
    return "medium", False


def clean(s, limit):
    s = re.sub(r"[`*#>]+", "", str(s or ""))
    s = re.sub(r"\s+", " ", s).strip()
    s = re.sub(r"^(?:(?:Summary|Impact|Description|Details|Overview|SUMMARY)\s+)+", "", s)
    if len(s) > limit:
        s = s[:limit].rsplit(" ", 1)[0] + "…"
    return s


def goq(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def entry(adv, note, fixes=None):
    if adv.get("cve"):
        ident = "CVE-" + str(adv["cve"])
    elif adv.get("ghsa"):
        ident = "GHSA-" + str(adv["ghsa"])
    elif adv.get("osvdb"):
        ident = "OSVDB-" + str(adv["osvdb"])
    else:
        return None
    ranges = affected(adv, fixes)
    if not ranges:
        return None
    sev, scored = severity(adv)
    return {
        "id": ident, "date": str(adv.get("date") or ""), "ranges": ranges, "sev": sev, "scored": scored,
        "title": clean(adv.get("title"), 150) or ident, "desc": clean(adv.get("description"), 220),
        "ref": str(adv.get("url") or "https://rubysec.com/advisories/" + ident), "notes": [note] if note else [],
    }


def union(ranges):
    out = []
    for lo, hi in sorted(ranges):
        if out and lo <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], hi))
        else:
            out.append((lo, hi))
    return out


def render(e):
    specs = []
    for lo, hi in union(e["ranges"]):
        fields = []
        if lo != NEG:
            fields.append("Introduced: " + goq(fmt(lo)))
        if hi != INF:
            fields.append("Fixed: " + goq(fmt(hi)))
        if not fields:
            fields.append('Introduced: "0"')
        specs.append("{" + ", ".join(fields) + "}")
    notes = list(e["notes"])
    if not e["scored"]:
        notes.append("severity not scored upstream (shown as medium)")
    line = "{ID: %s, Severity: %s, Title: %s, Description: %s, Reference: %s, " % (
        goq(e["id"]), goq(e["sev"]), goq(e["title"]), goq(e["desc"]), goq(e["ref"]))
    if notes:
        line += "Note: %s, " % goq("; ".join(notes))
    line += "Affected: []RangeSpec{%s}}," % ", ".join(specs)
    return line


def load(path):
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def collect(paths, note_for):
    """Advisories for one catalogue key. An advisory filed under several gems
    (Rails components) is merged: its affected ranges are unioned."""
    seen, skipped = {}, 0
    for p in sorted(paths):
        fixes = OVERRIDES.get((os.path.basename(os.path.dirname(p)), os.path.basename(p)))
        try:
            res = entry(load(p), note_for(p), fixes)
        except Exception as exc:  # malformed or exotic constraint: skip, report
            skipped += 1
            print("skip %s: %s" % (p, exc), file=sys.stderr)
            continue
        if not res:
            continue
        prev = seen.get(res["id"])
        if prev is None:
            seen[res["id"]] = res
            continue
        prev["ranges"] += res["ranges"]
        for n in res["notes"]:
            if n not in prev["notes"]:
                prev["notes"].append(n)
        if not prev["scored"] and res["scored"]:
            prev["sev"], prev["scored"] = res["sev"], True
    rows = sorted(seen.values(), key=lambda r: (r["date"], r["id"]), reverse=True)
    return [render(r) for r in rows], skipped


def main():
    root = sys.argv[1]
    rev = subprocess.run(["git", "-C", root, "log", "-1", "--format=%h %cs"], capture_output=True, text=True).stdout.strip()
    skipped = 0
    out = []
    out.append("// Code generated by scripts/gen_vulndb.py from the RubySec advisory database")
    out.append("// (https://github.com/rubysec/ruby-advisory-db, revision %s). DO NOT EDIT." % rev)
    out.append("")
    out.append("package ruby")
    out.append("")
    out.append("// RubySecRevision identifies the advisory-database snapshot the built-in")
    out.append("// catalogue was generated from.")
    out.append("const RubySecRevision = %s" % goq(rev))
    out.append("")

    rows, s = collect(glob.glob(os.path.join(root, "rubies", "ruby", "*.yml")), lambda p: "")
    skipped += s
    out.append("// rubysecRuby holds the advisories for the reference Ruby interpreter.")
    out.append("var rubysecRuby = []FeedEntry{")
    out += ["\t" + r for r in rows]
    out.append("}")
    out.append("")

    out.append("// rubysecComponents holds advisories keyed by framework / runtime component.")
    out.append("var rubysecComponents = map[string][]FeedEntry{")
    rails_paths = []
    for g in RAILS_GEMS:
        rails_paths += glob.glob(os.path.join(root, "gems", g, "*.yml"))
    rows, s = collect(rails_paths, lambda p: "gem " + os.path.basename(os.path.dirname(p)))
    skipped += s
    out.append('\t"rails": {')
    out += ["\t\t" + r for r in rows]
    out.append("\t},")
    rows, s = collect(glob.glob(os.path.join(root, "rubies", "jruby", "*.yml")), lambda p: "")
    skipped += s
    out.append('\t"jruby": {')
    out += ["\t\t" + r for r in rows]
    out.append("\t},")
    out.append("}")
    out.append("")

    out.append("// rubysecGems holds advisories keyed by gem name.")
    out.append("var rubysecGems = map[string][]FeedEntry{")
    total = 0
    for gem_dir in sorted(glob.glob(os.path.join(root, "gems", "*"))):
        gem = os.path.basename(gem_dir)
        if gem in RAILS_GEMS:
            continue
        rows, s = collect(glob.glob(os.path.join(gem_dir, "*.yml")), lambda p: "")
        skipped += s
        if not rows:
            continue
        total += len(rows)
        out.append("\t%s: {" % goq(gem.lower()))
        out += ["\t\t" + r for r in rows]
        out.append("\t},")
    out.append("}")
    print("\n".join(out))
    print("generated %s; skipped %d advisories; %d gem advisories" % (datetime.date.today(), skipped, total), file=sys.stderr)


if __name__ == "__main__":
    main()
