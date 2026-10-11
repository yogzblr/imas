#!/usr/bin/env python3
"""Roll a day's status fragments up into docs/BUILD-STATUS.md.

Feature PRs do not edit docs/BUILD-STATUS.md. They add a fragment file,
docs/status/days/YYYY-MM-DD/<topic>.md, so two PRs never touch the same
file. Once a day this script applies that day's fragments to BUILD-STATUS.md
and writes the day's record to docs/status/YYYY-MM-DD.md. See
docs/status/README.md for the fragment format.

    scripts/status/rollup.py --date 2026-10-11     # apply one day
    scripts/status/rollup.py --check               # validate every fragment

Standard library only. Applying a day twice gives the same result.
"""
import argparse
import re
import sys
from pathlib import Path

ACTIONS = {"add", "update", "close"}
KEYS = {"change", "pr", "item", "action", "section", "sub", "title", "rag",
        "next", "next-append"}
ID_RE = re.compile(r"^P\d+$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
LAST_RE = re.compile(r"^Last rolled up:")


class StatusError(Exception):
    pass


def parse_fragment(path):
    """Return a list of blocks (dicts) from one fragment file."""
    blocks, cur = [], {}
    for n, raw in enumerate(path.read_text().split("\n"), 1):
        line = raw.rstrip()
        if line.strip() == "---":
            if cur:
                blocks.append(cur)
            cur = {}
            continue
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = re.match(r"^([a-z-]+):\s?(.*)$", line)
        if not m:
            raise StatusError(f"{path}:{n}: expected 'key: value', got {line[:60]!r}")
        k, v = m.group(1), m.group(2).strip()
        if k not in KEYS:
            raise StatusError(f"{path}:{n}: unknown key {k!r}")
        if k in cur:
            raise StatusError(f"{path}:{n}: key {k!r} repeated in one block")
        if re.search(r"(?<!\\)\|", v):
            raise StatusError(f"{path}:{n}: unescaped '|' in {k!r}; write \\|")
        cur[k] = v
    if cur:
        blocks.append(cur)
    for b in blocks:
        validate(path, b)
    if not blocks:
        raise StatusError(f"{path}: no blocks")
    return blocks


def validate(path, b):
    if "item" in b:
        if not ID_RE.match(b["item"]):
            raise StatusError(f"{path}: item {b['item']!r} is not P<number>")
        if b.get("action") not in ACTIONS:
            raise StatusError(f"{path}: {b['item']}: action must be one of {sorted(ACTIONS)}")
        if b["action"] == "add":
            for k in ("section", "title", "rag", "next"):
                if k not in b:
                    raise StatusError(f"{path}: {b['item']}: add needs {k!r}")
    elif "action" in b:
        raise StatusError(f"{path}: action without item")
    if "item" not in b and "change" not in b:
        raise StatusError(f"{path}: block needs 'change' or 'item'")


def load_day(root, date):
    d = root / "docs" / "status" / "days" / date
    files = sorted(d.glob("*.md")) if d.is_dir() else []
    return [(f, parse_fragment(f)) for f in files]


# ---- BUILD-STATUS.md editing -------------------------------------------

def find_row(lines, pid):
    pat = re.compile(r"^\|\s*" + re.escape(pid) + r"\s*\|")
    for i, l in enumerate(lines):
        if pat.match(l):
            return i
    return None


def split_row(line):
    cells = re.split(r"(?<!\\)\|", line.strip())
    return [c.strip() for c in cells[1:-1]]


def join_row(cells):
    return "| " + " | ".join(cells) + " |"


def find_table_end(lines, section, sub):
    """Index just after the last row of the table to append to."""
    start = None
    for i, l in enumerate(lines):
        if l.startswith("### " + section) or l.startswith("## " + section):
            start = i
            break
    if start is None:
        raise StatusError(f"section {section!r} not found in BUILD-STATUS.md")
    end = len(lines)
    for j in range(start + 1, len(lines)):
        if lines[j].startswith("## ") or lines[j].startswith("### "):
            end = j
            break
    i = start
    if sub:
        while i < end and not lines[i].startswith("**" + sub):
            i += 1
        if i >= end:
            raise StatusError(f"sub-section {sub!r} not found in {section!r}")
    while i < end and not lines[i].startswith("|"):
        i += 1
    if i >= end:
        raise StatusError(f"no table in section {section!r}")
    while i < end and lines[i].startswith("|"):
        i += 1
    return i


def apply_item(lines, b, warn):
    pid, act = b["item"], b["action"]
    idx = find_row(lines, pid)
    if act == "close":
        if idx is None:
            warn(f"{pid}: close: row not found (already closed?)")
        else:
            del lines[idx]
        return
    if idx is None:
        if act == "update":
            raise StatusError(f"{pid}: update: row not found")
        at = find_table_end(lines, b["section"], b.get("sub"))
        lines.insert(at, join_row([pid, b["title"], b["rag"], b["next"]]))
        return
    cells = split_row(lines[idx])
    if len(cells) != 4:
        raise StatusError(f"{pid}: row has {len(cells)} cells, expected 4")
    if "title" in b:
        cells[1] = b["title"]
    if "rag" in b:
        cells[2] = b["rag"]
    if "next" in b:
        cells[3] = b["next"]
    if "next-append" in b and b["next-append"] not in cells[3]:
        cells[3] = cells[3].rstrip() + " " + b["next-append"]
    lines[idx] = join_row(cells)


def set_last_rolled(lines, date):
    text = f"Last rolled up: {date} ([docs/status/{date}.md](status/{date}.md))."
    for i, l in enumerate(lines):
        if LAST_RE.match(l):
            lines[i] = text
            return
    for i, l in enumerate(lines):
        if l.startswith("## Baseline"):
            lines[i:i] = [text, ""]
            return
    raise StatusError("no '## Baseline' heading to place 'Last rolled up' before")


def day_record(date, frags):
    out = [f"# Status changes, {date}", "",
           "Generated by `scripts/status/rollup.py` from `docs/status/days/"
           f"{date}/`. Do not edit by hand.", "", "## Changes", ""]
    items = []
    for f, blocks in frags:
        for b in blocks:
            if "change" in b:
                pr = f" (PR #{b['pr']})" if "pr" in b else ""
                out.append(f"- {b['change']}{pr}")
            if "item" in b:
                what = b["action"]
                extra = b.get("rag") or b.get("title") or b.get("next-append") or b.get("next") or ""
                items.append(f"| {b['item']} | {what} | {extra[:140]} |")
    if items:
        out += ["", "## Item changes", "", "| ID | Action | Detail |", "|---|---|---|"] + items
    return "\n".join(out) + "\n"


def rollup(root, date):
    frags = load_day(root, date)
    if not frags:
        raise StatusError(f"no fragments in docs/status/days/{date}/")
    bs = root / "docs" / "BUILD-STATUS.md"
    lines = bs.read_text().rstrip("\n").split("\n")
    warnings = []
    for f, blocks in frags:
        for b in blocks:
            if "item" in b:
                try:
                    apply_item(lines, b, warnings.append)
                except StatusError as e:
                    raise StatusError(f"{f}: {e}")
    set_last_rolled(lines, date)
    bs.write_text("\n".join(lines) + "\n")
    (root / "docs" / "status" / f"{date}.md").write_text(day_record(date, frags))
    return warnings


def check(root):
    n = 0
    base = root / "docs" / "status" / "days"
    for d in sorted(base.glob("*")) if base.is_dir() else []:
        if not DATE_RE.match(d.name):
            raise StatusError(f"{d}: directory name is not a date")
        for f in sorted(d.glob("*.md")):
            parse_fragment(f)
            n += 1
    return n


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--date")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--root", default=".")
    a = ap.parse_args(argv)
    root = Path(a.root)
    try:
        if a.check:
            print(f"{check(root)} fragment file(s) OK")
        elif a.date and DATE_RE.match(a.date):
            for w in rollup(root, a.date):
                print("warning:", w, file=sys.stderr)
            print(f"rolled up {a.date}")
        else:
            ap.error("give --date YYYY-MM-DD or --check")
    except StatusError as e:
        print("error:", e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
