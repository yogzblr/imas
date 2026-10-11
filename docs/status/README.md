# Status fragments

`docs/BUILD-STATUS.md` is the live tracker, but **feature PRs do not edit it**.
Every PR used to touch the same table rows and the same change log, so any
two open PRs conflicted. Now a PR adds one small file of its own, and a daily
roll-up applies the day's files to `BUILD-STATUS.md`.

## What a PR adds

`docs/status/days/YYYY-MM-DD/<topic>.md`, where the date is the day the PR is
written (not the roll-up day). One file per PR, named for the topic, so no two
PRs share a file. It holds one or more blocks separated by a line `---`.
Each block is `key: value` lines (one line per value; escape a pipe as `\|`):

| Key | Meaning |
|---|---|
| `change` | One line for the day's record. Optional if the block has an `item`. |
| `pr` | PR number, shown in the record. |
| `item` | A pending item ID, `P<number>`. |
| `action` | With `item`: `add`, `update` or `close`. |
| `section` | `add` only: the table's heading, `S1`, `S2`, `S3`, `S4` or `Planned`. |
| `sub` | `add` only, for `S1`: `S1a`, `S1b` or `S1c`. |
| `title`, `rag`, `next` | The row's Item, RAG and Next step cells. `add` needs all three plus `section`; `update` changes only the ones given. |
| `next-append` | `update`: text added to the end of the Next step cell (skipped if it is already there). |

Example:

```
change: P18 decided: GPG-signed checksums are the update trust root.
pr: 193
item: P18
action: update
rag: Amber
next-append: Release GPG key goes in the keyring file.
---
item: P22
action: add
section: S1
sub: S1b
title: **Fleet update trust by GPG-signed checksums**
rag: Red
next: Build it; see the design doc.
```

Fragments of one day apply in file-name order. If your fragment changes an item that another fragment of the same day adds or rewrites, give yours a name that sorts after it (for example a `z-` prefix), or the roll-up fails: an `update` that sorts before the `add` of a new item names an item that does not exist yet, and an `add` of an existing row that sorts after your `update` overwrites your fields.

Check a fragment before you push: `scripts/status/rollup.py --check`.

## The daily roll-up

`scripts/status/rollup.py --date YYYY-MM-DD` applies that day's fragments to
`BUILD-STATUS.md` (updating the "Last rolled up" line) and writes the day's
record to `docs/status/YYYY-MM-DD.md`. It is safe to run twice. It stops with
an error if an `update` names an item that is not in the file; a `close` of a
missing item only warns. Python 3 standard library only; tests:
`cd scripts/status && python3 -I -m unittest`.

Run it at the end of the day and send the result as one PR. A change that
matters before then (a decision, a Red item) can still edit `BUILD-STATUS.md`
directly in a PR of its own, with the fragment added alongside.

History up to 2026-10-11 was moved here from the old change log, in the
`000-history.md` files.
