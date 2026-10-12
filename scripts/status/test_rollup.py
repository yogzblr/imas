import tempfile
import unittest
from pathlib import Path

import rollup

BS = """# Build Status

intro

## Baseline

x

## Pending items

### S1 Blocking

**S1a, before the first Azure run**

| ID | Item | RAG | Next step |
|---|---|---|---|
| P1 | **Run** | **Red** | Do it. |
| P19 | **Deadlock** | Amber | Trace it. |

**S1b, before dispatch**

| ID | Item | RAG | Next step |
|---|---|---|---|
| P18 | **Keyring** | Amber | Fill it. |

### S2 High

| ID | Item | RAG | Next step |
|---|---|---|---|
| P5 | **Scale** | **Red** | Run 10k. |

## Change log

- nothing
"""


def make(frags):
    d = Path(tempfile.mkdtemp())
    (d / "docs" / "status" / "days" / "2026-10-12").mkdir(parents=True)
    (d / "docs" / "BUILD-STATUS.md").write_text(BS)
    for name, text in frags.items():
        (d / "docs" / "status" / "days" / "2026-10-12" / name).write_text(text)
    return d


class Rollup(unittest.TestCase):
    def run_day(self, frags):
        d = make(frags)
        w = rollup.rollup(d, "2026-10-12")
        return d, (d / "docs" / "BUILD-STATUS.md").read_text(), w

    def test_update_close_add(self):
        d, out, _ = self.run_day({
            "a.md": "change: keyring decided\npr: 7\nitem: P18\naction: update\nrag: Green\nnext-append: Done.\n",
            "b.md": "item: P19\naction: close\n---\nitem: P22\naction: add\nsection: S1\nsub: S1b\ntitle: **New**\nrag: Red\nnext: Build.\n",
            "c.md": "item: P30\naction: add\nsection: S2\ntitle: **Hi**\nrag: Amber\nnext: Soon.\n",
        })
        self.assertIn("| P18 | **Keyring** | Green | Fill it. Done. |", out)
        self.assertNotIn("P19", out)
        self.assertLess(out.index("| P22 |"), out.index("### S2 High"))
        self.assertLess(out.index("| P18 |"), out.index("| P22 |"))
        self.assertLess(out.index("| P5 |"), out.index("| P30 |"))
        self.assertIn("Last rolled up: 2026-10-12", out)
        rec = (d / "docs" / "status" / "2026-10-12.md").read_text()
        self.assertIn("- keyring decided (PR #7)", rec)
        self.assertIn("| P19 | close |", rec)

    def test_idempotent(self):
        frags = {"a.md": "item: P18\naction: update\nnext-append: Done.\n---\nitem: P19\naction: close\n---\n"
                         "item: P22\naction: add\nsection: S1\nsub: S1b\ntitle: T\nrag: Red\nnext: N\n"}
        d = make(frags)
        rollup.rollup(d, "2026-10-12")
        once = (d / "docs" / "BUILD-STATUS.md").read_text()
        w = rollup.rollup(d, "2026-10-12")
        self.assertEqual(once, (d / "docs" / "BUILD-STATUS.md").read_text())
        self.assertTrue(any("P19" in x for x in w))

    def test_errors(self):
        for text in ["item: P99\naction: update\nrag: Red\n",
                     "item: X1\naction: update\n",
                     "item: P1\naction: add\nsection: S1\n",
                     "bogus: 1\n", "change: a | b\n", "pr: 3\n", "item: P1\n"]:
            with self.subTest(text=text):
                d = make({"a.md": text})
                with self.assertRaises(rollup.StatusError):
                    rollup.rollup(d, "2026-10-12")

    def test_no_fragments(self):
        d = make({})
        with self.assertRaises(rollup.StatusError):
            rollup.rollup(d, "2026-10-12")

    def test_check(self):
        d = make({"a.md": "change: ok\n"})
        self.assertEqual(rollup.check(d), 1)

    def test_order_ignores_case(self):
        # A capitalised unit name sorts after the lowercase fragment that
        # adds the row it updates, as the names read.
        frags = {
            "z-build-summary.md": "item: P27\naction: add\nsection: S2\ntitle: **Left**\nrag: Amber\nnext: Fix.\n",
            "z-E4.md": "item: P27\naction: update\nnext-append: E4 built.\n",
        }
        d, out, _ = self.run_day(frags)
        self.assertIn("| P27 | **Left** | Amber | Fix. E4 built. |", out)
        self.assertEqual([f.name for f, _ in rollup.load_day(d, "2026-10-12")], ["z-build-summary.md", "z-E4.md"])

    def test_check_dry_runs_pending_days(self):
        # An update of a row nothing has added fails --check, as it would
        # fail the roll-up; BUILD-STATUS.md is not written.
        d = make({"a.md": "item: P99\naction: update\nnext-append: x\n"})
        with self.assertRaises(rollup.StatusError):
            rollup.check(d)
        self.assertEqual((d / "docs" / "BUILD-STATUS.md").read_text(), BS)
        # A day already rolled up is not applied again.
        bs = d / "docs" / "BUILD-STATUS.md"
        bs.write_text(BS.replace("## Baseline", "Last rolled up: 2026-10-12 (x).\n\n## Baseline"))
        self.assertEqual(rollup.check(d), 1)
        # Pending days apply in date order on top of each other.
        bs.write_text(BS)
        (d / "docs" / "status" / "days" / "2026-10-12" / "a.md").write_text(
            "item: P99\naction: add\nsection: S2\ntitle: T\nrag: Red\nnext: N\n")
        (d / "docs" / "status" / "days" / "2026-10-13").mkdir()
        (d / "docs" / "status" / "days" / "2026-10-13" / "a.md").write_text("item: P99\naction: update\nrag: Amber\n")
        self.assertEqual(rollup.check(d), 2)


if __name__ == "__main__":
    unittest.main()
