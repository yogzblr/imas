# imas docs site

An [mdBook](https://rust-lang.github.io/mdBook/) site, published to GitHub
Pages by [`.github/workflows/docs.yml`](../.github/workflows/docs.yml) on
every push to `main`.

- `src/introduction.md`, `src/installation.md`, `src/SUMMARY.md` — hand-written,
  edit these directly. `installation.md` `{{#include}}`s
  [`../docs/INSTALL.md`](../docs/INSTALL.md) rather than duplicating it.
- `src/ingredients/*.md` — **generated**, not committed (see `.gitignore`).
  Produced by [`tools/gendocs`](../tools/gendocs) directly from
  `internal/ingredients/`'s `Methods()` / `PropertiesForMethod()`, so the
  ingredient reference can't drift from the code.

To build locally:

```sh
make docs         # regenerates ingredients/*.md, then `mdbook build` -> docs-site/book/
make docs-serve   # same, then serves with live reload
```

Needs [mdBook](https://rust-lang.github.io/mdBook/guide/installation.html)
on your `PATH`. `make gendocs` alone just regenerates the ingredient pages
without needing mdBook.

If you add a new ingredient package under `internal/ingredients/`, add it to
the `category` map at the top of
[`tools/gendocs/main.go`](../tools/gendocs/main.go) (core / linux / windows)
— everything else about its page is derived from the code automatically.
