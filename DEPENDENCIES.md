# Dependencies

All the dependencies required to build imas are listed in the [go.mod] file.

The licenses for each dependency are vendored in the [dependencies] directory, sorted by URL.
This directory is automatically updated on push through GitHub actions.

Licenses associated with the specific commit you are running can be found by using `imas version` and referencing the associated commit in the (publicly available) git history.
If you are using an official tagged release, the sources associated are available in the zipped archive attached to the release post.

## Licences outside the Apache-2.0/MIT default

Dependencies are Apache-2.0 or MIT by default; BSD and ISC are treated the same.
MPL-2.0 is an accepted exception (`docs/design/requirements.md` item 21): MPL code
is used unmodified, or any change to it is shared. For MPL-2.0 modules
`go-licenses save` copies the module's full source, not just its licence, into
[dependencies](dependencies).

| Module | Licence | Pulled in by |
|---|---|---|
| `github.com/openbao/openbao/api/v2` | MPL-2.0 | `internal/openbao`, the official OpenBao Go client behind every server-side OpenBao identity, and the sprout's `sdb://openbao` provider (`internal/ingredients/sdb/openbao`), so it ships in the sprout binary |
| `github.com/hashicorp/errwrap`, `go-cleanhttp`, `go-multierror`, `go-retryablehttp`, `go-secure-stdlib/parseutil`, `go-secure-stdlib/strutil`, `go-sockaddr`, `hcl` | MPL-2.0 | the OpenBao client |
| `github.com/go-sql-driver/mysql` | MPL-2.0 | the PXC/MySQL store |

The OpenBao client's other dependencies are `github.com/cenkalti/backoff/v5`,
`github.com/go-viper/mapstructure/v2`, `github.com/mitchellh/mapstructure` and
`github.com/ryanuber/go-glob` (MIT), `github.com/go-jose/go-jose/v4` (Apache-2.0,
its `json` package BSD-3-Clause), and `golang.org/x/net`, `x/text` and `x/time`
(BSD-3-Clause). None needs CGO.
