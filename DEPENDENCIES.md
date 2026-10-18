# Dependencies

All the dependencies required to build imas are listed in the [go.mod] file.

The licenses for each dependency are vendored in the [dependencies] directory, sorted by URL.
This directory is automatically updated on push through GitHub actions.

Licenses associated with the specific commit you are running can be found by using `imas version` and referencing the associated commit in the (publicly available) git history.
If you are using an official tagged release, the sources associated are available in the zipped archive attached to the release post.

## How `dependencies/` is kept current

[`.github/workflows/go-licenses.yml`](.github/workflows/go-licenses.yml) runs
`go-licenses` v2.0.1, pinned, for three targets: `linux/amd64 ./...`,
`windows/amd64 ./cmd/sprout` (the Windows sprout links `go-ole`, `go-tpm` and
`go-bindings-win32`, which no Linux build does) and `darwin/arm64 ./cmd/imas`.

- On pull requests that touch `go.mod`, `go.sum`, Go code or the workflow,
  `go-licenses check` fails on a licence of type forbidden, restricted or
  unknown (one it cannot identify). Nothing is saved.
- On push to `main` (and `v1`, `v2`) the same check runs, then
  `go-licenses save` regenerates this directory and commits it if it changed.

`./...` covers every non-test package, so the directory also holds modules
that only a test helper imports (the `modernc.org` SQLite stack below), not
only what the shipped binaries link. Test-only imports (`_test.go`) are not
included.

## Recorded Apache-2.0 and MIT additions

Modules added under the Apache-2.0/MIT default that a design brief named,
recorded here with their licence as the brief asked:

| Module | Licence | Linked by | Why |
|---|---|---|---|
| `github.com/m-mizutani/masq` v0.2.3 | Apache-2.0 (its own tree has no other licence; its one requirement, `github.com/m-mizutani/gt`, Apache-2.0, is used by its tests only and not linked) | farmer | Masks secrets in string params of the audit log (`internal/audit`, `docs/briefs/S-hardening.md` S2). Standard library only, no CGO. |

## Licences outside the Apache-2.0/MIT default

Dependencies are Apache-2.0 or MIT by default (`CLAUDE.md`).
`docs/design/requirements.md` item 21 also allows BSD-2-Clause, BSD-3-Clause,
ISC and 0BSD, permissive licences with no copyleft (owner, 2026-10-17). Its
recorded exceptions are Percona XtraDB Cluster (a deployed database, not a Go
module) and MPL-2.0 generally: MPL code is used unmodified, or any change to
it is shared. For MPL-2.0 modules `go-licenses save` copies the module's full
source, not just its licence, into [dependencies](dependencies). No module in
the build has any other licence: `go-licenses report` for the three targets
above finds only Apache-2.0, MIT and the licences in the table below. A new
one is flagged before it is added.

Every module in the build whose licence is anything other than Apache-2.0 or
MIT, and which of the six binaries (sprout, farmer, saasapi, farmerbus,
migrate, imas CLI) links it, on any platform the release
builds. "All six" means every one of them. imas's own code is 0BSD
([LICENSE](LICENSE)) and is not listed.

| Module | Licence | Linked by |
|---|---|---|
| `dario.cat/mergo` | BSD-3-Clause | sprout |
| `filippo.io/edwards25519` | BSD-3-Clause | farmer, saasapi, migrate |
| `github.com/ProtonMail/go-crypto` | BSD-3-Clause | sprout |
| `github.com/atotto/clipboard` | BSD-3-Clause | imas CLI |
| `github.com/cloudflare/circl` | BSD-3-Clause | sprout |
| `github.com/cyphar/filepath-securejoin` | BSD-3-Clause AND MPL-2.0 (per file). The sprout links only the root package, whose files are all BSD-3-Clause; the MPL-2.0 code (`pathrs-lite`) is not linked | sprout |
| `github.com/emirpasic/gods` | BSD-2-Clause; its AVL tree ISC | sprout |
| `github.com/glebarez/go-sqlite` | BSD-3-Clause | none: only `internal/fleetcatalog/fleetcatalogtest`, a test helper, imports it (through `github.com/glebarez/sqlite`, MIT) |
| `github.com/go-git/gcfg` | BSD-3-Clause | sprout |
| `github.com/go-jose/go-jose/v4` | Apache-2.0; its `json` package BSD-3-Clause | sprout, farmer, saasapi, farmerbus, imas CLI |
| `github.com/go-sql-driver/mysql` | MPL-2.0 | farmer, saasapi, migrate |
| `github.com/gogrlx/snack` | 0BSD | sprout |
| `github.com/google/uuid` | BSD-3-Clause | sprout, farmer, imas CLI |
| `github.com/gorilla/websocket` | BSD-2-Clause | imas CLI |
| `github.com/hashicorp/errwrap` | MPL-2.0 | sprout, farmer, saasapi, farmerbus, imas CLI |
| `github.com/hashicorp/go-cleanhttp` | MPL-2.0 | sprout, farmer, saasapi, farmerbus, imas CLI |
| `github.com/hashicorp/go-multierror` | MPL-2.0 | sprout, farmer, saasapi, farmerbus, imas CLI |
| `github.com/hashicorp/go-retryablehttp` | MPL-2.0 | sprout, farmer, saasapi, farmerbus, imas CLI |
| `github.com/hashicorp/go-secure-stdlib/parseutil` | MPL-2.0 | sprout, farmer, saasapi, farmerbus, imas CLI |
| `github.com/hashicorp/go-secure-stdlib/strutil` | MPL-2.0 | sprout, farmer, saasapi, farmerbus, imas CLI |
| `github.com/hashicorp/go-sockaddr` | MPL-2.0 | sprout, farmer, saasapi, farmerbus, imas CLI |
| `github.com/hashicorp/hcl` | MPL-2.0 | sprout, farmer, saasapi, farmerbus, imas CLI |
| `github.com/klauspost/compress` | Apache-2.0, BSD-3-Clause (`s2`, `internal/snapref`, parts of the root LICENSE), MIT (`zstd/internal/xxhash`) | all six |
| `github.com/klauspost/crc32` | BSD-3-Clause | sprout, farmer, imas CLI |
| `github.com/nats-io/nats-server/v2` | Apache-2.0; `internal/fastrand` BSD-3-Clause | sprout, farmer, saasapi, farmerbus, imas CLI |
| `github.com/openbao/openbao/api/v2` | MPL-2.0 | sprout, farmer, saasapi, farmerbus, imas CLI |
| `github.com/remyoudompheng/bigfft` | BSD-3-Clause | none: only `internal/fleetcatalog/fleetcatalogtest`, a test helper, imports it (through `github.com/glebarez/sqlite`, MIT) |
| `github.com/spf13/pflag` | BSD-3-Clause | imas CLI |
| `github.com/taigrr/jety` | 0BSD | sprout, farmer, saasapi, farmerbus, imas CLI |
| `github.com/taigrr/log-mux` | 0BSD | all six |
| `github.com/taigrr/log-nats/v2` | 0BSD | all six |
| `github.com/taigrr/openrc` | 0BSD | sprout |
| `github.com/taigrr/systemctl` | 0BSD | sprout |
| `github.com/zeebo/xxh3` | BSD-2-Clause | sprout, farmer, imas CLI |
| `golang.org/x/crypto` | BSD-3-Clause | all six |
| `golang.org/x/mod` | BSD-3-Clause | sprout, farmer, saasapi |
| `golang.org/x/net` | BSD-3-Clause | sprout, farmer, saasapi, farmerbus, imas CLI |
| `golang.org/x/sync` | BSD-3-Clause | sprout, farmer, saasapi, migrate, imas CLI |
| `golang.org/x/sys` | BSD-3-Clause | all six |
| `golang.org/x/term` | BSD-3-Clause | imas CLI |
| `golang.org/x/text` | BSD-3-Clause | sprout, farmer, saasapi, farmerbus, imas CLI |
| `golang.org/x/time` | BSD-3-Clause | sprout, farmer, saasapi, farmerbus, imas CLI |
| `gopkg.in/warnings.v0` | BSD-2-Clause | sprout |
| `modernc.org/libc` | BSD-3-Clause; its `LICENSE-3RD-PARTY.md` adds notices for code taken from Go (BSD-3-Clause), musl (MIT), go-netdb and nixpkgs | none: only `internal/fleetcatalog/fleetcatalogtest`, a test helper, imports it (through `github.com/glebarez/sqlite`, MIT) |
| `modernc.org/mathutil` | BSD-3-Clause | none: only `internal/fleetcatalog/fleetcatalogtest`, a test helper, imports it (through `github.com/glebarez/sqlite`, MIT) |
| `modernc.org/memory` | BSD-3-Clause | none: only `internal/fleetcatalog/fleetcatalogtest`, a test helper, imports it (through `github.com/glebarez/sqlite`, MIT) |
| `modernc.org/sqlite` | BSD-3-Clause | none: only `internal/fleetcatalog/fleetcatalogtest`, a test helper, imports it (through `github.com/glebarez/sqlite`, MIT) |

Notes on the MPL-2.0 modules:

- `github.com/openbao/openbao/api/v2` is the official OpenBao Go client
  behind `internal/openbao` (every server-side OpenBao identity) and the
  sprout's `sdb://openbao` provider (`internal/ingredients/sdb/openbao`), so it
  ships in the sprout binary. The eight `github.com/hashicorp/*` MPL-2.0
  modules above are its dependencies and link wherever it does.
- `github.com/go-sql-driver/mysql` is the PXC/MySQL store.
- `github.com/cyphar/filepath-securejoin` comes in through go-git. Its full
  source is saved because the module carries MPL-2.0 code, though the sprout
  links none of it.

None of the modules above needs CGO.

## Deployed components

Images the Helm charts run that are not part of the Go build:

| Component | Licence | Where |
|---|---|---|
| Versity Gateway (`versitygw`, `docker.io/versity/versitygw`, pinned by digest) | Apache-2.0 | `deploy/helm/farmer`, optional (`versity.enabled`, off by default): the S3 gateway in front of Azure Blob, the production object store (design D18) |

The chart subcharts (OpenBao, PXC, Valkey) and their licences are listed in
`deploy/helm/farmer/README.md`, "Licensing".

[go.mod]: go.mod
[dependencies]: dependencies
