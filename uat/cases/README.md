# Ingredient conformance cases (UAT.7)

One case file per registered ingredient method, run by
`uat/tests/ingredients` as the `ingredients` tier of the UAT gate
([plan section 4h](../../docs/claude-code-parallel-build-plan.md#4h-azure-uat-gate-uat1-to-uat8)).
[INVENTORY.md](INVENTORY.md) lists every method a sprout registers, per
platform, with its properties. It is generated from the source, not
written by hand.

**Status: no case has run on a real sprout yet.** The cases were written
from reading each ingredient's code, and the runner was tested against a
fake sprout only. Windows Server 2022 Core may not support some of them
(shortcuts, DSC over local WinRM, features whose payload was removed). Such
a case will fail there, and the owner decides whether to use a Desktop
Experience image or turn the case into a skip.

## Layout

`<ingredient>/<method>.yaml`, one per `I.<ingredient>.<method>`. The id
decides the file name. There are also cases for methods a package registers
that no sprout imports (`win_dacl`, all skips) and for the `sdb://` secret
backends (`sdb/<backend>.yaml`, with `backend:`).

## The cycle

On each sprout of a matching OS in tenant 1, in `(order, id)` order on one
sprout and in parallel across sprouts:

1. **setup** (host script, optional). It must exit 0.
2. Upload the recipe to the tenant as `uat.i.<ingredient>.<method>.<nonce>`.
3. **Cook in test mode.** The item must succeed. Then **check** out of band:
   with `pre_check: absent` (the default) the check must still fail, which
   shows test mode changed nothing. The sprout's job log for the cook must
   show every step completed.
4. **Cook for real.** The item must succeed and at least one step must
   report a change (`changes: true`, the default).
5. **Cook in test mode again**, then **for real again**. The second real
   cook must report no change (`idempotent: true`, the default).
6. **Check** out of band. The check must exit 0 and print `expect_output` if
   that is set.
7. **Revert** (always, even after a failure): cook `revert_recipe` if set,
   then run the `revert` script. Remove the recipes from the tenant.

Cases marked `tenant2: true` run on tenant 2's sprouts too. After tenant
2's real cook, its check runs on tenant 1's sprout of the same OS, which
has the same sproutid, and must fail there. Only cases whose check depends
on the per-run nonce can be in this subset.

**Test mode can't show a pending change.** The sprout drops a test mode
step's `Changed` and notes (`internal/cook/sproutcook.go`), so neither the
API nor the job log carries them. The cycle asserts it by effect instead,
as UAT.5's R5 does: test mode succeeds, its steps complete and the host is
untouched. The changes and idempotency are read from the sprout's own job
log (`<joblogdir>/<jid>.jsonl`, by the batch item's jid) through
`vmctl.sh run`, because batch items carry only a status.

## Case format (YAML, unknown fields are errors)

| Field | Meaning |
|---|---|
| `id` | `I.<ingredient>.<method>`, required |
| `title` | one line |
| `os` | sprout OSes the case runs on: `ubuntu`, `alma`, `windows` |
| `skip` | a written reason the whole case doesn't run (a documented skip) |
| `skip_os` | `{os: reason}`: an OS the method is registered on where the case doesn't run |
| `needs` | what it depends on beyond a plain sprout: `internet`, `reboot`, `openbao`, `winrm-local`, `windows-feature:<name>`, `second-nic`, ... |
| `order` | default 100. A case that needs `reboot` must be at 900 or more (it runs last) |
| `tenant2` | repeat on tenant 2 with the cross-tenant check |
| `changes` | default `true`: the first real cook reports a change. `false` for assertion methods (`file.exists`, probes) |
| `idempotent` | default `true`: the second real cook reports none. `false` where the method acts on every run by design (`cmd.run`, `service.restarted`) |
| `pre_check` | `absent` (default), `present` (the state is already there: assertion methods), `none` (no check) |
| `timeout` | each cook's limit, a Go duration (default `6m`) |
| `backend` | for a backend case: `sdb:<name>` |
| `notes` | why the change is harmless, and what reading the code says the result will be |
| `linux`, `windows` | the family's part (below) |
| `ubuntu`, `alma` | an OS's own part, laid over `linux` field by field |

A part has `setup`, `recipe`, `check`, `expect_output`, `revert_recipe` and
`revert`. Scripts are POSIX `sh` run as root on Linux, and PowerShell run as
SYSTEM in a child `powershell.exe -File` on Windows. A script reports failure
with a non-zero exit status (`exit 1`; on Windows an uncaught error exits 1).
The recipe holds only the steps under test, written literally: no `{{ }}`,
because farmer renders recipes as templates. Placeholders, filled per case
and sprout:

| Placeholder | Value |
|---|---|
| `@NONCE@` | 8 random lowercase letters and digits, fresh for every case on every sprout |
| `@TMP@` | `/var/tmp`, or `C:\Windows\Temp` |
| `@SRCTMP@` | the temp directory as a file `source` (`/Windows/Temp` on Windows: the file ingredient reads a path that starts with `/` as the file protocol) |
| `@TENANT@` | 1 or 2 |
| `@SPROUT_ID@` | the sprout's ID |
| `@CASE@` | the id with dots as dashes |

## Harmless changes

Nothing touches the sprout's own connection, the default firewall policy, or
anything that needs a reboot:

- **Firewall:** a table of its own with a hookless chain on Linux; one
  inbound block rule for an unused port on Windows.
- **Network:** a dummy interface with RFC 5737 TEST-NET addresses and routes.
- **Mount:** a 1 MiB tmpfs under `/var/tmp`. fstab lines are `noauto`.
- **SELinux:** runtime mode and booleans only, restored by the revert.
- **lgpo:** an ADMX of its own and a `registry.pol` in the temp directory,
  never the machine's.
- **Certificates:** a throwaway public certificate in the Personal store.
- **Server Manager:** `Telnet-Client`.
- **Services:** throwaway units (Linux) and a throwaway service plus the
  Print Spooler's state, recorded and restored (Windows).

Changing DNS, installing Windows updates, IIS, SMTP and SNMP are skips that
say why, so the owner can decide.

## Coverage

`go test ./...` runs `TestCoverage` (in `uat/tests/ingredients`). It fails
when a method the source registers, on an OS it applies to, has neither a
case that runs there nor a written skip. It also fails when a case names
something not registered, lists an OS the method isn't registered on, or
whose recipe doesn't cook the method. So a new ingredient fails CI until it
has a case. In a UAT run, `TestIngredientsCoverage` does the same, logs
every skip with its reason, and writes them to
`<report>/ingredients-coverage.txt`. Each skip also shows as a `SKIP` line
in the run summary.

When the source changes, regenerate the inventory:

```sh
go test ./uat/tests/ingredients -run TestInventoryUpToDate -update
```

## Running

```sh
IMAS_UAT_DIR=... uat/tests/run.sh ingredients                     # all cases
IMAS_UAT_DIR=... uat/tests/run.sh ingredients I.file.content I.cron.present
IMAS_UAT_DIR=... uat/tests/run.sh lifecycle                       # L4, L5
```

Subtests are `TestIngredients/<id>/<t1-ubuntu>`. When an OS has no sprout in
the run (the local rig has no Windows), its subtest is `t1-<os>` and is
skipped with that reason. It is never passed. `IMAS_UAT_CASES_DIR` reads the
cases from somewhere else.

Lifecycle (in the same package): **L4** needs `IMAS_UAT_UPGRADE_FROM_TAG`
(the workflow input `upgrade_from_tag`) and skips without it. **L5** runs
only with `IMAS_UAT_DISPATCH_FLAGS=on` (saasapi with
`SAASAPI_FLEET_UPDATE_DISPATCH_ENABLED=true` and farmer with
`IMAS_SELF_UPDATE_ENABLED=true`) plus `IMAS_UAT_UPGRADE_FROM_TAG` and
`IMAS_UAT_RELEASE_TAG`. Both run on the Linux sprouts of tenant 1. Windows is
a skip with the reason, as in S6.
