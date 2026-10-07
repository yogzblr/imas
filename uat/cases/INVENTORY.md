<!-- generated from the source by uat/tests/ingredients (RenderInventory); do not edit by hand.
     Regenerate: go test ./uat/tests/ingredients -run TestInventoryUpToDate -update -->
# Ingredient inventory (UAT.7)

Every ingredient method a sprout registers, read from the code: the packages
`cmd/sprout` imports for each GOOS (`include.go`, `include_linux.go`,
`include_windows.go`, and what they import in turn), every
`ingredients.RegisterAllMethods(T{})` in their `init` functions, and `T`'s
`Methods()` and `PropertiesForMethod()`. Build constraints are applied per
GOOS with CGO off, as the sprout is built. Linux means the Ubuntu 24.04 and
AlmaLinux 9 sprouts of the UAT gate; Windows means Windows Server 2022 Core.

**100 methods** in 32 ingredients: 46 on both platforms, 22 on Linux only, 32 on Windows only.
Each has a case file `uat/cases/<ingredient>/<method>.yaml` (format: [README.md](README.md)).

Properties: `*` marks a required one. A note says when they couldn't be read
from the source or look wrong.


## cmd

Package `internal/ingredients/cmd`, type `Cmd`.

| Case id | OS | Properties |
|---|---|---|
| `I.cmd.run` | Linux (ubuntu, alma), Windows | `name`* string, `args` string, `env` []string, `cwd` string, `runas` string, `path` string, `timeout` string |

## cron

Package `internal/ingredients/cron`, type `Cron`.

| Case id | OS | Properties |
|---|---|---|
| `I.cron.absent` | Linux (ubuntu, alma) | `name`* string, `command` string, `user` string, `identifier` string |
| `I.cron.present` | Linux (ubuntu, alma) | `name`* string, `command`* string, `user` string, `identifier` string, `minute` string, `hour` string, `dayofmonth` string, `month` string, `dayofweek` string |

## file

Package `internal/ingredients/file`, type `File`.

| Case id | OS | Properties |
|---|---|---|
| `I.file.absent` | Linux (ubuntu, alma), Windows | `name`* string (note: PropertiesForMethod switches on the receiver's method field, not its argument: File{}.PropertiesForMethod("absent") returns an error (finding)) |
| `I.file.append` | Linux (ubuntu, alma), Windows | `name`* string, `makedirs` bool, `source` string, `source_hash` string, `source_hashes` []string, `sources` []string, `template` bool, `text` []string (note: PropertiesForMethod switches on the receiver's method field, not its argument: File{}.PropertiesForMethod("append") returns an error (finding)) |
| `I.file.cached` | Linux (ubuntu, alma), Windows | `name`* string, `hash` string, `skip_verify` bool, `source`* string (note: PropertiesForMethod switches on the receiver's method field, not its argument: File{}.PropertiesForMethod("cached") returns an error (finding)) |
| `I.file.contains` | Linux (ubuntu, alma), Windows | `name`* string, `source` string, `source_hash` string, `source_hashes` []string, `sources` []string, `template` bool, `text` []string (note: PropertiesForMethod switches on the receiver's method field, not its argument: File{}.PropertiesForMethod("contains") returns an error (finding)) |
| `I.file.content` | Linux (ubuntu, alma), Windows | `name`* string, `text` []string, `makedirs` bool, `source` string, `source_hash` string, `template` bool, `sources` []string, `source_hashes` []string (note: PropertiesForMethod switches on the receiver's method field, not its argument: File{}.PropertiesForMethod("content") returns an error (finding)) |
| `I.file.copy` | Linux (ubuntu, alma), Windows | `name`* string, `source`* string, `direction` string, `glob` string, `exclude` []string, `mkdir` bool, `chmod_x` bool (note: PropertiesForMethod switches on the receiver's method field, not its argument: File{}.PropertiesForMethod("copy") returns an error (finding)) |
| `I.file.directory` | Linux (ubuntu, alma), Windows | `name`* string, `user` string, `group` string, `recurse` bool, `dir_mode` string, `file_mode` string, `makedirs` bool (note: PropertiesForMethod switches on the receiver's method field, not its argument: File{}.PropertiesForMethod("directory") returns an error (finding)) |
| `I.file.exists` | Linux (ubuntu, alma), Windows | `name`* string (note: PropertiesForMethod switches on the receiver's method field, not its argument: File{}.PropertiesForMethod("exists") returns an error (finding)) |
| `I.file.line` | Linux (ubuntu, alma), Windows | `name`* string, `mode`* string, `match` string, `content` string, `location` string (note: PropertiesForMethod switches on the receiver's method field, not its argument: File{}.PropertiesForMethod("line") returns an error (finding)) |
| `I.file.managed` | Linux (ubuntu, alma), Windows | `name`* string, `source`* string, `source_hash` string, `user` string, `group` string, `mode` string, `template` bool, `makedirs` bool, `dir_mode` string, `sources` []string, `source_hashes` []string (note: PropertiesForMethod switches on the receiver's method field, not its argument: File{}.PropertiesForMethod("managed") returns an error (finding)) |
| `I.file.missing` | Linux (ubuntu, alma), Windows | `name`* string (note: PropertiesForMethod switches on the receiver's method field, not its argument: File{}.PropertiesForMethod("missing") returns an error (finding)) |
| `I.file.prepend` | Linux (ubuntu, alma), Windows | `name`* string, `text` []string, `makedirs` bool, `source` string, `source_hash` string, `template` bool, `sources` []string, `source_hashes` []string (note: PropertiesForMethod switches on the receiver's method field, not its argument: File{}.PropertiesForMethod("prepend") returns an error (finding)) |
| `I.file.symlink` | Linux (ubuntu, alma), Windows | `name`* string, `target`* string, `makedirs` bool, `user` string, `group` string, `mode` string (note: PropertiesForMethod switches on the receiver's method field, not its argument: File{}.PropertiesForMethod("symlink") returns an error (finding)) |
| `I.file.sync` | Linux (ubuntu, alma), Windows | `name`* string, `source`* string, `delete` bool, `exclude` []string, `mkdir` bool (note: PropertiesForMethod switches on the receiver's method field, not its argument: File{}.PropertiesForMethod("sync") returns an error (finding)) |
| `I.file.touch` | Linux (ubuntu, alma), Windows | `name`* string, `atime` string, `mtime` string, `makedirs` bool (note: PropertiesForMethod switches on the receiver's method field, not its argument: File{}.PropertiesForMethod("touch") returns an error (finding)) |

## firewall

Package `internal/ingredients/firewall`, type `Firewall`.

| Case id | OS | Properties |
|---|---|---|
| `I.firewall.chain_absent` | Linux (ubuntu, alma) | `name`* string, `table`* string, `family` string |
| `I.firewall.chain_present` | Linux (ubuntu, alma) | `name`* string, `table`* string, `family` string, `hook` string, `type` string, `priority` string, `policy` string |
| `I.firewall.rule_absent` | Linux (ubuntu, alma) | `name`* string, `table`* string, `chain`* string, `family` string |
| `I.firewall.rule_present` | Linux (ubuntu, alma) | `name`* string, `table`* string, `chain`* string, `family` string, `protocol` string, `saddr` string, `daddr` string, `sport` string, `dport` string, `iifname` string, `oifname` string, `action`* string, `counter` bool, `position` string |
| `I.firewall.table_absent` | Linux (ubuntu, alma) | `name`* string, `family` string |
| `I.firewall.table_present` | Linux (ubuntu, alma) | `name`* string, `family` string |

## group

Package `internal/ingredients/group`, type `Group`.

| Case id | OS | Properties |
|---|---|---|
| `I.group.absent` | Linux (ubuntu, alma), Windows | `name`* string |
| `I.group.exists` | Linux (ubuntu, alma), Windows | `name`* string |
| `I.group.present` | Linux (ubuntu, alma), Windows | `name`* string, `gid` string, `system` bool, `members` []string |

## lgpo

Package `internal/ingredients/lgpo`, type `LGPO`.

| Case id | OS | Properties |
|---|---|---|
| `I.lgpo.absent` | Windows | `name`* string, `admx`* string, `adml` string, `class`* string, `pol_path` string |
| `I.lgpo.present` | Windows | `name`* string, `admx`* string, `adml` string, `class`* string, `state`* string, `pol_path` string |

## mount

Package `internal/ingredients/mount`, type `Mount`.

| Case id | OS | Properties |
|---|---|---|
| `I.mount.fstab_absent` | Linux (ubuntu, alma) | `name`* string |
| `I.mount.fstab_present` | Linux (ubuntu, alma) | `name`* string, `device`* string, `fstype`* string, `opts` []string, `dump` string, `pass` string |
| `I.mount.mounted` | Linux (ubuntu, alma) | `name`* string, `device`* string, `fstype`* string, `opts` []string, `dump` string, `pass` string, `persist` bool, `makedirs` bool, `force_remount` bool |
| `I.mount.unmounted` | Linux (ubuntu, alma) | `name`* string, `persist` bool |

## network

Package `internal/ingredients/network`, type `Network`.

| Case id | OS | Properties |
|---|---|---|
| `I.network.address_absent` | Linux (ubuntu, alma) | `name`* string, `address`* string, `verify_connectivity` bool, `connectivity_target` string, `connectivity_timeout` string, `rollback_on_failure` bool |
| `I.network.address_present` | Linux (ubuntu, alma) | `name`* string, `address`* string, `label` string |
| `I.network.link` | Linux (ubuntu, alma) | `name`* string, `state`* string, `mtu` string, `verify_connectivity` bool, `connectivity_target` string, `connectivity_timeout` string, `rollback_on_failure` bool |
| `I.network.route_absent` | Linux (ubuntu, alma) | `destination`* string, `gateway` string, `name` string, `table` string, `verify_connectivity` bool, `connectivity_target` string, `connectivity_timeout` string, `rollback_on_failure` bool |
| `I.network.route_present` | Linux (ubuntu, alma) | `destination`* string, `gateway` string, `name` string, `metric` string, `table` string, `verify_connectivity` bool, `connectivity_target` string, `connectivity_timeout` string, `rollback_on_failure` bool |

## pkg

Package `internal/ingredients/pkg`, type `Pkg`.

| Case id | OS | Properties |
|---|---|---|
| `I.pkg.cleaned` | Linux (ubuntu, alma), Windows | `autoremove` bool, `name`* string |
| `I.pkg.group_installed` | Linux (ubuntu, alma), Windows | `name`* string |
| `I.pkg.held` | Linux (ubuntu, alma), Windows | `name`* string, `pkgs` []string |
| `I.pkg.installed` | Linux (ubuntu, alma), Windows | `fromrepo` string, `name`* string, `pkgs` []string, `refresh` bool, `reinstall` bool, `version` string |
| `I.pkg.key_managed` | Linux (ubuntu, alma), Windows | `absent` bool, `name`* string |
| `I.pkg.latest` | Linux (ubuntu, alma), Windows | `fromrepo` string, `name`* string, `pkgs` []string, `refresh` bool |
| `I.pkg.purged` | Linux (ubuntu, alma), Windows | `name`* string, `pkgs` []string |
| `I.pkg.removed` | Linux (ubuntu, alma), Windows | `name`* string, `pkgs` []string |
| `I.pkg.repo_managed` | Linux (ubuntu, alma), Windows | `absent` bool, `name`* string, `url` string |
| `I.pkg.unheld` | Linux (ubuntu, alma), Windows | `name`* string, `pkgs` []string |
| `I.pkg.upgraded` | Linux (ubuntu, alma), Windows | `fromrepo` string, `name`* string, `pkgs` []string, `refresh` bool |
| `I.pkg.uptodate` | Linux (ubuntu, alma), Windows | `name`* string, `refresh` bool |

## probe

Package `internal/ingredients/probe`, type `Probe`.

| Case id | OS | Properties |
|---|---|---|
| `I.probe.database` | Linux (ubuntu, alma), Windows | `driver`* string, `dsn`* string, `query`* string, `timeout` string, `expect_value` string |
| `I.probe.http` | Linux (ubuntu, alma), Windows | `url`* string, `method` string, `body` string, `timeout` string, `insecure_skip_verify` bool, `expect_body_contains` string |

## registry

Package `internal/ingredients/registry`, type `Registry`.

| Case id | OS | Properties |
|---|---|---|
| `I.registry.absent` | Windows | `name`* string, `vname` string |
| `I.registry.key_absent` | Windows | `name`* string, `force` bool |
| `I.registry.key_present` | Windows | `name`* string |
| `I.registry.present` | Windows | `name`* string, `vname` string, `vtype` string, `vdata`* string |

## selfupdate

Package `internal/ingredients/selfupdate`, type `SelfUpdate`.

| Case id | OS | Properties |
|---|---|---|
| `I.selfupdate.apply` | Linux (ubuntu, alma), Windows | `version`* string |

## selinux

Package `internal/ingredients/selinux`, type `SELinux`.

| Case id | OS | Properties |
|---|---|---|
| `I.selinux.boolean_off` | Linux (ubuntu, alma) | `name`* string, `persist` bool |
| `I.selinux.boolean_on` | Linux (ubuntu, alma) | `name`* string, `persist` bool |
| `I.selinux.context_present` | Linux (ubuntu, alma) | `name`* string, `context`* string, `recurse` bool |
| `I.selinux.enforcing` | Linux (ubuntu, alma) | none declared |
| `I.selinux.permissive` | Linux (ubuntu, alma) | none declared |

## service

Package `internal/ingredients/service`, type `Service`.

| Case id | OS | Properties |
|---|---|---|
| `I.service.disabled` | Linux (ubuntu, alma), Windows | none declared (note: declares no properties (PropertiesForMethod returns nil)) |
| `I.service.enabled` | Linux (ubuntu, alma), Windows | none declared (note: declares no properties (PropertiesForMethod returns nil)) |
| `I.service.masked` | Linux (ubuntu, alma), Windows | none declared (note: declares no properties (PropertiesForMethod returns nil)) |
| `I.service.reloaded` | Linux (ubuntu, alma), Windows | none declared (note: declares no properties (PropertiesForMethod returns nil)) |
| `I.service.restarted` | Linux (ubuntu, alma), Windows | none declared (note: declares no properties (PropertiesForMethod returns nil)) |
| `I.service.running` | Linux (ubuntu, alma), Windows | none declared (note: declares no properties (PropertiesForMethod returns nil)) |
| `I.service.stopped` | Linux (ubuntu, alma), Windows | none declared (note: declares no properties (PropertiesForMethod returns nil)) |
| `I.service.unmasked` | Linux (ubuntu, alma), Windows | none declared (note: declares no properties (PropertiesForMethod returns nil)) |

## user

Package `internal/ingredients/user`, type `User`.

| Case id | OS | Properties |
|---|---|---|
| `I.user.absent` | Linux (ubuntu, alma), Windows | `name`* string, `purge` bool |
| `I.user.exists` | Linux (ubuntu, alma), Windows | `name`* string |
| `I.user.present` | Linux (ubuntu, alma), Windows | `name`* string, `uid` string, `gid` string, `groups` []string, `shell` string, `home` string, `comment` string, `createhome` bool, `system` bool, `password_hash` string, `password` string |

## wait

Package `internal/ingredients/wait`, type `Wait`.

| Case id | OS | Properties |
|---|---|---|
| `I.wait.poll` | Linux (ubuntu, alma), Windows | `cmd`* string, `timeout` string, `interval` string, `negate` bool |

## win_appx

Package `internal/ingredients/winappx`, type `Package`.

| Case id | OS | Properties |
|---|---|---|
| `I.win_appx.installed` | Windows | `name`* string, `path`* string, `timeout` string |
| `I.win_appx.removed` | Windows | `name`* string, `timeout` string |

## win_auditpol

Package `internal/ingredients/winauditpol`, type `Subcategory`.

| Case id | OS | Properties |
|---|---|---|
| `I.win_auditpol.configured` | Windows | `name`* string, `success` bool, `failure` bool, `timeout` string |

## win_certutil

Package `internal/ingredients/wincertutil`, type `Cert`.

| Case id | OS | Properties |
|---|---|---|
| `I.win_certutil.cert_absent` | Windows | `name`* string, `thumbprint`* string, `store` string, `timeout` string |
| `I.win_certutil.cert_present` | Windows | `name`* string, `path`* string, `thumbprint`* string, `store` string, `timeout` string |

## win_dns_client

Package `internal/ingredients/windnsclient`, type `Interface`.

| Case id | OS | Properties |
|---|---|---|
| `I.win_dns_client.configured` | Windows | `name`* string, `servers`* []string, `timeout` string |

## win_dsc

Package `internal/ingredients/windsc`, type `Dsc`.

| Case id | OS | Properties |
|---|---|---|
| `I.win_dsc.applied` | Windows | `name`* string, `path`* string, `timeout` string |

## win_firewall

Package `internal/ingredients/winfirewall`, type `Rule`.

| Case id | OS | Properties |
|---|---|---|
| `I.win_firewall.rule_absent` | Windows | `name`* string, `timeout` string |
| `I.win_firewall.rule_present` | Windows | `name`* string, `dir` string, `action` string, `protocol` string, `localport` string, `remoteip` string, `timeout` string |

## win_iis

Package `internal/ingredients/winiis`, type `Site`.

| Case id | OS | Properties |
|---|---|---|
| `I.win_iis.started` | Windows | `name`* string, `timeout` string |
| `I.win_iis.stopped` | Windows | `name`* string, `timeout` string |

## win_pki

Package `internal/ingredients/winpki`, type `Cert`.

| Case id | OS | Properties |
|---|---|---|
| `I.win_pki.cert_absent` | Windows | `name`* string, `thumbprint`* string, `store_location` string, `store_name` string, `timeout` string |
| `I.win_pki.cert_present` | Windows | `name`* string, `path`* string, `thumbprint`* string, `store_location` string, `store_name` string, `timeout` string |

## win_powercfg

Package `internal/ingredients/winpowercfg`, type `Scheme`.

| Case id | OS | Properties |
|---|---|---|
| `I.win_powercfg.active_scheme` | Windows | `name`* string, `timeout` string |

## win_psget

Package `internal/ingredients/winpsget`, type `PSGet`.

| Case id | OS | Properties |
|---|---|---|
| `I.win_psget.installed` | Windows | `name`* string, `version` string, `scope` string, `repository` string, `timeout` string |
| `I.win_psget.removed` | Windows | `name`* string, `timeout` string |

## win_servermanager

Package `internal/ingredients/winservermanager`, type `ServerManager`.

| Case id | OS | Properties |
|---|---|---|
| `I.win_servermanager.installed` | Windows | `name`* string, `include_management_tools` bool, `timeout` string |
| `I.win_servermanager.removed` | Windows | `name`* string, `timeout` string |

## win_shortcut

Package `internal/ingredients/winshortcut`, type `Shortcut`.

| Case id | OS | Properties |
|---|---|---|
| `I.win_shortcut.absent` | Windows | `name`* string |
| `I.win_shortcut.present` | Windows | `name`* string, `target`* string, `arguments` string, `description` string, `working_dir` string, `icon_location` string, `icon_index` string, `window_style` string, `hotkey` string |

## win_smtp_server

Package `internal/ingredients/winsmtpserver`, type `Setting`.

| Case id | OS | Properties |
|---|---|---|
| `I.win_smtp_server.setting` | Windows | `name`* string, `value`* string, `timeout` string |

## win_snmp

Package `internal/ingredients/winsnmp`, type `Community`.

| Case id | OS | Properties |
|---|---|---|
| `I.win_snmp.community_absent` | Windows | `name`* string, `timeout` string |
| `I.win_snmp.community_present` | Windows | `name`* string, `permission` string, `timeout` string |

## win_task

Package `internal/ingredients/wintaskscheduler`, type `Task`.

| Case id | OS | Properties |
|---|---|---|
| `I.win_task.absent` | Windows | `name`* string |
| `I.win_task.present` | Windows | `name`* string, `command`* string, `trigger_type`* string, `arguments` string, `start_in` string, `description` string, `enabled` bool, `hidden` bool, `run_level` string, `user_name` string, `password` string, `start_date` string, `start_time` string, `days_interval` string, `weeks_interval` string, `days_of_week` []string |

## win_update

Package `internal/ingredients/winupdate`, type `Update`.

| Case id | OS | Properties |
|---|---|---|
| `I.win_update.installed` | Windows | `kb_ids`* []string, `search_criteria` string, `accept_eula` bool |

## Registered by a package no sprout imports

These packages call `RegisterAllMethods`, but `cmd/sprout` doesn't import them on
any platform, so a recipe naming them fails with "unknown ingredient" on every
sprout. Their cases are skips that say so (a finding for the owner).

| Case id | Built for | Package | Properties |
|---|---|---|---|
| `I.win_dacl.ace_absent` | Windows | `internal/ingredients/windacl` | `name`* string, `object_type`* string, `principal`* string, `access_mode`* string |
| `I.win_dacl.ace_present` | Windows | `internal/ingredients/windacl` | `name`* string, `object_type`* string, `principal`* string, `access_mode`* string, `rights`* string, `propagation` string |
| `I.win_dacl.inheritance_disabled` | Windows | `internal/ingredients/windacl` | `name`* string, `object_type`* string, `copy_inherited` bool |
| `I.win_dacl.inheritance_enabled` | Windows | `internal/ingredients/windacl` | `name`* string, `object_type`* string |

## Registries the ingredients delegate to

Not methods, but registered the same way: the `sdb://` secret backends a step's
`secrets:` resolve through, and the protocols a file `source` is fetched with.

| Registry | Name | OS | Package |
|---|---|---|---|
| file source | `file` | Linux (ubuntu, alma), Windows | `internal/ingredients/file/local` |
| file source | `http` | Linux (ubuntu, alma), Windows | `internal/ingredients/file/http` |
| file source | `https` | Linux (ubuntu, alma), Windows | `internal/ingredients/file/http` |
| sdb | `awssm` | Linux (ubuntu, alma), Windows | `internal/ingredients/sdb/awssm` |
| sdb | `azurekv` | Linux (ubuntu, alma), Windows | `internal/ingredients/sdb/azurekv` |
| sdb | `gcpsm` | Linux (ubuntu, alma), Windows | `internal/ingredients/sdb/gcpsm` |
| sdb | `openbao` | Linux (ubuntu, alma), Windows | `internal/ingredients/sdb/openbao` |
