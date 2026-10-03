<p align="center">
  <img src="docs/logos/imas-banner.png" alt="imas — Infrastructure Management At Scale" width="100%">
</p>

# imas — Infrastructure Management At Scale

[![License 0BSD](https://img.shields.io/badge/License-0BSD-pink.svg)](https://opensource.org/licenses/0BSD)
[![Go Report Card](https://goreportcard.com/badge/github.com/yogzblr/imas)](https://goreportcard.com/report/github.com/yogzblr/imas) [![GoDoc](https://img.shields.io/badge/GoDoc-reference-007d9c)](https://pkg.go.dev/github.com/yogzblr/imas)
[![CodeQL](https://github.com/yogzblr/imas/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/yogzblr/imas/actions/workflows/codeql-analysis.yml)
[![govulncheck](https://github.com/yogzblr/imas/actions/workflows/govulncheck.yml/badge.svg)](https://github.com/yogzblr/imas/actions/workflows/govulncheck.yml)
[![GitHub commit activity (branch)](https://img.shields.io/github/commit-activity/m/yogzblr/imas)](https://github.com/yogzblr/imas)

imas is a pure-[Go](http://golang.org) DevOps automation engine designed to use few system resources and keep your application front and center.

> imas began as a fork of [gogrlx/grlx](https://github.com/gogrlx/grlx) and has since diverged into its own project.

## Quick Start

imas no longer installs as a single `farmer` with an embedded bus, so the
old bootstrap-script quick start (one control server, sprouts dialing it
directly, `imas keys accept` to approve them) doesn't apply any more.
[docs/INSTALL.md](docs/INSTALL.md) is the install guide. In outline:

1. Build the binaries with `make` (they land in `bin/`), or use the
   release images and packages once a release has been cut. None has been
   yet; see [docs/BUILD-STATUS.md](docs/BUILD-STATUS.md).
2. Install the core Helm chart, [`deploy/helm/farmer`](deploy/helm/farmer/README.md)
   (`farmer` and `saasapi`, with PXC, OpenBao and Valkey either bundled for
   an eval or external), then the DMZ chart,
   [`deploy/helm/nats`](deploy/helm/nats/README.md) (`farmerbus` and Envoy).
3. Create a tenant and mint a one-time enrollment key through the SaaS API.
4. Install `imas-sprout` on each managed host with that key as its join
   token. It enrolls through Envoy and connects to the bus with its own JWT.
   The Ansible role [`imas_sprout`](ansible/README.md) does this for a fleet.

## Documentation

Please see the [official docs site](https://docs.imas.dev) for complete documentation.

## Why imas?

Our team started out using competing solutions, and we ran into scalability issues.
Python is a memory hog and is interpreted to boot.
Many systems struggle with installing Python dependencies properly, and with so many moving parts, the probability of something going wrong increases.

## Architecture

imas runs in two tiers, with the managed hosts outside both:

- **DMZ:** `farmerbus` (the NATS bus) behind an Envoy gateway. These are the only things sprouts ever connect to.
- **Core (non-DMZ):** `farmer` (the API, job dispatch and tenant provisioning), `saasapi` (the multi-tenant control-plane API) and `fleetreleaser` (signs sprout update manifests), with PXC, Valkey, OpenBao and object storage. The core connects out to the bus; the bus never connects in.
- **Sprouts:** the `sprout` daemon on each managed system (a 'sprout'), enrolled into one tenant.

The `imas` CLI is optional: it talks to farmer's TLS API and to the bus.

<p align="center"><img src="docs/diagrams/imas-architecture.svg" width="100%" alt="imas architecture: sprouts, the DMZ (farmerbus, Envoy) and the non-DMZ core (farmer, saasapi, PXC, Valkey, OpenBao), with the enrollment and payload-encryption flows"></p>

## Batteries Included

imas is split into a DMZ tier and a core tier. `farmerbus` runs the messaging Pub-Sub server ([NATS](https://github.com/nats-io/nats-server)) behind an Envoy gateway in the DMZ; `farmer` (the core, with its API server) and `saasapi` (the multi-tenant control plane) run outside the DMZ and connect to the bus outbound only.
Nodes running `sprout` enroll once with a one-time key, then connect to the bus with their own JWT.
The API server and the bus use TLS. Command (`cmd.run`) and recipe (`cook`) payloads are additionally sealed with per-tenant and per-sprout keys; interactive shell, facts and some other traffic are not yet (see [docs/BUILD-STATUS.md](docs/BUILD-STATUS.md)). See [docs/INSTALL.md](docs/INSTALL.md) and [docs/diagrams/imas-architecture.svg](docs/diagrams/imas-architecture.svg).

Jobs can be created with the `imas` command-line interface and typically come in the form of stateful targets called 'recipes'.
Recipes are yaml documents which describe the desired state of a sprout after the recipe is applied (`cook`ed).
Because the `farmer` exposes an API, `imas` is by no means the only way to create or manage jobs, but it is the only supported method at the beginning.

## Sponsors

A big thank you to all of imas's sponsors.
If you're a small company or individual user and you'd like to donate to imas's development, you can donate to individual developers using the GitHub Sponsors button.

For prioritized and commercial support, we have partnered with ADAtomic, Inc., to offer official, on-call hours.
For more information, please [contact the team](mailto:imas@adatomic.com) via email.

### Founders Club

<p align="left">
    <a href="https://newleafsolutions.dev">
        <img src="docs/logos/newleaf.png" width="125" alt="New Leaf Solutions">
    </a>
    <a href="https://github.com/ADAtomic">
        <img src="docs/logos/adatomic.png" width="125" alt="ADAtomic, inc.">
    </a>
</p>

## Early Adopters

If you or your company use imas and you'd like to be added to this list, [Create an Issue](https://github.com/yogzblr/imas/issues/new?assignees=taigrr&labels=docs&projects=&template=add_my_company.md&title=%5BUSER%5D).

<p align="left">
    <a href="https://www.cellpointsystems.com/software-development">
        <img src="docs/logos/cellpointsystems.png" width="125" alt="Cellpoint Systems, Inc.">
    </a>
    <a href="https://dendra.science">
        <img src="docs/logos/dendrascience.png" width="125" alt="Dendra Science">
    </a>
    <a href="https://newleafsolutions.dev">
        <img src="docs/logos/newleaf.png" width="125" alt="New Leaf Solutions, Inc.">
    </a> 
    <a href="https://google.com">
        <img src="docs/logos/google.png" width="125" alt="Google, Inc.">
    </a>
    <a href="https://github.com/ADAtomic">
        <img src="docs/logos/adatomic.png" width="125" alt="ADAtomic, Inc.">
    </a>
    <a href="https://gladhost.cloud">
        <img src="docs/logos/gladhost.png" width="125" alt="GLADHOST">
    </a>
</p>


## Package Hosting

Package repository hosting is graciously provided by [Cloudsmith](https://cloudsmith.com).
Cloudsmith is the only fully hosted, cloud-native, universal package management solution, that
enables your organization to create, store and share packages in any format, to any place, with total
confidence.

## License

Dependencies may carry their own license agreements.
To see the licenses of dependencies, please view [DEPENDENCIES.md](https://github.com/yogzblr/imas/blob/master/DEPENDENCIES.md).

Unless otherwise noted, the imas source files are distributed under the 0BSD license found in the [LICENSE](https://github.com/yogzblr/imas/blob/master/LICENSE) file.

All imas logos are Copyright 2021 Tai Groot and Licensed under CC BY 3.0.
