# Installation

Note these are only rough installation instructions.
If you have any issues, please [report a bug](https://github.com/yogzblr/imas/issues/new/choose).
This repo is seeing many rapid changes and you'll likely get a response within a couple of days.

## Basic Topology

imas is a one-to-many client-server system. You'll need to provision one server
as a control server, designated as the `farmer`. All other systems you wish to
control and manage are `sprout`s. If you wish, the farmer may also run as a sprout,
allowing you to manage the farmer alongside the other systems using the same stack.

Unlike other management systems, imas comes with a command line utility, also named
`imas`, which may be run on a developer's machine or on a hardened jump server,
but *the command line utility does not need to run on the farmer itself.* This
critical difference allows users and orgs to employ RBAC and track which user
is running each command and easily establish a trail of accountability.

Where other tools require all users to log into the control server directly
and dispatch controlled commands via sudo/doas or as the root user, imas
allows each user to securely auth against the control server but use their own
systems (or dedicated jump servers), opening up many more options for hardening.

## Acquiring imas

The `farmer`, `sprout`, and `imas` cli may be grabbed from the releases tab on
GitHub. Note that only Linux is officially supported for the farmer and sprout
at this time. Future support for Windows and macOS is forthcoming for the sprout,
but the farmer will only support Linux. The imas CLI officially supports Linux
and macOS, Windows likely works but is not included in the releases as it's not
officially supported yet.

It is also possible to build the binaries yourself by cloning the repo
and using the Makefile: this will build and drop the built binaries into `bin`.

On linux:
    `make`

On any other operating system:
    `GOOS=linux make`

Note you will have to have a working go toolchain to build imas.
See the install instructions for your operating system [here](https://go.dev/doc/install).



## Farmer Installation

It's recommended to run the farmer as an unprivledged user on the server,
with read/write access to `/etc/imas`.
1. Place the `farmer` bin at `/usr/local/bin/imas-farmer` and copy the example
`imas-farmer.service` file into `/etc/systemd/system/imas-farmer.service`.
1. Set up the user:

```bash
useradd farmer
mkdir -p /etc/imas
chown farmer:farmer /etc/imas
systemctl daemon-reload
systemctl enable --now imas-farmer
```
3. Configure at least one imas CLI to set up the keys, then return to the farmer to restart the service.

## Command Line Installation

1. Acquire a copy of imas and put it into your path.
1. Run `imas auth` and hit 'n' to reject the public key.
1. Edit your config (usually ~/.config/imas/imas) to point the farmer interface
and URL to the farmer install.
1. Run `imas auth privkey` to generate a new private key. Hit enter to pin the
farmer's TLS certificate.
1. Run `imas auth pubkey` to see your public key (from your config file).
1. Edit the configuration *on the farmer* to add the following:
```yaml
pubkeys:
    admin:
        - <YOUR PUBKEY HERE>
```
7. On the farmer, run `systemctl restart imas-farmer`
8. On the system where you've set up the CLI, run `imas version` to validate you
have authenticated with the farmer correctly.

## Sprout Installation

The sprout should run as the root user to allow configuration of all system
files.
To install the sprout:
1. Drop the `sprout` binary into `/usr/local/bin/imas-sprout`
1. Drop the sample systemd service file (`imas-sprout.service`) into `/etc/systemd/system/imas-sprout.service`
1. Create a config file at /etc/imas/sprout:
```yaml
farmerinterface: <DOMAIN OR IP HERE>
farmerurl: https://<DOMAIN OR IP HERE>:5405
```
4. Run `systemctl daemon-reload && systemctl enable --now imas-sprout`

## Required Ports
All traffic flows in one direction: cli/sprout to farmer. The farmer needs two ports,
which default to 5405 and 5406 (TCP). Make sure traffic can flow to these ports
from the sprouts and the cli, and you should be good to go.
