# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| > 1.0   | :white_check_mark:                |

## Reporting a Vulnerability

Contact security@imas.dev with any relevant info including:

 - criticality
 - a summary
 - any reproduction information
 - whether or not you desire attribution
 - patches (if you have them)

Turnaround time should be within a matter of hours, at most 72 for confirmation.

If your vulnerability is accepted, we will release a new hotfix and notify users.
We will explain the vulnerability to the community after a reasonable amount of 
time has elapsed, allowing users the chance to update, and you will be credited at
this time, if you desire.

## Release Signatures

All imas releases are cryptographically signed with GPG to ensure authenticity and integrity.

### GPG Key Information

- **Key ID**: `33DCE4DD`
- **Fingerprint**: `3F62 7C68 8B72 ACC6 BC4C  A9A7 1E0B 7A1D 33DC E4DD`
- **Owner**: imas signing key <security@imas.dev>

### Importing the Public Key

```bash
# Method 1: From key servers
gpg --keyserver keyserver.ubuntu.com --recv-keys 33DCE4DD

# Method 2: From this repository
curl -s https://raw.githubusercontent.com/yogzblr/imas/master/gpg-public-key.asc | gpg --import

# Method 3: Manual import
gpg --import gpg-public-key.asc
```

### Verifying Downloads

#### GitHub Releases
```bash
# Download the files
curl -LO https://github.com/yogzblr/imas/releases/download/v1.0.0/checksums.txt
curl -LO https://github.com/yogzblr/imas/releases/download/v1.0.0/checksums.txt.sig

# Verify signature
gpg --verify checksums.txt.sig checksums.txt

# Verify binary checksum
sha256sum -c checksums.txt --ignore-missing
```

#### Cosign (keyless)
Release checksums and container images are also signed keylessly with
[cosign](https://docs.sigstore.dev/), by the `release.yml` workflow of this
repository on a `v*` tag. No key to fetch: you verify the signer's identity.
```bash
IDENTITY='^https://github\.com/yogzblr/imas/\.github/workflows/release\.yml@refs/tags/v[0-9].*$'
ISSUER=https://token.actions.githubusercontent.com

# The release checksums (then check your download against them as above)
curl -LO https://github.com/yogzblr/imas/releases/download/v1.0.0/checksums.txt.sigstore.json
cosign verify-blob --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp "$IDENTITY" --certificate-oidc-issuer "$ISSUER" checksums.txt

# A container image (farmer, sprout, saasapi, farmerbus, fleetreleaser)
cosign verify ghcr.io/yogzblr/imas-farmer:1.0.0 \
  --certificate-identity-regexp "$IDENTITY" --certificate-oidc-issuer "$ISSUER"
```

### Trust Verification

After importing the key, verify the fingerprint matches:

```bash
gpg --fingerprint 33DCE4DD
```

Expected output:
```
pub   ed25519 2025-06-08 [SC]
      3F62 7C68 8B72 ACC6 BC4C  A9A7 1E0B 7A1D 33DC E4DD
uid           imas signing key <security@imas.dev>
sub   cv25519 2025-06-08 [E]
```
