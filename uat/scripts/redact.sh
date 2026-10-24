# shellcheck shell=bash
# redact.sh: the UAT gate's redaction filter, sourced (not run) by
# diagnostics.sh, collect-artifacts.sh, uat/tests/run.sh and
# uat/access/channel.sh (W10).
#
#   . uat/scripts/redact.sh
#   some command | redact
#
# redact copies stdin to stdout with anything secret-shaped replaced by
# [redacted]: private key blocks, Bearer, Basic, NTLM and Negotiate
# Authorization credentials, values of keys that look like a password
# (password, passwd: not a bare "pass", or go test's "--- PASS: TestX" would go),
# secret, token, access or secret key or credential, JWTs, NKey seeds, and
# base64 runs of 400 characters or more (a sealed payload, an NTLM blob or
# a key file is never that short in a log line, and nothing the report needs
# is). Where collect-artifacts.sh's scan matches a key name itself
# (client-key-data:, "unseal_keys...", "registration_key"), the key goes
# too, so the scan never matches redact's output: a file that went through
# it is uploaded rather than deleted.
# GNU sed writes each line as it comes (-u): run.sh streams the tests'
# output through redact into the job log and build.log.
_redact_flags=(-E)
if sed --version >/dev/null 2>&1; then _redact_flags+=(-u); fi
redact() {
  sed "${_redact_flags[@]}" \
    -e '/-----BEGIN [A-Z ]*PRIVATE KEY-----/,/-----END [A-Z ]*PRIVATE KEY-----/c\[redacted private key]' \
    -e 's/(Bearer[[:space:]]+)[^[:space:]",;}]+/\1[redacted]/Ig' \
    -e 's/(Authorization"?[[:space:]]*[:=][[:space:]]*"?Basic[[:space:]]+)[^[:space:]",;}]+/\1[redacted]/Ig' \
    -e 's/((NTLM|Negotiate)[[:space:]]+)[A-Za-z0-9+/]{8,}={0,2}/\1[redacted]/g' \
    -e 's/TlRMTVNTUA[A-Za-z0-9+/]*={0,2}/[redacted ntlm]/g' \
    -e 's/(client-(key|certificate)-data)[[:space:]]*:[[:space:]]*[^[:space:]]+/\1 [redacted]/g' \
    -e 's/((pass(word|wd)|secret|token|access[_-]?key|secret[_-]?key|api[_-]?key|credential|client-key-data|client-certificate-data|root[_-]?(user|pass(word)?))[A-Za-z0-9_.-]*"?[[:space:]]*[:=][[:space:]]*)("[^"]*"|[^[:space:],;}]+)/\1[redacted]/Ig' \
    -e 's/eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*/[redacted jwt]/g' \
    -e 's/(^|[^A-Z0-9])S[OAUNCX][A-Z2-7]{56}([^A-Z2-7]|$)/\1[redacted seed]\2/g' \
    -e 's/[A-Za-z0-9+/_-]{400,}={0,2}/[redacted long base64]/g' \
    -e 's/"unseal_keys[a-z0-9_]*"[[:space:]]*:[[:space:]]*(\[[^]]*\]|"[^"]*")/"[redacted]": null/g' \
    -e 's/"registration_key"[[:space:]]*:[[:space:]]*("[^"]*"|[^[:space:],}]+)/"[redacted]": null/g'
}
