# imas-saasapi-cred-publisher: the publish Job's policy, and ONLY the
# publish Job's (`farmer publish-saasapi-credential`, internal/saasapicred).
# The one grant in imas with write access to the published SaaS API JWT.
# Source: deploy/farmer/README.md, "OpenBao policy"; chart_test.go checks
# the policy statements below still match it.
#
# FLAG FOR SECURITY REVIEW.
#   - create/update: the KV v2 write. read: the idempotency check.
#   - Never patch, delete or list; nothing on secret/metadata/,
#     secret/delete/, secret/undelete/ or secret/destroy/; no "*" or "+";
#     nothing on the seed path.
#   - Attach it to the imas-saasapi-cred-publisher role only, bound to the
#     publisher ServiceAccount only. Never to a role farmer can log in with.

path "secret/data/platform/imas/saasapi-nats-user" {
  capabilities = ["create", "update", "read"]
}
