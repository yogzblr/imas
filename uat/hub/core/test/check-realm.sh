#!/usr/bin/env bash
# check-realm.sh [realm.json]: jq checks of the imas-uat realm import file
# against what saasapi expects (docs/api/saasapi.md, "Authentication" and
# "Recipes"; deploy/helm/farmer values saasapi.recipes.*Role and
# saasapi.jwt.*). Exits non zero, naming each failed check.
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
realm="${1:-$here/../chart/files/imas-uat-realm.json}"
command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }

failed=0
# t <description> <jq expression that must be true>
t() {
	if jq -e "$2" "$realm" >/dev/null 2>&1; then
		printf 'ok    realm: %s\n' "$1"
	else
		printf 'FAIL  realm: %s\n' "$1"
		failed=$((failed + 1))
	fi
}
up='.components["org.keycloak.userprofile.UserProfileProvider"][0].config["kc.user.profile.config"][0] | fromjson'
tests_client='.clients[] | select(.clientId == "imas-uat-tests")'
user() { printf '.users[] | select(.username == "%s")' "$1"; }

t "is valid JSON for realm imas-uat" '.realm == "imas-uat" and .enabled == true'
# The issuer is <frontendUrl>/realms/imas-uat; frontendUrl is the core FQDN
# URL that Keycloak's env (UAT_KEYCLOAK_URL, chart keycloak.yaml) supplies.
t "issuer base is the core FQDN URL placeholder" '.attributes.frontendUrl == "${UAT_KEYCLOAK_URL}"'
t "realm roles are exactly imas-recipes-read and imas-recipes-write" \
	'[.roles.realm[].name] | sort == ["imas-recipes-read", "imas-recipes-write"]'
t "audience client imas-saasapi issues no tokens" \
	'.clients[] | select(.clientId == "imas-saasapi") | .bearerOnly == true and .directAccessGrantsEnabled == false and .standardFlowEnabled == false'
t "test client is confidential, password grant only" \
	"$tests_client"' | .publicClient == false and .directAccessGrantsEnabled == true and .standardFlowEnabled == false and .implicitFlowEnabled == false and .serviceAccountsEnabled == false'
t "test client secret is a per-run placeholder" "$tests_client"' | .secret == "${UAT_TESTS_CLIENT_SECRET}"'
t "test client adds audience imas-saasapi to access tokens" \
	"$tests_client"' | .protocolMappers[] | select(.protocolMapper == "oidc-audience-mapper") | .config["included.client.audience"] == "imas-saasapi" and .config["access.token.claim"] == "true"'
t "test client maps organization_id to the organization.id claim" \
	"$tests_client"' | .protocolMappers[] | select(.protocolMapper == "oidc-usermodel-attribute-mapper") | .config["user.attribute"] == "organization_id" and .config["claim.name"] == "organization.id" and .config["access.token.claim"] == "true" and .config["jsonType.label"] == "String"'
t "four users, two per tenant" '[.users[].username] | sort == ["t1-admin", "t1-reader", "t2-admin", "t2-reader"]'
for u in t1-admin t2-admin; do
	t "$u holds both recipe roles" "$(user "$u")"' | (.realmRoles | index("imas-recipes-read")) and (.realmRoles | index("imas-recipes-write"))'
done
for u in t1-reader t2-reader; do
	t "$u holds the read role only" "$(user "$u")"' | (.realmRoles | index("imas-recipes-read")) and ((.realmRoles | index("imas-recipes-write")) | not)'
done
t "every password is a per-run placeholder, none committed" \
	'all(.users[]; (.credentials | length) == 1 and (.credentials[0].value | test("^\\$\\{UAT_T[12]_(ADMIN|READER)_PASSWORD\\}$")) and .credentials[0].temporary == false)'
t "each user's password placeholder is its own" \
	'all(.users[]; .credentials[0].value == ("${UAT_" + (.username | ascii_upcase | sub("-"; "_")) + "_PASSWORD}"))'
t "no user carries an organization_id at import (bind-tenant.sh sets it)" \
	'all(.users[]; (.attributes.organization_id // null) == null)'
t "no user has a pending required action (the password grant would fail)" 'all(.users[]; (.requiredActions // []) == [])'
t "user profile: organization_id is admin-edit and admin-view only" \
	"$up"' | .attributes[] | select(.name == "organization_id") | .permissions.edit == ["admin"] and .permissions.view == ["admin"]'
t "user profile: users can edit nothing" "$up"' | all(.attributes[]; .permissions.edit == ["admin"])'
t "no other \${...} placeholder than the six per-run values" \
	'[.. | strings | scan("\\$\\{[^}]*\\}")] | unique | sort == ["${UAT_KEYCLOAK_URL}", "${UAT_T1_ADMIN_PASSWORD}", "${UAT_T1_READER_PASSWORD}", "${UAT_T2_ADMIN_PASSWORD}", "${UAT_T2_READER_PASSWORD}", "${UAT_TESTS_CLIENT_SECRET}"]'
t "self registration and password reset are off" '.registrationAllowed == false and .resetPasswordAllowed == false'

((failed == 0)) || { echo "$failed realm check(s) failed" >&2; exit 1; }
