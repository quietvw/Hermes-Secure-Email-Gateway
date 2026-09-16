#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

fail() {
  echo "FAIL: $1" >&2
  exit 1
}

grep -q "include /etc/nginx/snippets/auth_admin.conf" \
  "$ROOT/config/hermes/opt/hermes/templates/hermes-ssl.conf" \
  || fail "admin location is not wired to auth_admin.conf"

grep -q "include /etc/nginx/snippets/auth_users.conf" \
  "$ROOT/config/hermes/opt/hermes/templates/hermes-ssl.conf" \
  || fail "users location is not wired to auth_users.conf"

grep -q "google_sso_auth_request.cfm?target=admin" \
  "$ROOT/config/hermes/opt/hermes/templates/hermes-ssl.conf" \
  || fail "admin auth-request bridge endpoint is missing"

grep -q "google_sso_auth_request.cfm?target=users" \
  "$ROOT/config/hermes/opt/hermes/templates/hermes-ssl.conf" \
  || fail "users auth-request bridge endpoint is missing"

grep -q "/user-auth/google_sso_verify.cfm?target=admin" \
  "$ROOT/config/hermes/var/www/html/admin/Application.cfc" \
  || fail "admin application does not use Google SSO verify bridge"

grep -q "/user-auth/google_sso_verify.cfm?target=users" \
  "$ROOT/config/hermes/var/www/html/users/Application.cfc" \
  || fail "users application does not use Google SSO verify bridge"

grep -q "googleSsoIssueSession(flowEmail, flowName)" \
  "$ROOT/config/hermes/var/www/html/user-auth/google_login.cfm" \
  || fail "google login does not issue bridge sessions"

grep -q "AND status = 'OK'" \
  "$ROOT/config/hermes/var/www/html/user-auth/google_login.cfm" \
  || fail "google login does not guard redirects with active recipient status"

grep -q "googleProvisionStatus = \"disabled\"" \
  "$ROOT/config/hermes/var/www/html/user-auth/inc/google_auto_provision_relay_recipient.cfm" \
  || fail "google auto-provisioning does not block disabled recipients"

grep -q "<cflocation url=\"/admin/\" addtoken=\"no\">" \
  "$ROOT/config/hermes/var/www/html/user-auth/google_login.cfm" \
  || fail "google login does not route admins to /admin/"

grep -q "<cflocation url=\"/users/\" addtoken=\"no\">" \
  "$ROOT/config/hermes/var/www/html/user-auth/google_login.cfm" \
  || fail "google login does not route users to /users/"

echo "PASS: Google SSO bridge wiring looks correct"
