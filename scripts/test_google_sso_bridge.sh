#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export ROOT

python3 <<'PY'
import os
import pathlib
import re
import sys

root = pathlib.Path(os.environ["ROOT"])

def read(relpath: str) -> str:
    return (root / relpath).read_text(encoding="utf-8")

def require(condition: bool, message: str) -> None:
    if not condition:
        print(f"FAIL: {message}", file=sys.stderr)
        raise SystemExit(1)

ssl_conf = read("config/hermes/opt/hermes/templates/hermes-ssl.conf")
admin_app = read("config/hermes/var/www/html/admin/Application.cfc")
users_app = read("config/hermes/var/www/html/users/Application.cfc")
google_login = read("config/hermes/var/www/html/user-auth/google_login.cfm")
google_provision = read("config/hermes/var/www/html/user-auth/inc/google_auto_provision_relay_recipient.cfm")
google_session = read("config/hermes/var/www/html/user-auth/inc/google_sso_session.cfm")
google_verify = read("config/hermes/var/www/html/user-auth/google_sso_verify.cfm")

require("include /etc/nginx/snippets/auth_admin.conf" in ssl_conf, "admin location is not wired to auth_admin.conf")
require("include /etc/nginx/snippets/auth_users.conf" in ssl_conf, "users location is not wired to auth_users.conf")
require("google_sso_auth_request.cfm?target=admin" in ssl_conf, "admin auth-request bridge endpoint is missing")
require("google_sso_auth_request.cfm?target=users" in ssl_conf, "users auth-request bridge endpoint is missing")

require("/user-auth/google_sso_verify.cfm?target=admin" in admin_app, "admin application does not use Google SSO verify bridge")
require("/user-auth/google_sso_verify.cfm?target=users" in users_app, "users application does not use Google SSO verify bridge")

require('ListFindNoCase("created,created_email_failed,exists", googleProvisionStatus)' in google_login, "google login success redirect block is missing")
require("googleSsoIssueSession(flowEmail, flowName)" in google_login, "google login does not issue bridge sessions")
require("has_admin_access" in google_login and "has_user_access" in google_login, "google login does not compute redirect access flags")
require(re.search(r"status\s*=\s*'OK'", google_login) is not None, "google login does not guard user redirects with active recipient status")
require(re.search(r"<cflocation\s+url=\"/admin/\"\s+addtoken=\"no\">", google_login) is not None, "google login does not route admins to /admin/")
require(re.search(r"<cflocation\s+url=\"/users/\"\s+addtoken=\"no\">", google_login) is not None, "google login does not route users to /users/")

require(re.search(r'googleProvisionStatus\s*=\s*"disabled"', google_provision) is not None, "google auto-provisioning does not block disabled recipients")
require("ldap_get_user_groups.cfm" in google_provision, "google auto-provisioning does not verify pre-existing LDAP relay users")
require(
    re.search(r"ldapUserFound\s+AND\s+CompareNoCase\(ldapUsername,\s*recipientEmail\)\s+EQ\s+0\s+AND\s+isRelay", google_provision) is not None,
    "google auto-provisioning does not confirm the existing LDAP relay identity matches the recipient"
)

require("googleSsoGenerateIvHex" in google_session, "google bridge cookie does not generate a per-session IV")
require("java.security.SecureRandom" in google_session and "nextBytes" in google_session, "google bridge cookie IV is not generated from a cryptographically secure random source")
require("AES/CBC/PKCS5Padding" in google_session, "google bridge cookie does not use an explicit CBC mode")
require(re.search(r'googleSsoSignValue\(ivHex\s*&\s*":"\s*&\s*encryptedPayload\)', google_session) is not None, "google bridge cookie does not sign the IV and ciphertext together")
require("cgi.server_name" in google_verify and "console.host" not in google_verify, "google verify fallback still depends on console.host instead of the current request host")
require("Authorized" in google_verify and "Unauthorized" in google_verify and "/api/verify" in google_verify, "google verify fallback does not reduce the upstream response to a simple authorization result")
require("https://hermes_console_host$request_uri" in read("config/hermes/opt/hermes/templates/auth_admin.conf"), "admin auth redirect is not pinned to the configured console host")
require("https://hermes_console_host$request_uri" in read("config/hermes/opt/hermes/templates/auth_users.conf"), "users auth redirect is not pinned to the configured console host")

print("PASS: Google SSO bridge wiring looks correct")
PY
