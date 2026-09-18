#!/bin/bash

# Shared SQL builder for selecting ALL non-wildcard host rows for a MariaDB user.
# Intended for cleanup paths that may DROP USER host-scoped rows.
# Callers must restrict this helper to validated Hermes-managed service accounts
# only (never arbitrary user input) and enforce account-level guardrails
# (for example protecting root).
# Accepts raw username input and performs SQL escaping internally.
hermes_sql_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\'/\'\'}"
    printf "%s" "$s"
}

hermes_non_wildcard_host_query() {
    local username="$1"
    local user_esc
    user_esc="$(hermes_sql_escape "$username")"
    cat <<EOF
SELECT Host FROM mysql.user
 WHERE User='${user_esc}'
   AND Host <> '%';
EOF
}
