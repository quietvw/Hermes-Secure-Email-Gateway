#!/bin/bash

# Shared SQL builder for selecting ALL non-wildcard host rows for a MariaDB user.
# Intended for cleanup paths that may DROP USER host-scoped rows.
# Callers must restrict this helper to validated Hermes-managed service accounts
# only (never arbitrary user input) and enforce account-level guardrails
# (for example protecting root).
# Expects SQL-escaped username input.
hermes_non_wildcard_host_query() {
    local user_esc="$1"
    cat <<EOF
SELECT Host FROM mysql.user
 WHERE User='${user_esc}'
   AND Host <> '%';
EOF
}
