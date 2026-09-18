#!/bin/bash

# Shared SQL builder for selecting ALL non-wildcard host rows for a MariaDB user.
# Callers are responsible for account-level guardrails (for example protecting root).
# Expects SQL-escaped username input.
hermes_non_wildcard_host_query() {
    local user_esc="$1"
    cat <<EOF
SELECT Host FROM mysql.user
 WHERE User='${user_esc}'
   AND Host <> '%';
EOF
}
