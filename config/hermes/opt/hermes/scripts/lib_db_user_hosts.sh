#!/bin/bash

# Shared SQL builder for selecting Hermes-managed stale host-scoped MariaDB users.
# Expects SQL-escaped username input.
hermes_stale_host_query() {
    local user_esc="$1"
    cat <<EOF
SELECT Host FROM mysql.user
 WHERE User='${user_esc}'
   AND Host <> '%';
EOF
}
