#!/bin/bash

# Shared SQL builder for selecting Hermes-managed stale host-scoped MariaDB users.
# Expects SQL-escaped username input.
hermes_stale_host_query() {
    local user_esc="$1"
    cat <<EOF
SELECT Host FROM mysql.user
 WHERE User='${user_esc}'
   AND Host <> '%'
   AND (
        Host REGEXP '^hermes_[A-Za-z0-9_-]+'
        OR Host LIKE '%.seg_hermes_net_ext'
        OR Host IN ('localhost','127.0.0.1','::1')
   );
EOF
}
