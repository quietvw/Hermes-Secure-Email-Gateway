#!/usr/bin/env bash

set -euo pipefail

TMP_DIR="$(mktemp -d /tmp/hermes-install-confirm-XXXXXX)"
TMP_DIR_CANCEL="$(mktemp -d /tmp/hermes-install-cancel-XXXXXX)"
trap 'rm -rf "${TMP_DIR}" "${TMP_DIR_CANCEL}"' EXIT

mkdir -p "${TMP_DIR}/scripts" "${TMP_DIR}/updates/v260101"
cp "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/install_hermes_docker.sh" "${TMP_DIR}/scripts/install_hermes_docker.sh"
chmod +x "${TMP_DIR}/scripts/install_hermes_docker.sh"
touch "${TMP_DIR}/docker-compose.yml"

OUTPUT="$(
    printf '1\n' | \
    HERMES_ROOT="${TMP_DIR}" \
    HERMES_INSTALL_AUTO_CONFIRM=1 \
    HERMES_INSTALL_TEST_MODE=1 \
    TERM=xterm \
    bash "${TMP_DIR}/scripts/install_hermes_docker.sh" 2>&1
)"

printf '%s\n' "${OUTPUT}" | grep -q "Auto-confirming install continuation via HERMES_INSTALL_AUTO_CONFIRM=1"
printf '%s\n' "${OUTPUT}" | grep -q "Install confirmation test mode complete."

mkdir -p "${TMP_DIR_CANCEL}/scripts" "${TMP_DIR_CANCEL}/updates/v260101"
cp "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/install_hermes_docker.sh" "${TMP_DIR_CANCEL}/scripts/install_hermes_docker.sh"
chmod +x "${TMP_DIR_CANCEL}/scripts/install_hermes_docker.sh"
touch "${TMP_DIR_CANCEL}/docker-compose.yml"

CANCEL_OUTPUT="$(
    printf '1\nn\n' | \
    HERMES_ROOT="${TMP_DIR_CANCEL}" \
    HERMES_INSTALL_TEST_MODE=1 \
    TERM=xterm \
    bash "${TMP_DIR_CANCEL}/scripts/install_hermes_docker.sh" 2>&1
)"

printf '%s\n' "${CANCEL_OUTPUT}" | grep -q "Installation cancelled."

echo "install auto-confirm test passed"
