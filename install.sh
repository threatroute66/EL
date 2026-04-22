#!/usr/bin/env bash
# EL — Edmond Locard DFIR Orchestrator
# Idempotent bootstrap from a clean SANS SIFT Workstation.
#
# What this script assumes is already on the box (i.e. SIFT base):
#   - Python 3.11+ (SIFT 2024.x ships 3.12)
#   - virtualenv OR python3-venv
#   - dotnet runtime (for EZ Tools)
#   - The Sleuth Kit (fls, mactime, mmls, ...)
#   - Plaso suite (log2timeline.py, psort.py, pinfo.py)
#   - bulk_extractor
#   - /opt/zimmermantools/ EZ Tools collection
#
# What this script installs ON TOP:
#   - Listed apt packages from provisioning/apt-packages.txt (currently: yara)
#   - A Python venv at .venv with all deps from pyproject.toml
#
# Captures pre/post snapshots in provisioning/snapshots/ so a later
# operator can audit exactly what changed on the host.
#
# Usage:
#   ./install.sh             # full bootstrap + snapshot
#   ./install.sh --no-apt    # skip apt phase (assumes packages already present)
#   ./install.sh --doctor    # only run the post-install verification
#   ./install.sh --with-serve  # also install + enable the el serve
#                              # systemd --user unit (case-report viewer
#                              # auto-starts at login, survives reboots)

set -euo pipefail

EL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SNAP="${EL_DIR}/provisioning/snapshots"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
APT_LIST="${EL_DIR}/provisioning/apt-packages.txt"

mkdir -p "${SNAP}"

log() { echo "[el-install $(date -u +%FT%TZ)] $*"; }

skip_apt=0
only_doctor=0
with_serve=0
for arg in "$@"; do
    case "$arg" in
        --no-apt) skip_apt=1 ;;
        --doctor) only_doctor=1 ;;
        --with-serve) with_serve=1 ;;
        --help|-h)
            grep '^#' "$0" | sed 's/^# \?//'
            exit 0
            ;;
    esac
done

if [[ ${only_doctor} -eq 1 ]]; then
    "${EL_DIR}/.venv/bin/el" doctor
    exit 0
fi

# --- Pre-install snapshot ---------------------------------------------------
log "capturing pre-install snapshot to ${SNAP}/*-pre-${TS}.txt"
{ uname -a; cat /etc/os-release 2>/dev/null || true; } > "${SNAP}/host-pre-${TS}.txt"
dpkg -l 2>/dev/null > "${SNAP}/dpkg-pre-${TS}.txt" || true
ls /opt 2>/dev/null > "${SNAP}/opt-pre-${TS}.txt" || true
command -v vol >/dev/null && vol --help >/dev/null 2>&1 && \
    echo "vol3 already on PATH" > "${SNAP}/vol3-pre-${TS}.txt" || \
    echo "vol3 not on PATH" > "${SNAP}/vol3-pre-${TS}.txt"

# --- apt phase --------------------------------------------------------------
if [[ ${skip_apt} -eq 0 && -s "${APT_LIST}" ]]; then
    log "installing apt packages from ${APT_LIST}"
    sudo apt-get update -qq
    # shellcheck disable=SC2046
    sudo apt-get install -y -qq $(grep -v '^#' "${APT_LIST}" | grep -v '^$' | tr '\n' ' ')
else
    log "skipping apt phase"
fi

# --- venv phase -------------------------------------------------------------
if [[ ! -d "${EL_DIR}/.venv" ]]; then
    log "creating Python venv at ${EL_DIR}/.venv"
    if command -v virtualenv >/dev/null 2>&1; then
        virtualenv -q "${EL_DIR}/.venv"
    elif python3 -m venv --help >/dev/null 2>&1; then
        python3 -m venv "${EL_DIR}/.venv"
    else
        echo "ERROR: neither virtualenv nor python3-venv is available" >&2
        echo "Try: sudo apt install -y python3-venv  OR  sudo apt install -y python3-virtualenv" >&2
        exit 2
    fi
fi

log "upgrading pip"
"${EL_DIR}/.venv/bin/pip" install --quiet --upgrade pip

log "installing EL + Python deps from pyproject.toml"
"${EL_DIR}/.venv/bin/pip" install --quiet -e "${EL_DIR}[dev]"

# --- Post-install snapshot --------------------------------------------------
log "capturing post-install snapshot"
dpkg -l 2>/dev/null > "${SNAP}/dpkg-post-${TS}.txt" || true
ls /opt 2>/dev/null > "${SNAP}/opt-post-${TS}.txt" || true
"${EL_DIR}/.venv/bin/pip" freeze > "${SNAP}/pip-freeze-post-${TS}.txt"

# --- Diff: what changed -----------------------------------------------------
log "writing install diff to ${SNAP}/diff-${TS}.txt"
{
    echo "=== apt packages added ==="
    diff "${SNAP}/dpkg-pre-${TS}.txt" "${SNAP}/dpkg-post-${TS}.txt" \
        | grep -E '^>' | awk '{print $3}' || true
    echo
    echo "=== pip packages installed in EL venv ==="
    cat "${SNAP}/pip-freeze-post-${TS}.txt"
} > "${SNAP}/diff-${TS}.txt"

# --- Doctor -----------------------------------------------------------------
log "ensuring user_allow_other is enabled in /etc/fuse.conf (needed for ewfmount -X allow_other)"
if ! grep -q '^user_allow_other' /etc/fuse.conf 2>/dev/null; then
    sudo sed -i 's/^#user_allow_other$/user_allow_other/' /etc/fuse.conf || true
fi

log "running doctor for verification"
"${EL_DIR}/.venv/bin/el" doctor || true

if [[ ${with_serve} -eq 1 ]]; then
    log "installing + enabling systemd --user unit for 'el serve'"
    "${EL_DIR}/.venv/bin/el" serve --install-service || \
        log "WARN: 'el serve --install-service' returned non-zero; skipping"
    log "case-report viewer will auto-start at login. For reboot survival"
    log "even when not logged in, run: loginctl enable-linger \$USER"
    log "viewer URL: http://127.0.0.1:8089/"
fi

log "done. Snapshots in ${SNAP}/. Run './install.sh --doctor' anytime to re-verify."
if [[ ${with_serve} -eq 0 ]]; then
    log "to install the case-report viewer as a persistent service later,"
    log "run: ./install.sh --with-serve  OR  el serve --install-service"
fi
