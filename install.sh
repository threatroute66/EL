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
#   - Missing EZ Tools that EL expects (downloads from ericzimmermanstools.com)
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

# --- yaffs2utils (source-built) ---------------------------------------------
# The Debian-packaged `unyaffs` covers the canonical 2K+64B Android NAND
# layout, but real-world userdata partitions sometimes use a layout it
# doesn't recognise. yaffs2utils ships unyaffs2/mkyaffs2/unspare2 with
# explicit -p/-s page+spare flags that handle the long tail of NAND
# geometries. We clone + build to /opt/yaffs2utils/ so the YAFFS2 skill's
# stage-2 fallback finds it. Idempotent — re-runs noop when already built.
Y2U_DIR="/opt/yaffs2utils"
if [[ ${skip_apt} -eq 0 ]] && command -v gcc >/dev/null 2>&1; then
    if [[ ! -x "${Y2U_DIR}/unyaffs2" ]]; then
        log "building yaffs2utils from source -> ${Y2U_DIR}"
        Y2U_BUILD="$(mktemp -d)"
        if git clone --depth 1 https://github.com/justsoso8/yaffs2utils.git \
                "${Y2U_BUILD}/yaffs2utils" >/dev/null 2>&1; then
            (cd "${Y2U_BUILD}/yaffs2utils/src" && make -s 2>&1 | tail -20) \
                || log "yaffs2utils build failed (gcc warnings?) — continuing"
            sudo mkdir -p "${Y2U_DIR}"
            for bin in unyaffs2 mkyaffs2 unspare2; do
                if [[ -x "${Y2U_BUILD}/yaffs2utils/src/${bin}" ]]; then
                    sudo cp -p "${Y2U_BUILD}/yaffs2utils/src/${bin}" \
                        "${Y2U_DIR}/${bin}"
                fi
            done
            rm -rf "${Y2U_BUILD}"
            if [[ -x "${Y2U_DIR}/unyaffs2" ]]; then
                log "yaffs2utils installed at ${Y2U_DIR}/"
            fi
        else
            log "yaffs2utils clone failed — skill's unyaffs2 fallback unavailable"
        fi
    else
        log "yaffs2utils already at ${Y2U_DIR} — skipping build"
    fi
fi

# --- EZ Tools phase ---------------------------------------------------------
# Check for and install EZ Tools that EL expects but may be missing from
# SIFT's default installation. Downloads from Eric Zimmerman's official site.
install_missing_eztools() {
    local eztools_dir="/opt/zimmermantools"
    local missing_tools=()

    # Create base directory if it doesn't exist
    if [[ ! -d "$eztools_dir" ]]; then
        log "creating $eztools_dir directory"
        sudo mkdir -p "$eztools_dir"
    fi

    # Check for EZ Tools that EL expects (based on el/tooling.py probes)
    [[ ! -f "$eztools_dir/EvtxeCmd/EvtxECmd.dll" ]] && missing_tools+=("EvtxeCmd")
    [[ ! -f "$eztools_dir/MFTECmd.dll" ]] && missing_tools+=("MFTECmd")
    [[ ! -f "$eztools_dir/RECmd/RECmd.dll" ]] && missing_tools+=("RECmd")
    [[ ! -f "$eztools_dir/PECmd.dll" ]] && missing_tools+=("PECmd")
    [[ ! -f "$eztools_dir/AmcacheParser.dll" ]] && missing_tools+=("AmcacheParser")

    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log "downloading missing EZ Tools: ${missing_tools[*]}"
        for tool in "${missing_tools[@]}"; do
            log "downloading $tool..."
            local zip_path="/tmp/${tool}.zip"
            local download_url="https://download.ericzimmermanstools.com/net9/${tool}.zip"

            # Download the tool
            if curl -L -o "$zip_path" "$download_url" >/dev/null 2>&1; then
                if [[ -f "$zip_path" ]] && file "$zip_path" | grep -q "Zip archive"; then
                    # Extract to temp directory first
                    local temp_dir="/tmp/${tool}_extract"
                    mkdir -p "$temp_dir"
                    if unzip -q "$zip_path" -d "$temp_dir" 2>/dev/null; then
                        # Copy files to appropriate location
                        if [[ "$tool" == "EvtxeCmd" || "$tool" == "RECmd" ]]; then
                            # These tools have subdirectories
                            sudo mkdir -p "$eztools_dir/$tool"
                            sudo cp -r "$temp_dir"/* "$eztools_dir/$tool/"
                        else
                            # These tools go in the root
                            sudo cp "$temp_dir"/* "$eztools_dir/"
                        fi
                        log "$tool installed successfully"
                    else
                        log "WARN: failed to extract $tool.zip"
                    fi
                    rm -rf "$temp_dir"
                else
                    log "WARN: downloaded $tool.zip appears invalid"
                fi
                rm -f "$zip_path"
            else
                log "WARN: failed to download $tool from $download_url"
            fi
        done
    else
        log "all required EZ Tools already present"
    fi
}

if [[ ${skip_apt} -eq 0 ]]; then
    install_missing_eztools
else
    log "skipping EZ Tools check (--no-apt specified)"
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
