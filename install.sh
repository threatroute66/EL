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
            # yaffs2utils is old (2010) C that compiles cleanly to working
            # binaries on modern gcc but emits cosmetic warnings (-Wunused-
            # result, -Wstringop-truncation, -Warray-bounds). Capture the full
            # build to a log instead of spamming the console — only a genuine
            # non-zero make (real error, not a warning) is worth surfacing.
            # NB: the old `make … | tail` masked make's exit status behind
            # tail's, so failures were silently swallowed; this checks make
            # directly.
            Y2U_LOG="${SNAP}/yaffs2utils-build-${TS}.log"
            if (cd "${Y2U_BUILD}/yaffs2utils/src" && make -s >"${Y2U_LOG}" 2>&1); then
                if grep -qi warning "${Y2U_LOG}" 2>/dev/null; then
                    log "yaffs2utils built (compiler warnings logged to ${Y2U_LOG})"
                else
                    log "yaffs2utils built -> ${Y2U_DIR}/"
                fi
            else
                log "yaffs2utils build failed — see ${Y2U_LOG}; continuing (optional stage-2 YAFFS2 fallback; Debian unyaffs still covers the common layout)"
            fi
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

# --- refsprogs (source-built) -----------------------------------------------
# Linux + Sleuth Kit have no ReFS support, so the Windows 11 Dev Drive +
# Server 2016+ ReFS volumes go unreadable on SIFT by default. refsprogs
# (https://github.com/unsound/refsprogs, GPLv2+) is the only userspace
# ReFS reader. We clone + build into /usr/local/ so the refsls / refscat /
# refsinfo / refslabel binaries plus librefs are on the standard library
# search path. Idempotent — re-runs noop when already installed.
if [[ ${skip_apt} -eq 0 ]] && command -v gcc >/dev/null 2>&1; then
    if ! command -v refsinfo >/dev/null 2>&1; then
        log "building refsprogs from source -> /usr/local/{bin,lib}"
        RFP_BUILD="$(mktemp -d)"
        if git clone --depth 1 https://github.com/unsound/refsprogs.git \
                "${RFP_BUILD}/refsprogs" >/dev/null 2>&1; then
            (cd "${RFP_BUILD}/refsprogs" \
                && ./autogen.sh >/dev/null 2>&1 \
                && ./configure --prefix=/usr/local >/dev/null 2>&1 \
                && make -j2 -s >/dev/null 2>&1 \
                && sudo make install >/dev/null 2>&1) \
                || log "refsprogs build failed — continuing without ReFS support"
            # librefs.so lands under /usr/local/lib; refresh linker cache.
            sudo ldconfig
            rm -rf "${RFP_BUILD}"
            if command -v refsinfo >/dev/null 2>&1; then
                log "refsprogs installed (refsinfo / refsls / refscat / refslabel)"
            fi
        else
            log "refsprogs clone failed — ReFS partitions will fall through to fls (which fails) instead of refsls"
        fi
    else
        log "refsprogs already installed — skipping build"
    fi
fi

# --- dwarf2json (source-built) ----------------------------------------------
# Volatility 3 auto-downloads Windows PDB symbols, but Linux/macOS memory
# images need a per-kernel ISF JSON that has no public download. dwarf2json
# (https://github.com/volatilityfoundation/dwarf2json) builds that ISF from a
# matching debug vmlinux. `el.tooling.probe_dwarf2json` + the
# MemoryForensicatorAgent ISF remediation (commits f129494 / a635ec8) point
# the analyst at /opt/dwarf2json/dwarf2json, so install it there. Needs Go,
# not gcc. Idempotent — re-runs noop when already built. Absence is non-fatal:
# Windows memory needs nothing here; the doctor probe just flags it missing.
D2J_DIR="/opt/dwarf2json"
if [[ ${skip_apt} -eq 0 ]]; then
    if [[ ! -x "${D2J_DIR}/dwarf2json" ]]; then
        if command -v go >/dev/null 2>&1; then
            log "building dwarf2json from source -> ${D2J_DIR}"
            if sudo git clone --depth 1 \
                    https://github.com/volatilityfoundation/dwarf2json.git \
                    "${D2J_DIR}" >/dev/null 2>&1; then
                # Build in-tree as the invoking user (Go needs a writable cache);
                # the repo is sudo-owned, so build to a temp GOPATH/GOCACHE and
                # copy the binary back with sudo.
                D2J_CACHE="$(mktemp -d)"
                if (cd "${D2J_DIR}" && sudo env \
                        GOPATH="${D2J_CACHE}/gopath" \
                        GOCACHE="${D2J_CACHE}/gocache" \
                        GOFLAGS=-mod=mod \
                        go build -o "${D2J_DIR}/dwarf2json" . >/dev/null 2>&1); then
                    sudo chmod 755 "${D2J_DIR}/dwarf2json"
                    log "dwarf2json installed at ${D2J_DIR}/dwarf2json (Linux/macOS-memory ISF builder)"
                else
                    log "dwarf2json build failed — Linux/macOS memory images will need a manually-built ISF"
                fi
                rm -rf "${D2J_CACHE}"
            else
                log "dwarf2json clone failed — see provisioning/optional-tools.txt for the manual ISF workflow"
            fi
        else
            log "go not installed — skipping dwarf2json (apt install golang-go, then re-run; needed only for Linux/macOS memory images)"
        fi
    else
        log "dwarf2json already at ${D2J_DIR} — skipping build"
    fi
fi

# --- MITRE CAR analytic rule pack -------------------------------------------
# `el.skills.car_import` is wired into SigmaAnalystAgent and looks for
# CAR YAMLs at /opt/EL/rules/car/ by default. The loader was shipped in
# `9d10bd3` but no analytics live at that path on a fresh clone, so the
# loader sat idle. Clone the official MITRE CAR repo to populate the
# default location — ~100 analytics tagged tightly against ATT&CK.
# Idempotent: re-runs noop when the directory already exists.
CAR_DIR="/opt/EL/rules/car"
if [[ ! -d "${CAR_DIR}" ]]; then
    log "fetching MITRE CAR analytics -> ${CAR_DIR}"
    CAR_TMP="$(mktemp -d)"
    if git clone --depth 1 https://github.com/mitre-attack/car.git \
            "${CAR_TMP}/car" >/dev/null 2>&1; then
        sudo mkdir -p "${CAR_DIR}"
        if [[ -d "${CAR_TMP}/car/analytics" ]]; then
            sudo cp -r "${CAR_TMP}/car/analytics/." "${CAR_DIR}/"
            sudo chown -R "$(id -u):$(id -g)" "${CAR_DIR}"
            n="$(find "${CAR_DIR}" -maxdepth 1 -name 'CAR-*.yaml' | wc -l)"
            log "CAR analytics installed: ${n} YAML files"
        else
            log "CAR repo has no analytics/ subdir — schema changed upstream?"
        fi
        rm -rf "${CAR_TMP}"
    else
        log "CAR clone failed — SigmaAnalystAgent will run sigma rules only"
    fi
else
    log "CAR analytics already at ${CAR_DIR} — skipping clone"
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

# --- UAC installation phase ------------------------------------------------
# Install Unix Artifact Collector (UAC) for live response collection
install_uac() {
    local uac_dir="/opt/uac"
    local uac_wrapper="/usr/local/bin/uac"

    if [[ ! -d "$uac_dir" ]]; then
        log "installing UAC (Unix Artifact Collector)"
        local temp_dir="/tmp/uac_install"
        mkdir -p "$temp_dir"

        # Download latest UAC release
        local uac_tarball="${temp_dir}/uac.tar.gz"
        if curl -L -o "$uac_tarball" "https://api.github.com/repos/tclahr/uac/tarball/v3.3.0"; then
            cd "$temp_dir" && tar -xf "$uac_tarball" >/dev/null 2>&1
            local extracted_dir=$(find . -maxdepth 1 -type d -name "tclahr-uac-*" | head -1)

            if [[ -n "$extracted_dir" && -f "$extracted_dir/uac" ]]; then
                sudo mv "$extracted_dir" "$uac_dir"

                # Create wrapper script
                sudo tee "$uac_wrapper" > /dev/null << 'EOF'
#!/bin/bash
# UAC wrapper script to run from correct directory
cd /opt/uac && exec ./uac "$@"
EOF
                sudo chmod +x "$uac_wrapper"

                log "UAC installed at $uac_dir with wrapper at $uac_wrapper"
            else
                log "WARN: UAC extraction failed — live response collection unavailable"
            fi
        else
            log "WARN: UAC download failed — live response collection unavailable"
        fi

        rm -rf "$temp_dir"
    else
        log "UAC already installed at $uac_dir — skipping"
    fi
}

if [[ ${skip_apt} -eq 0 ]]; then
    install_uac
else
    log "skipping UAC installation (--no-apt specified)"
fi

# --- MemProcFS installation phase ------------------------------------------
# Install MemProcFS for memory-as-filesystem forensic triage (complements vol3)
install_memprocfs() {
    local memprocfs_dir="/opt/memprocfs"
    local version="v5.17"
    local file_version="v5.17.6-linux_x64-20260426"
    local url="https://github.com/ufrisk/MemProcFS/releases/download/${version}/MemProcFS_files_and_binaries_${file_version}.tar.gz"

    if [[ -x "${memprocfs_dir}/memprocfs" ]]; then
        log "MemProcFS already installed at ${memprocfs_dir} — skipping"
        return 0
    fi

    log "installing MemProcFS ${version}"
    local temp_tar="/tmp/memprocfs.tar.gz"
    if curl -L -s -o "${temp_tar}" "${url}"; then
        if [[ -f "${temp_tar}" ]] && file "${temp_tar}" | grep -q "gzip"; then
            sudo mkdir -p "${memprocfs_dir}"
            sudo tar -xzf "${temp_tar}" -C "${memprocfs_dir}"
            if [[ -x "${memprocfs_dir}/memprocfs" ]]; then
                log "MemProcFS installed at ${memprocfs_dir}"
            else
                log "WARN: MemProcFS extraction did not produce expected binary"
            fi
        else
            log "WARN: downloaded MemProcFS tarball appears invalid"
        fi
        rm -f "${temp_tar}"
    else
        log "WARN: MemProcFS download failed — memory-as-FS triage unavailable"
    fi
}

if [[ ${skip_apt} -eq 0 ]]; then
    install_memprocfs
else
    log "skipping MemProcFS installation (--no-apt specified)"
fi

# --- YARA-X installation phase --------------------------------------------
# Install YARA-X (Rust rewrite of YARA, ~10x faster). yara_hunt skill
# auto-prefers it when present. Falls back to YARA 4.x if install fails.
install_yara_x() {
    if [[ -x /usr/local/bin/yr ]]; then
        log "YARA-X already installed at /usr/local/bin/yr — skipping"
        return 0
    fi
    log "installing YARA-X v1.15.0"
    local url="https://github.com/VirusTotal/yara-x/releases/download/v1.15.0/yara-x-v1.15.0-x86_64-unknown-linux-gnu.gz"
    local temp="/tmp/yarax_install"
    mkdir -p "$temp"
    if curl -L -s -o "$temp/yr.tar.gz" "$url"; then
        if tar -xzf "$temp/yr.tar.gz" -C "$temp" 2>/dev/null && [[ -f "$temp/yr" ]]; then
            sudo mv "$temp/yr" /usr/local/bin/yr
            sudo chmod +x /usr/local/bin/yr
            log "YARA-X installed at /usr/local/bin/yr"
        else
            log "WARN: YARA-X archive extraction failed — yara_hunt will use YARA 4.x"
        fi
    else
        log "WARN: YARA-X download failed — yara_hunt will use YARA 4.x"
    fi
    rm -rf "$temp"
}

if [[ ${skip_apt} -eq 0 ]]; then
    install_yara_x
else
    log "skipping YARA-X installation (--no-apt specified)"
fi

# --- FoxIO JA4 tools phase -------------------------------------------------
# Clone FoxIO/ja4 (BSD-3-Clause + FoxIO License 1.1) for JA4+ family
# fingerprinting. Depends on tshark >= 4.0.6 (already on SIFT).
install_ja4_tools() {
    if [[ -f /opt/ja4-tools/python/ja4.py ]]; then
        log "FoxIO ja4 tools already present at /opt/ja4-tools/ — skipping"
        return 0
    fi
    log "cloning FoxIO ja4 tools to /opt/ja4-tools"
    if sudo git clone --quiet --depth 1 \
        https://github.com/FoxIO-LLC/ja4.git /tmp/foxio-ja4 2>/dev/null; then
        sudo mkdir -p /opt/ja4-tools
        sudo cp -r /tmp/foxio-ja4/python /opt/ja4-tools/python
        sudo rm -rf /tmp/foxio-ja4
        log "FoxIO ja4 tools installed at /opt/ja4-tools/python/"
    else
        log "WARN: FoxIO ja4 clone failed — JA4 fingerprinting unavailable (JA3 still works)"
    fi
}

if [[ ${skip_apt} -eq 0 ]]; then
    install_ja4_tools
else
    log "skipping FoxIO ja4 install (--no-apt specified)"
fi

# --- Microsoft-Extractor-Suite (PowerShell) phase --------------------------
# Install Invictus IR's PowerShell module for M365 / Entra ID acquisition.
# Best-effort: requires pwsh (PowerShell 7) which SIFT ships natively.
install_m365_extractor_suite() {
    if ! command -v pwsh >/dev/null 2>&1; then
        log "INFO: pwsh not present — skipping Microsoft-Extractor-Suite install"
        return 0
    fi
    if pwsh -NoProfile -NonInteractive -Command \
        "if (Get-Module -ListAvailable -Name Microsoft-Extractor-Suite) { exit 0 } else { exit 1 }" \
        >/dev/null 2>&1; then
        log "Microsoft-Extractor-Suite already installed — skipping"
        return 0
    fi
    log "installing Microsoft-Extractor-Suite (Invictus IR, MIT) for current user"
    pwsh -NoProfile -NonInteractive -Command \
        "Install-Module Microsoft-Extractor-Suite -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop" \
        2>/dev/null \
        || log "WARN: Microsoft-Extractor-Suite install failed — M365 acquisition unavailable"
}

if [[ ${skip_apt} -eq 0 ]]; then
    install_m365_extractor_suite
else
    log "skipping Microsoft-Extractor-Suite install (--no-apt specified)"
fi

# --- Tracee (eBPF runtime forensics) phase --------------------------------
# Install Aqua Security Tracee (Apache-2.0) to /opt/tracee. Needed for
# live-system runtime capture (chains off live-linux-system evidence kind).
# Does not run at install time; just stages the binary.
install_tracee() {
    if [[ -x /opt/tracee/dist/tracee || -x /usr/local/bin/tracee ]]; then
        log "Tracee already installed — skipping"
        return 0
    fi
    log "installing Tracee v0.24.1"
    local url="https://github.com/aquasecurity/tracee/releases/download/v0.24.1/tracee-x86_64.v0.24.1.tar.gz"
    local temp="/tmp/tracee.tar.gz"
    if curl -L -s -o "$temp" "$url"; then
        sudo mkdir -p /opt/tracee
        sudo tar -xzf "$temp" -C /opt/tracee
        if [[ -x /opt/tracee/dist/tracee ]]; then
            sudo ln -sf /opt/tracee/dist/tracee /usr/local/bin/tracee
            log "Tracee installed at /opt/tracee/dist/tracee (symlink in /usr/local/bin)"
        else
            log "WARN: Tracee extracted but binary not where expected"
        fi
        rm -f "$temp"
    else
        log "WARN: Tracee download failed — eBPF runtime capture unavailable"
    fi
}

if [[ ${skip_apt} -eq 0 ]]; then
    install_tracee
else
    log "skipping Tracee install (--no-apt specified)"
fi

# --- Mandiant macos-UnifiedLogs (Rust parser) phase -----------------------
# Install unifiedlog_iterator for parsing macOS tracev3 / .logarchive
# bundles on Linux. ~100x faster than Apple's `log show` and runs natively.
install_macos_unifiedlogs() {
    if [[ -x /opt/macos-unifiedlogs/unifiedlog_iterator ]]; then
        log "macos-UnifiedLogs parser already installed — skipping"
        return 0
    fi
    log "installing Mandiant macos-UnifiedLogs v0.5.1 (Rust)"
    local url="https://github.com/mandiant/macos-UnifiedLogs/releases/download/v0.5.1/unifiedlog_iterator-v0.5.1-x86_64-unknown-linux-gnu.tar.gz"
    local temp="/tmp/macos_ulogs.tar.gz"
    if curl -L -s -o "$temp" "$url"; then
        local extract_dir="/tmp/macos_ulogs_x"
        mkdir -p "$extract_dir"
        if tar -xzf "$temp" -C "$extract_dir" 2>/dev/null; then
            local binary
            binary=$(find "$extract_dir" -name unifiedlog_iterator -type f | head -1)
            if [[ -n "$binary" ]]; then
                sudo mkdir -p /opt/macos-unifiedlogs
                sudo mv "$binary" /opt/macos-unifiedlogs/unifiedlog_iterator
                sudo chmod +x /opt/macos-unifiedlogs/unifiedlog_iterator
                log "macos-UnifiedLogs installed at /opt/macos-unifiedlogs/unifiedlog_iterator"
            else
                log "WARN: macos-UnifiedLogs binary not found in archive"
            fi
        else
            log "WARN: macos-UnifiedLogs archive extraction failed"
        fi
        rm -rf "$temp" "$extract_dir"
    else
        log "WARN: macos-UnifiedLogs download failed"
    fi
}

if [[ ${skip_apt} -eq 0 ]]; then
    install_macos_unifiedlogs
else
    log "skipping macos-UnifiedLogs install (--no-apt specified)"
fi

# --- Python version preflight ------------------------------------------------
# EL's pyproject.toml requires Python 3.11+. SIFT 2024.x ships 3.12 so SIFT
# users never hit this — but Ubuntu 22.04 ships 3.10, Debian 11 ships 3.9,
# and a venv created from the wrong interpreter only fails 30 seconds later
# at `pip install -e .` with "Package 'el' requires a different Python".
# Preflight makes the failure visible at the right time with a fix-it hint.
# Choose the newest python3.X interpreter ≥3.11 that's on PATH; record the
# choice for the venv-creation step below.
PYTHON_BIN=""
for candidate in python3.13 python3.12 python3.11 python3; do
    if command -v "$candidate" >/dev/null 2>&1; then
        ver="$("$candidate" -c 'import sys; print("%d.%d"%sys.version_info[:2])' 2>/dev/null || echo 0.0)"
        major="${ver%%.*}"
        minor="${ver##*.}"
        if [[ "$major" -eq 3 && "$minor" -ge 11 ]]; then
            PYTHON_BIN="$candidate"
            break
        fi
    fi
done
if [[ -z "$PYTHON_BIN" ]]; then
    have_ver="$(python3 -c 'import sys; print("%d.%d"%sys.version_info[:2])' 2>/dev/null || echo none)"
    echo "ERROR: EL needs Python 3.11+ (pyproject.toml requires-python); found python3=${have_ver}" >&2
    echo "Install a newer Python and retry:" >&2
    echo "  Ubuntu 22.04: sudo add-apt-repository -y ppa:deadsnakes/ppa && sudo apt install -y python3.12 python3.12-venv" >&2
    echo "  Debian 11:    sudo apt install -y python3.11 python3.11-venv  (after enabling bookworm-backports)" >&2
    echo "  SIFT 2024.x:  already ships python3.12 — this branch shouldn't fire on a real SIFT install" >&2
    exit 2
fi
log "selected python interpreter: ${PYTHON_BIN} ($(${PYTHON_BIN} --version 2>&1))"

# --- venv phase -------------------------------------------------------------
if [[ ! -d "${EL_DIR}/.venv" ]]; then
    log "creating Python venv at ${EL_DIR}/.venv (using ${PYTHON_BIN})"
    # Prefer `<python> -m venv` so the venv inherits the exact interpreter the
    # preflight selected. `virtualenv` without --python could otherwise default
    # back to the system python3 (3.10 on Ubuntu 22.04) and undo the preflight.
    #
    # BUT: `python -m venv` needs the ensurepip scaffolding, which on
    # Debian/Ubuntu ships in a SEPARATE apt package (pythonX.Y-venv). The
    # interpreter can be present without it — and crucially `-m venv --help`
    # STILL succeeds — so the old guard committed to the stdlib-venv path and
    # then failed at creation with "ensurepip is not available", never reaching
    # the virtualenv fallback. Test ensurepip itself; remediate via apt; only
    # then choose the creation method.
    venv_pkg="${PYTHON_BIN##*/}-venv"   # python3.12 -> python3.12-venv
    if ! "${PYTHON_BIN}" -c 'import ensurepip' >/dev/null 2>&1; then
        if [[ ${skip_apt} -eq 0 ]]; then
            log "ensurepip missing for ${PYTHON_BIN}; installing ${venv_pkg}"
            sudo apt-get install -y "${venv_pkg}" >/dev/null 2>&1 \
                || sudo apt-get install -y python3-venv >/dev/null 2>&1 \
                || log "could not apt-install ${venv_pkg}/python3-venv — will try virtualenv"
        else
            log "ensurepip missing for ${PYTHON_BIN} and --no-apt set — will try virtualenv"
        fi
    fi

    if "${PYTHON_BIN}" -c 'import ensurepip' >/dev/null 2>&1; then
        "${PYTHON_BIN}" -m venv "${EL_DIR}/.venv"
    elif command -v virtualenv >/dev/null 2>&1; then
        log "stdlib venv unavailable for ${PYTHON_BIN}; falling back to virtualenv"
        virtualenv -q --python="${PYTHON_BIN}" "${EL_DIR}/.venv"
    elif [[ ${skip_apt} -eq 0 ]] && sudo apt-get install -y python3-virtualenv >/dev/null 2>&1; then
        log "installed python3-virtualenv; creating venv with it"
        virtualenv -q --python="${PYTHON_BIN}" "${EL_DIR}/.venv"
    else
        echo "ERROR: cannot create a venv for ${PYTHON_BIN} — ensurepip is" >&2
        echo "missing and virtualenv is unavailable." >&2
        echo "  Install the venv scaffolding and retry:" >&2
        echo "    sudo apt install -y ${venv_pkg}      # or: sudo apt install -y python3-venv" >&2
        echo "  Or install virtualenv:  sudo apt install -y python3-virtualenv" >&2
        exit 2
    fi
fi

log "upgrading pip"
"${EL_DIR}/.venv/bin/pip" install --quiet --upgrade pip

log "installing EL + Python deps from pyproject.toml"
"${EL_DIR}/.venv/bin/pip" install --quiet -e "${EL_DIR}[dev]"

# --- vol3 on PATH -----------------------------------------------------------
# Volatility 3 is venv-resident (installed via pyproject above), so the bare
# `vol` only works inside an activated venv. Expose it two ways:
#   1. /usr/local/bin/vol3  — the stable operator command, run vol3 from any
#      shell the way Vol2 was historically invoked. `el doctor` reports the
#      resolved target under volatility3's note.
#   2. /opt/volatility3-2.20.0/vol.py — a charter-compatibility SHIM. The
#      Protocol SIFT global ~/.claude/CLAUDE.md (a prerequisite installed
#      independently of this repo) documents `python3 /opt/volatility3-2.20.0/
#      vol.py`; that path does not exist on a venv install. Rather than wait
#      for a charter edit to reach every host, materialise the documented path
#      as a stdlib re-exec shim so the unmodified charter just works. A bare
#      symlink would NOT do — the charter prefixes `python3`, and the venv
#      console-script fails under the system interpreter (no volatility3 there);
#      the shim re-execs the venv `vol`, so both `python3 .../vol.py` and a
#      direct `.../vol.py` resolve to the venv build.
if [[ -x "${EL_DIR}/.venv/bin/vol" ]]; then
    sudo ln -sf "${EL_DIR}/.venv/bin/vol" /usr/local/bin/vol3 \
        && log "symlinked vol3 -> /usr/local/bin/vol3 (→ ${EL_DIR}/.venv/bin/vol)" \
        || log "NOTE: could not symlink /usr/local/bin/vol3 (sudo?); use ${EL_DIR}/.venv/bin/vol"
    _vol_shim_dir=/opt/volatility3-2.20.0
    if sudo mkdir -p "${_vol_shim_dir}" 2>/dev/null; then
        sudo tee "${_vol_shim_dir}/vol.py" >/dev/null <<SHIM || true
#!/usr/bin/env python3
"""Protocol SIFT charter compatibility shim -> EL venv Volatility 3.

The global ~/.claude/CLAUDE.md charter documents the invocation
\`python3 /opt/volatility3-2.20.0/vol.py\`, but EL ships Volatility 3 inside its
venv. This stdlib-only shim re-execs the venv console-script so the documented
path works whether invoked as \`python3 .../vol.py ...\` (system python3 runs
this shim) or \`.../vol.py ...\` directly. Stable name: vol3. \`el doctor\`
reports the real resolved path. Generated by EL install.sh — do not edit.
"""
import os
import sys

_VENV_VOL = "${EL_DIR}/.venv/bin/vol"
if not os.path.exists(_VENV_VOL):
    sys.exit("EL venv Volatility 3 not found at %s -- run install.sh" % _VENV_VOL)
os.execv(_VENV_VOL, [_VENV_VOL, *sys.argv[1:]])
SHIM
        sudo chmod +x "${_vol_shim_dir}/vol.py" 2>/dev/null || true
        log "wrote charter-compat vol3 shim -> ${_vol_shim_dir}/vol.py (→ ${EL_DIR}/.venv/bin/vol)"
    else
        log "NOTE: could not create ${_vol_shim_dir} (sudo?); charter path uncovered, use vol3"
    fi
fi

# --- el on PATH -------------------------------------------------------------
# The venv entrypoint lives at .venv/bin/el; symlink it into ~/.local/bin so
# operators can just type `el doctor` from anywhere. ~/.local/bin is on PATH
# by default on SIFT (Ubuntu 22.04+ user-systemd-path); if it isn't, the
# warning below tells the operator how to add it.
mkdir -p "${HOME}/.local/bin"
ln -sf "${EL_DIR}/.venv/bin/el" "${HOME}/.local/bin/el"
log "symlinked el -> ${HOME}/.local/bin/el"
case ":${PATH}:" in
    *":${HOME}/.local/bin:"*) ;;
    *) log "NOTE: ${HOME}/.local/bin not on PATH — add it to your shell rc to use 'el' directly" ;;
esac

# Hindsight (pyhindsight) imports ccl_chromium_reader — GitHub-only dep that
# isn't published to PyPI. pip install from the upstream repo so the venv has
# everything Chromium-family browser forensics needs.
log "installing ccl_chromium_reader (Hindsight transitive dep, from GitHub)"
"${EL_DIR}/.venv/bin/pip" install --quiet \
    "git+https://github.com/cclgroupltd/ccl_chromium_reader.git" \
    || log "WARN: ccl_chromium_reader install failed — Chromium browser forensics will be skipped"

# Stage Amnesty Tech mercenary-spyware IOC bundles for MVT to use. Without
# them, MVT runs but only emits "no IOC matches" — still useful (it parses
# the artifacts, which downstream agents consume), but the headline
# detection signal is silent. Operators can refresh later with:
#   sudo -E "${EL_DIR}/.venv/bin/mvt-ios" download-iocs --output /opt/mvt-iocs
log "downloading public Amnesty Tech IOCs for MVT (best-effort)"
sudo mkdir -p /opt/mvt-iocs
sudo "${EL_DIR}/.venv/bin/mvt-ios" download-iocs 2>/dev/null \
    || log "INFO: MVT IOC download skipped — run manually if needed (see Amnesty Tech investigations repo)"

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
