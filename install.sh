#!/usr/bin/env sh
# install.sh: Selective POSIX installer for Hephaestus (slice, shield, verify, memory, voice)
set -eu

REPO="Hephaestus-Zero/hephaestus"
VERSION="0.1.0"
PREFIX="${PREFIX:-$HOME/.local}"
MODE="all"
ONLY_RAW=""
UNINSTALL=0
FROM_SOURCE="${HEPHAESTUS_FROM_SOURCE:-0}"

usage() {
    cat <<'EOF'
hephaestus installer (v0.1.0)

usage:
  ./install.sh [--all] [--prefix DIR]
  ./install.sh --only slice[,shield,verify,memory,voice] [--prefix DIR]
  ./install.sh --uninstall [--prefix DIR]

options:
  --all                 Install all 5 organs: slice, shield, verify, memory, voice (default)
  --only ORGANS         Comma-separated subset of organs to build and install
  --prefix DIR          Installation prefix (default: $HOME/.local)
  --from-source         Force compiling from source instead of release binary tarball
  --uninstall           Remove installed hephaestus binaries and shared assets from --prefix
  -h, --help            Show this help message
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --all)
            MODE="all"
            ONLY_RAW=""
            ;;
        --only)
            if [ $# -lt 2 ]; then
                echo "install.sh: --only requires an organ list (e.g. --only slice)" >&2
                exit 2
            fi
            MODE="only"
            ONLY_RAW="$2"
            shift
            ;;
        --only=*)
            MODE="only"
            ONLY_RAW="${1#*=}"
            ;;
        --prefix)
            if [ $# -lt 2 ]; then
                echo "install.sh: --prefix requires a directory path" >&2
                exit 2
            fi
            PREFIX="$2"
            shift
            ;;
        --prefix=*)
            PREFIX="${1#*=}"
            ;;
        --from-source)
            FROM_SOURCE=1
            ;;
        --uninstall)
            UNINSTALL=1
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "install.sh: unknown option '$1' (see --help)" >&2
            exit 2
            ;;
    esac
    shift
done

BINDIR="${PREFIX}/bin"
SHAREDIR="${PREFIX}/share/hephaestus"

if [ "${UNINSTALL}" = "1" ]; then
    for b in hephaestus hslice hfind hsearch hshield hhook hverify hmemory hvoice; do
        rm -f "${BINDIR}/${b}"
    done
    rm -rf "${SHAREDIR}"
    echo "Uninstalled hephaestus from ${BINDIR} and ${SHAREDIR}"
    exit 0
fi

WANT_SLICE=0
WANT_SHIELD=0
WANT_VERIFY=0
WANT_MEMORY=0
WANT_VOICE=0

if [ "${MODE}" = "all" ]; then
    WANT_SLICE=1
    WANT_SHIELD=1
    WANT_VERIFY=1
    WANT_MEMORY=1
    WANT_VOICE=1
else
    OLD_IFS="${IFS}"
    IFS=","
    set -- ${ONLY_RAW}
    IFS="${OLD_IFS}"
    if [ $# -eq 0 ]; then
        echo "install.sh: --only requires at least one organ" >&2
        exit 2
    fi
    for tok in "$@"; do
        clean="$(printf '%s' "${tok}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
        case "${clean}" in
            slice)  WANT_SLICE=1 ;;
            shield) WANT_SHIELD=1 ;;
            verify) WANT_VERIFY=1 ;;
            memory) WANT_MEMORY=1 ;;
            voice)  WANT_VOICE=1 ;;
            all)
                WANT_SLICE=1
                WANT_SHIELD=1
                WANT_VERIFY=1
                WANT_MEMORY=1
                WANT_VOICE=1
                ;;
            "") ;;
            *)
                echo "install.sh: unknown organ '${clean}' (valid: slice, shield, verify, memory, voice)" >&2
                exit 2
                ;;
        esac
    done
fi

SELECTED_LIST=""
append_organ() {
    if [ -z "${SELECTED_LIST}" ]; then
        SELECTED_LIST="$1"
    else
        SELECTED_LIST="${SELECTED_LIST},$1"
    fi
}
[ "${WANT_SLICE}" = "1" ] && append_organ "slice"
[ "${WANT_SHIELD}" = "1" ] && append_organ "shield"
[ "${WANT_VERIFY}" = "1" ] && append_organ "verify"
[ "${WANT_MEMORY}" = "1" ] && append_organ "memory"
[ "${WANT_VOICE}" = "1" ] && append_organ "voice"

if [ -z "${SELECTED_LIST}" ]; then
    echo "install.sh: no organs selected" >&2
    exit 2
fi

need_cmd() {
    command -v "$1" >/dev/null 2>&1
}

prune_unselected_binaries() {
    if [ "${MODE}" != "only" ]; then
        return 0
    fi
    if [ "${WANT_SLICE}" = "0" ]; then
        rm -f "${BINDIR}/hslice" "${BINDIR}/hfind" "${BINDIR}/hsearch"
        rm -rf "${SHAREDIR}/skills/slice"
    fi
    if [ "${WANT_SHIELD}" = "0" ]; then
        rm -f "${BINDIR}/hshield" "${BINDIR}/hhook"
        rm -rf "${SHAREDIR}/skills/shield"
    fi
    if [ "${WANT_VERIFY}" = "0" ]; then
        rm -f "${BINDIR}/hverify"
        rm -rf "${SHAREDIR}/skills/verify"
    fi
    if [ "${WANT_MEMORY}" = "0" ]; then
        rm -f "${BINDIR}/hmemory"
        rm -rf "${SHAREDIR}/skills/memory"
    fi
    if [ "${WANT_VOICE}" = "0" ]; then
        rm -f "${BINDIR}/hvoice"
        rm -rf "${SHAREDIR}/skills/voice"
    fi
}

install_selected_from_stage() {
    STAGE_BIN="$1"
    STAGE_ROOT="$2"

    mkdir -p "${BINDIR}" "${SHAREDIR}/mcp" "${SHAREDIR}/skills"
    install -m 0755 "${STAGE_ROOT}/bin/hephaestus" "${BINDIR}/hephaestus"
    install -m 0755 "${STAGE_ROOT}/mcp/hephaestus_mcp.py" "${SHAREDIR}/mcp/hephaestus_mcp.py"

    if [ "${WANT_SLICE}" = "1" ]; then
        install -m 0755 "${STAGE_BIN}/hslice" "${BINDIR}/hslice"
        install -m 0755 "${STAGE_BIN}/hfind" "${BINDIR}/hfind"
        ln -sf hfind "${BINDIR}/hsearch"
        mkdir -p "${SHAREDIR}/skills/slice"
        install -m 0644 "${STAGE_ROOT}/skills/slice/SKILL.md" "${SHAREDIR}/skills/slice/SKILL.md"
    fi

    if [ "${WANT_SHIELD}" = "1" ]; then
        install -m 0755 "${STAGE_BIN}/hshield" "${BINDIR}/hshield"
        install -m 0755 "${STAGE_BIN}/hhook" "${BINDIR}/hhook"
        mkdir -p "${SHAREDIR}/skills/shield"
        install -m 0644 "${STAGE_ROOT}/skills/shield/SKILL.md" "${SHAREDIR}/skills/shield/SKILL.md"
    fi

    if [ "${WANT_VERIFY}" = "1" ]; then
        install -m 0755 "${STAGE_BIN}/hverify" "${BINDIR}/hverify"
        mkdir -p "${SHAREDIR}/skills/verify"
        install -m 0644 "${STAGE_ROOT}/skills/verify/SKILL.md" "${SHAREDIR}/skills/verify/SKILL.md"
    fi

    if [ "${WANT_MEMORY}" = "1" ]; then
        install -m 0755 "${STAGE_BIN}/hmemory" "${BINDIR}/hmemory"
        mkdir -p "${SHAREDIR}/skills/memory"
        install -m 0644 "${STAGE_ROOT}/skills/memory/SKILL.md" "${SHAREDIR}/skills/memory/SKILL.md"
    fi

    if [ "${WANT_VOICE}" = "1" ]; then
        install -m 0755 "${STAGE_BIN}/hvoice" "${BINDIR}/hvoice"
        mkdir -p "${SHAREDIR}/skills/voice"
        install -m 0644 "${STAGE_ROOT}/skills/voice/SKILL.md" "${SHAREDIR}/skills/voice/SKILL.md"
    fi

    prune_unselected_binaries

    if need_cmd python3; then
        "${BINDIR}/hephaestus" enable "${SELECTED_LIST}" --only >/dev/null
    fi
}

build_and_install_from_tree() {
    SRC_ROOT="$1"
    BUILD_STAGE="$(mktemp -d)"
    trap 'rm -rf "${BUILD_STAGE}"' EXIT

    if [ "${WANT_SLICE}" = "1" ]; then
        make -s -C "${SRC_ROOT}/organs/slice" BUILD_DIR="${BUILD_STAGE}"
    fi
    if [ "${WANT_SHIELD}" = "1" ]; then
        make -s -C "${SRC_ROOT}/organs/shield" BUILD_DIR="${BUILD_STAGE}"
    fi
    if [ "${WANT_VERIFY}" = "1" ]; then
        if [ -f "${SRC_ROOT}/organs/verify/Makefile" ]; then
            make -s -C "${SRC_ROOT}/organs/verify" BUILD_DIR="${BUILD_STAGE}"
        else
            install -m 0755 "${SRC_ROOT}/organs/verify/hverify" "${BUILD_STAGE}/hverify"
        fi
    fi
    if [ "${WANT_MEMORY}" = "1" ]; then
        make -s -C "${SRC_ROOT}/organs/memory" BUILD_DIR="${BUILD_STAGE}"
    fi
    if [ "${WANT_VOICE}" = "1" ]; then
        if [ -f "${SRC_ROOT}/organs/voice/Makefile" ]; then
            make -s -C "${SRC_ROOT}/organs/voice" BUILD_DIR="${BUILD_STAGE}"
        else
            install -m 0755 "${SRC_ROOT}/organs/voice/hvoice" "${BUILD_STAGE}/hvoice"
        fi
    fi

    install_selected_from_stage "${BUILD_STAGE}" "${SRC_ROOT}"
}

# 1. Local repository checkout path
SCRIPT_DIR=""
if [ -f "$0" ]; then
    SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
fi

if [ -n "${SCRIPT_DIR}" ] && [ -f "${SCRIPT_DIR}/bin/hephaestus" ] && [ -d "${SCRIPT_DIR}/organs" ]; then
    build_and_install_from_tree "${SCRIPT_DIR}"
    echo "Installed hephaestus (${SELECTED_LIST}) -> ${BINDIR}"
    exit 0
fi

# 2. Remote prebuilt release tarball path
OS="$(uname -s)"
ARCH="$(uname -m)"
TARBALL=""
if [ "${OS}" = "Linux" ] && [ "${ARCH}" = "x86_64" ]; then
    TARBALL="hephaestus-v${VERSION}-linux-x86_64.tar.gz"
elif [ "${OS}" = "Darwin" ] && [ "${ARCH}" = "arm64" ]; then
    TARBALL="hephaestus-v${VERSION}-macos-arm64.tar.gz"
fi

if [ "${FROM_SOURCE}" != "1" ] && [ -n "${TARBALL}" ] && need_cmd curl; then
    TMP_REL="$(mktemp -d)"
    trap 'rm -rf "${TMP_REL}"' EXIT
    BASE_URL="https://github.com/${REPO}/releases/latest/download"
    if curl -fsSL "${BASE_URL}/${TARBALL}" -o "${TMP_REL}/${TARBALL}" 2>/dev/null && \
       curl -fsSL "${BASE_URL}/SHA256SUMS" -o "${TMP_REL}/SHA256SUMS" 2>/dev/null; then
        if need_cmd sha256sum; then
            (cd "${TMP_REL}" && grep "${TARBALL}" SHA256SUMS | sha256sum -c - >/dev/null)
        elif need_cmd shasum; then
            (cd "${TMP_REL}" && grep "${TARBALL}" SHA256SUMS | shasum -a 256 -c - >/dev/null)
        fi
        tar -xzf "${TMP_REL}/${TARBALL}" -C "${TMP_REL}"
        EXTRACTED="$(find "${TMP_REL}" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
        if [ -n "${EXTRACTED}" ] && [ -d "${EXTRACTED}/bin" ]; then
            install_selected_from_stage "${EXTRACTED}/bin" "${EXTRACTED}"
            echo "Installed hephaestus (${SELECTED_LIST}) -> ${BINDIR} (verified SHA-256)"
            exit 0
        fi
    fi
    rm -rf "${TMP_REL}"
fi

# 3. Remote source build fallback
TMP_SRC="$(mktemp -d)"
trap 'rm -rf "${TMP_SRC}"' EXIT
if need_cmd git; then
    git clone --depth 1 "https://github.com/${REPO}.git" "${TMP_SRC}/hephaestus" >/dev/null 2>&1
elif need_cmd curl; then
    curl -fsSL "https://github.com/${REPO}/archive/refs/heads/main.tar.gz" | tar -xz -C "${TMP_SRC}"
    mv "${TMP_SRC}/hephaestus-main" "${TMP_SRC}/hephaestus"
else
    echo "install.sh: git or curl is required to fetch ${REPO}" >&2
    exit 1
fi

build_and_install_from_tree "${TMP_SRC}/hephaestus"
echo "Installed hephaestus (${SELECTED_LIST}) -> ${BINDIR}"
