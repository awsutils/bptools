#!/bin/sh
set -e

PAGES_BASE="https://awsutils.github.io/bptools"
BINARY="bptools"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

info()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok()    { printf '\033[1;32m  ✓\033[0m %s\n' "$*"; }
die()   { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

need() {
  command -v "$1" >/dev/null 2>&1 || die "'$1' is required but not installed"
}

# ---------------------------------------------------------------------------
# Detect OS
# ---------------------------------------------------------------------------

detect_os() {
  case "$(uname -s)" in
    Linux)  echo linux ;;
    Darwin) echo darwin ;;
    *)      die "Unsupported OS: $(uname -s)" ;;
  esac
}

# ---------------------------------------------------------------------------
# Detect CPU architecture
# ---------------------------------------------------------------------------

detect_arch() {
  case "$(uname -m)" in
    x86_64 | amd64)   echo amd64 ;;
    aarch64 | arm64)  echo arm64 ;;
    *)                die "Unsupported architecture: $(uname -m)" ;;
  esac
}

# ---------------------------------------------------------------------------
# Download helper (curl with wget fallback)
# ---------------------------------------------------------------------------

download() {
  url="$1"
  dest="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL -o "$dest" "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$dest" "$url"
  else
    die "Neither curl nor wget found. Install one and re-run."
  fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

OS=$(detect_os)
ARCH=$(detect_arch)

info "Detected platform: ${OS}/${ARCH}"

ASSET="${BINARY}-${OS}-${ARCH}"
BASE_URL="${PAGES_BASE}"

# Download binary
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

info "Downloading ${ASSET} from ${BASE_URL}..."
download "${BASE_URL}/${ASSET}" "${TMP_DIR}/${BINARY}"
chmod +x "${TMP_DIR}/${BINARY}"

# Verify checksum if sha256sum / shasum is available
info "Verifying checksum..."
if command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1; then
  download "${BASE_URL}/checksums.txt" "${TMP_DIR}/checksums.txt"

  # Filter to only the line for our asset and run the check from TMP_DIR
  if command -v sha256sum >/dev/null 2>&1; then
    CHECKER="sha256sum"
  else
    CHECKER="shasum -a 256"
  fi

  # Rewrite checksum line so it references just the local filename
  grep "${ASSET}$" "${TMP_DIR}/checksums.txt" \
    | sed "s|${ASSET}|${BINARY}|" \
    > "${TMP_DIR}/check.txt"

  (cd "${TMP_DIR}" && $CHECKER -c check.txt --status 2>/dev/null) \
    || die "Checksum verification failed. The download may be corrupt."
  ok "Checksum verified"
else
  printf '\033[1;33m  !\033[0m sha256sum/shasum not found, skipping checksum verification\n'
fi

# Install
if [ -w "${INSTALL_DIR}" ]; then
  mv "${TMP_DIR}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
else
  info "Installing to ${INSTALL_DIR} requires elevated privileges..."
  sudo mv "${TMP_DIR}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
fi

ok "${BINARY} ${VERSION} installed to ${INSTALL_DIR}/${BINARY}"
