#!/bin/bash
set -euo pipefail

REPO="uintptr/ubw"
INSTALL_DIR="${HOME}/.local/bin"
TMP_DIR=""

cleanup() {
    if [ -n "${TMP_DIR}" ] && [ -d "${TMP_DIR}" ]; then
        rm -rf "${TMP_DIR}"
    fi
}
trap cleanup EXIT INT TERM

# Detect OS and architecture
detect_platform() {
    local os arch

    case "$(uname -s)" in
        Linux*)  os="linux" ;;
        Darwin*) os="darwin" ;;
        *)
            echo "Error: Unsupported operating system: $(uname -s)" >&2
            exit 1
            ;;
    esac

    case "$(uname -m)" in
        x86_64|amd64) arch="amd64" ;;
        arm64|aarch64) arch="arm64" ;;
        *)
            echo "Error: Unsupported architecture: $(uname -m)" >&2
            exit 1
            ;;
    esac

    echo "${os}-${arch}"
}

# Get latest release tag from GitHub
get_latest_version() {
    curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/'
}

main() {
    local platform version download_url tmp_dir

    echo "Installing ubw..."

    platform=$(detect_platform)
    echo "Detected platform: ${platform}"

    version=$(get_latest_version)
    if [ -z "$version" ]; then
        echo "Error: Could not determine latest version" >&2
        exit 1
    fi
    echo "Latest version: ${version}"

    ubw_url="https://github.com/${REPO}/releases/download/${version}/ubw-${platform}"
    ubwmoz_url="https://github.com/${REPO}/releases/download/${version}/ubwmoz-${platform}"

    # Create install directory if it doesn't exist
    mkdir -p "${INSTALL_DIR}"

    # Download binaries
    TMP_DIR=$(mktemp -d)

    echo "Downloading ubw from ${ubw_url}..."
    if ! curl -fsSL -o "${TMP_DIR}/ubw" "${ubw_url}"; then
        echo "Error: Failed to download ubw" >&2
        exit 1
    fi

    echo "Downloading ubwmoz from ${ubwmoz_url}..."
    if ! curl -fsSL -o "${TMP_DIR}/ubwmoz" "${ubwmoz_url}"; then
        echo "Error: Failed to download ubwmoz" >&2
        exit 1
    fi

    # Install binaries
    chmod +x "${TMP_DIR}/ubw" "${TMP_DIR}/ubwmoz"
    mv "${TMP_DIR}/ubw" "${INSTALL_DIR}/ubw"
    mv "${TMP_DIR}/ubwmoz" "${INSTALL_DIR}/ubwmoz"

    echo "Successfully installed ubw and ubwmoz to ${INSTALL_DIR}"

    # Check if install dir is in PATH
    if [[ ":$PATH:" != *":${INSTALL_DIR}:"* ]]; then
        echo ""
        echo "Note: ${INSTALL_DIR} is not in your PATH."
        echo "Add it by running:"
        echo "  echo 'export PATH=\"\${HOME}/.local/bin:\${PATH}\"' >> ~/.bashrc"
        echo "  source ~/.bashrc"
    fi
}

main
