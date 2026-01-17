#!/bin/bash
set -euo pipefail

REPO="bender/ubw"
INSTALL_DIR="${HOME}/.local/bin"

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
    tmp_dir=$(mktemp -d)
    trap 'rm -rf "${tmp_dir}"' EXIT

    echo "Downloading ubw from ${ubw_url}..."
    if ! curl -fsSL -o "${tmp_dir}/ubw" "${ubw_url}"; then
        echo "Error: Failed to download ubw" >&2
        exit 1
    fi

    echo "Downloading ubwmoz from ${ubwmoz_url}..."
    if ! curl -fsSL -o "${tmp_dir}/ubwmoz" "${ubwmoz_url}"; then
        echo "Error: Failed to download ubwmoz" >&2
        exit 1
    fi

    # Install binaries
    chmod +x "${tmp_dir}/ubw" "${tmp_dir}/ubwmoz"
    mv "${tmp_dir}/ubw" "${INSTALL_DIR}/ubw"
    mv "${tmp_dir}/ubwmoz" "${INSTALL_DIR}/ubwmoz"

    echo ""
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
