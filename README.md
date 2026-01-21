# Unofficial Bitwarden CLI

An unofficial Bitwarden CLI client with SSH agent support, browser integration, and more.

## Installation

### Quick Install (Linux/macOS)

```sh
curl -fsSL https://raw.githubusercontent.com/uintptr/ubw/main/scripts/install.sh | bash
```

This installs both `ubw` and `ubwmoz` to `~/.local/bin`.

### From Source

```sh
cargo install --git https://github.com/uintptr/ubw ubw
cargo install --git https://github.com/uintptr/ubw ubw-moz
```

## Features

### SSH Agent

Set the socket path for the SSH agent:

```sh
SSH_AUTH_SOCK=$HOME/.local/share/ubw/ubw.sock
```

### macOS TouchID Support

Install the browser native messaging manifest for TouchID integration:

```sh
ubwmoz install
```

### xsecurelock Authenticator

Configure xsecurelock to use ubw for authentication:

```sh
export XSECURELOCK_AUTH=/path/to/auth_xss_ubw
```

Create the authenticator script:

```sh
#!/bin/sh
ubw x-secure-lock --email email@example.com --server-url https://bw.example.com
```
