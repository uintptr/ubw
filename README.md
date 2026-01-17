# Unofficial Bitwarden CLI

# ssh-agent

```
SSH_AUTH_SOCK=$HOME/.local/share/ubw/ubw.sock
```

# xsecurelock authenticator

```
export XSECURELOCK_AUTH=/path/to/auth_xss_ubw
```

```
cat -p /path/to/auth_xss_ubw
#!/bin/sh
ubw x-secure-lock --email email@example.com --server-url https://bw.example.com
```

# macOS TouchID support

```
ubw-moz install
```

# APIs

- /identity/connect/token
- /api/accounts/profile
- /api/sync

# Install

## Quick install (Linux/macOS)

```
curl -fsSL https://raw.githubusercontent.com/uintptr/ubw/main/scripts/install.sh | bash
```

This installs both `ubw` and `ubwmoz` to `~/.local/bin`.

## From source

```
cargo install --git https://github.com/uintptr/ubw ubw
cargo install --git https://github.com/uintptr/ubw ubwmoz
```

# Install the bitwarden manifest file

This is only supported for macOS + TouchID at this point

```
ubwmoz install
```
