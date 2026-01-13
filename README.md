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

# Install ubw

```
cargo install --git https://github.com/uintptr/ubw ubw
```

# Install ubw-moz biometric handler for mozilla / firefox

```
c https://github.com/uintptr/ubw ubw-moz
```

# Install the bitwarden manifest file

This is only supported for macOS + TouchID at this point

```
ubwmoz install
```
