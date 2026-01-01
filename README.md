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

# APIs

- /identity/connect/token
- /api/accounts/profile
- /api/sync

# Install

```
cargo install --git https://github.com/uintptr/ubw
```
