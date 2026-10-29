# 0.1.0

- Extracted the previous machine-specific deployment into a reusable package.
- Added topology discovery, installation state, guarded retries, policy groups,
  black/white lists, checksummed AdGuard archives and explicit uninstall.
- Only strict DNS mode is supported; no automatic public-DNS fallback.
- Existing unmanaged/legacy AdGuard installations are refused, not migrated.
- Built-in lists restrict access to selected major Russian online services,
  banks, and the Gosuslugi/ESIA platform.
- GitHub publication is optional; local versioned archives work independently.
