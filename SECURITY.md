# Security policy

pinentry-op handles GPG key passphrases, so security reports are welcome and
taken seriously.

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub:
[Report a vulnerability](https://github.com/codegeek/pinentry-op/security/advisories/new)
(also available from the repository's **Security** tab).

Do not open a public issue, pull request or discussion for a suspected
vulnerability. Include what you found, how to reproduce it, the affected
version and platform, and the impact you expect.

You should get an initial response within a week. Fixes are released as a new
version, and the advisory is published once a fixed release is available.

## Supported versions

Only the latest release receives security fixes.

## Scope

In scope: pinentry-op itself, for example passphrase leaks, unintended
approval of prompts, protocol handling, or how it starts `op` and the fallback
pinentry. Problems in GnuPG, the 1Password CLI or app, or the fallback pinentry
should be reported to those projects.

Release archives carry signed build provenance. Verify an archive with:

```sh
gh attestation verify pinentry-op-<target>.tar.xz --repo codegeek/pinentry-op
```
