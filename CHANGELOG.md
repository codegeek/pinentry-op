# Changelog

All notable changes to pinentry-op are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Changelog, contributing guide, code of conduct, and issue and pull request
  templates.

## [0.1.1] - 2026-10-19

No changes to how pinentry-op behaves. This release adds supply-chain
protections for the published archives.

### Added

- Signed build provenance for every release archive. Verify a download with
  `gh attestation verify <archive> --repo codegeek/pinentry-op`.
- Releases are now immutable: published archives and tags cannot be changed.
- Security policy (`SECURITY.md`) with private vulnerability reporting.

### Changed

- Updated the `toml` dependency to 1.1. Configuration files may now use
  TOML 1.1 syntax; existing files parse the same way.
- The Arch Linux instructions build the package from `packaging/aur`, since it
  is not yet published on the AUR.

## [0.1.0] - 2026-10-19

Initial release.

### Added

- Pinentry bridge that answers GnuPG passphrase requests from the 1Password CLI
  (`op read`) for keys mapped by keygrip, for both decryption and signing.
- Every other request, and every other interaction, goes to a configured
  fallback pinentry such as `pinentry-mac`, `pinentry-gnome3` or `pinentry-qt`.
- `on_lookup_failure` setting: `"cancel"` (default) cancels the request when
  `op` fails or times out; `"prompt"` opens the fallback pinentry instead, for
  example when the 1Password app is not running.
- Falls back to the manual prompt when `op` cannot be started, or returns an
  empty secret, a NUL byte or more than 64 KiB.
- Timeouts kill the whole `op` process group, including helper processes.
- `--config PATH` and `--config=PATH`, the `PINENTRY_OP_CONFIG` variable, and
  the default `~/.config/pinentry-op/config.toml`.
- Release archives for macOS (Apple Silicon, Intel) and Linux (x86_64, ARM64),
  a Homebrew tap (`brew install codegeek/tap/pinentry-op`), and an Arch Linux
  PKGBUILD.

[Unreleased]: https://github.com/codegeek/pinentry-op/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/codegeek/pinentry-op/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/codegeek/pinentry-op/releases/tag/v0.1.0
