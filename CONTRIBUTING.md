# Contributing to pinentry-op

Thanks for your interest in improving pinentry-op. It handles GPG key
passphrases, so changes are reviewed with security in mind and the codebase is
kept small on purpose.

By participating you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Reporting security issues

Do **not** open a public issue for a vulnerability. Report it privately as
described in [SECURITY.md](SECURITY.md).

## Reporting bugs and requesting features

Open an issue using the bug report or feature request form. For bugs, include
your platform, the versions of pinentry-op, GnuPG and the 1Password CLI, and
your fallback pinentry.

Never include passphrases. Redact vault and item IDs from secret references
(`op://VAULT_ID/ITEM_ID/password`) if you consider them private.

If a lookup fails, first run the same lookup by hand, which shows the 1Password
CLI's own error without printing the passphrase:

```sh
op read --no-newline "<your reference>" | wc -c
```

## Development

Requirements: Rust 1.85 or newer, Python 3, and GnuPG for the smoke test.

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build && python3 tests/gpg_smoke.py
```

`cargo test` runs unit tests and subprocess tests against fake `op` and pinentry
programs in `tests/fixtures`. `tests/gpg_smoke.py` runs real GnuPG signing and
decryption in a disposable keyring. None of the tests touch your vault or your
GPG configuration.

## Pull requests

- Open an issue first for anything beyond a small fix, so the approach can be
  agreed before you spend time on it.
- Keep each pull request to one change, with tests for new behavior and bug
  fixes.
- Avoid new dependencies unless they are clearly needed.
- Never log, print or write secrets. Diagnostics stay generic, and `op`'s error
  output is deliberately discarded because it can contain sensitive metadata.
- Update `README.md` when behavior or configuration changes, and add an entry
  under **Unreleased** in `CHANGELOG.md`.
- CI must pass on Linux and macOS.

## Releases

Releases are made by the maintainer, as described in the README's
[Releasing](README.md#releasing) section. Before tagging, move the
**Unreleased** changelog entries under the new version: the release workflow
uses that section as the GitHub release notes.
