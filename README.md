# pinentry-op

[![CI](https://github.com/codegeek/pinentry-op/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/codegeek/pinentry-op/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/codegeek/pinentry-op)](https://github.com/codegeek/pinentry-op/releases/latest)

A Rust pinentry bridge that supplies GPG key passphrases from the official
1Password CLI, for decryption and signing, with a normal pinentry handling
manual entry and other interactions. Supports macOS and Linux; Unix platforms only.

```text
gpg → gpg-agent → pinentry-op → op read → 1Password
                        └──→ fallback pinentry (manual prompts)
```

The fallback is `pinentry-mac` on macOS, or a desktop or terminal pinentry such
as `pinentry-gnome3`, `pinentry-qt` or `pinentry-curses` on Linux.

On Linux, signing and decryption have been verified with the 1Password desktop
app on an Arch-based KDE/GNOME desktop (CachyOS), and the automated tests and a
real-GPG smoke test run in CI on Ubuntu.

GnuPG keeps your private keys and performs decryption and signing. This program
retrieves only their passphrases. Public-key encryption ordinarily needs no
passphrase. Symmetric passphrases use the fallback prompt.

## Install

### Homebrew (macOS or Linux)

On macOS (Apple Silicon or Intel) or with Homebrew on Linux (x86_64 or ARM64):

```sh
brew install codegeek/tap/pinentry-op
```

This installs `pinentry-op` at `$(brew --prefix)/bin/pinentry-op`, a path that
stays the same across upgrades, and an example configuration at
`$(brew --prefix)/share/pinentry-op/config.example.toml`. On macOS, install
GnuPG, the 1Password CLI and pinentry-mac separately:

```sh
brew install gnupg pinentry-mac
brew install --cask 1password-cli
```

On Linux, install GnuPG and a pinentry from your distribution, and the 1Password
CLI from [1Password's package repository](https://developer.1password.com/docs/cli/get-started/).

### Arch Linux

The package is not on the AUR yet. Build and install it from the PKGBUILD in
this repository; `makepkg` downloads the tagged release source, checks its
SHA-256 checksum and runs the test suite:

```sh
git clone https://github.com/codegeek/pinentry-op
cd pinentry-op/packaging/aur
makepkg -si
```

This installs `/usr/bin/pinentry-op` and an example configuration at
`/usr/share/doc/pinentry-op/config.example.toml`. The `gnupg` package already
pulls in `pinentry`, which provides `pinentry-gnome3`, `pinentry-qt` and
`pinentry-curses`. The 1Password CLI is the AUR package `1password-cli`.

### Prebuilt archives

Prebuilt archives with SHA-256 checksums are also attached to each
[GitHub release](https://github.com/codegeek/pinentry-op/releases). Each archive
also has signed build provenance; verify a download with
`gh attestation verify <archive> --repo codegeek/pinentry-op`. v0.1.0 was
published before this was added and has none. To build
from source instead, see [Build and verify](#build-and-verify).

## Requirements

- Rust 1.85 or newer to build from source (latest stable recommended).
- GnuPG, the official `op` CLI, and a fallback pinentry such as `pinentry-mac`
  (macOS) or `pinentry-gnome3`, `pinentry-qt` or `pinentry-curses` (Linux).
- 1Password desktop app with **Settings → Developer → Integrate with 1Password CLI** enabled.
- Python 3 for subprocess tests; GnuPG for the optional real-GPG smoke test.

## Build and verify

```sh
cargo test
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo build --release
```

The subprocess tests use fake `op` and pinentry executables and synthetic secrets.
They never open your vault or change your GPG configuration.

For a real signing and decryption roundtrip, first run `cargo build`, then:

```sh
python3 tests/gpg_smoke.py
```

This creates an isolated, disposable GPG keyring with a signing primary key and an
encryption subkey. With the agent cache cleared each time, it signs and then
decrypts through pinentry-op with the fake CLI. It checks that each operation
looked up the 1Password reference mapped to that key's own keygrip. It does not
test actual 1Password desktop authentication; verify that separately after setup.

## Configure

Find your installed executable paths and keygrips:

```sh
command -v op
command -v pinentry-mac      # macOS
command -v pinentry-gnome3   # Linux; or pinentry-qt, pinentry-curses
gpg --with-keygrip --list-secret-keys
```

Copy `config.example.toml` to `~/.config/pinentry-op/config.toml`. Replace the
executable paths and example keygrips. Each keygrip is a 40-character uppercase
hex string, distinct from the OpenPGP fingerprint and key ID.

GnuPG asks for a passphrase per key, identified by keygrip, so add an entry for
**every key you use**. Decryption needs the encryption subkey (`[E]`). Signing
needs the signing subkey (`[S]`) if there is one, otherwise the primary key
(usually `[SC]`). The primary key and each subkey have different keygrips. When
one passphrase protects them all, as it usually does, point every keygrip at the
same 1Password reference. gpg-agent caches each keygrip separately, so signing
and then decrypting may contact 1Password twice.

```toml
op_program = "/opt/homebrew/bin/op"
fallback_program = "/opt/homebrew/bin/pinentry-mac"
timeout_seconds = 120
# account = "YOUR_ACCOUNT_ID"
# on_lookup_failure = "cancel"   # or "prompt"; see below

[keys]
# Primary key [SC]: used for signing when there is no signing subkey.
"0123456789ABCDEF0123456789ABCDEF01234567" = "op://VAULT_ID/ITEM_ID/password"
# Encryption subkey [E].
"89ABCDEF0123456789ABCDEF0123456789ABCDEF" = "op://VAULT_ID/ITEM_ID/password"
```

These paths are examples for Apple Silicon Homebrew. On Linux, `op` is usually
`/usr/bin/op` and the fallback something like `/usr/bin/pinentry-gnome3`, or
`/usr/bin/pinentry` where that is a wrapper choosing the right pinentry for the
desktop (as on Arch-based systems). Use `pinentry-curses` only if you always use
GPG from a terminal: it cannot prompt when there is no terminal, for example
when an editor or Git GUI signs a commit. Executables must use
absolute paths, without shell substitutions. Prefer vault and item IDs in secret
references to survive renames. The configuration contains references, not secrets;
keep it writable only by your user. Unknown TOML fields are rejected.

`--config PATH` (or `--config=PATH`) overrides `PINENTRY_OP_CONFIG`, which overrides the default path
`~/.config/pinentry-op/config.toml`. The program does not depend on shell startup
files or a shell PATH to find `op` or the fallback. The default config path uses
the HOME inherited by the agent. To avoid agent environment propagation issues,
use the default location.

Back up `~/.gnupg/gpg-agent.conf`, then point its `pinentry-program` line at
the installed executable. With Homebrew on Apple Silicon, that is:

```text
pinentry-program /opt/homebrew/bin/pinentry-op
```

With the Arch package, use `/usr/bin/pinentry-op`; with Homebrew on Linux,
`/home/linuxbrew/.linuxbrew/bin/pinentry-op`.

If you build from source, copy `target/release/pinentry-op` to a stable path of
your choice and use that path. Avoid pointing at the build directory, which
`cargo clean` or a failed rebuild can break.

Restart the agent to use the change:

```sh
gpgconf --kill gpg-agent
```

This clears the agent's in-memory passphrase cache. A mapped decryption or signature should
then request the password through 1Password as needed by its authorization
policy. If GnuPG disables external password caching (for example with
`no-allow-external-cache` in agent configuration), the normal prompt is used.

To restore your previous setup, restore the old `pinentry-program` line and run
`gpgconf --kill gpg-agent` again. No automatic installer edits your configuration.

## Behavior

- **Mapped private-key unlock:** only consult 1Password for `SETKEYINFO n/<keygrip>`
  when `OPTION allow-external-password-cache` has been accepted. Return
  `S PASSWORD_FROM_CACHE` and percent-escaped Assuan data on success.
- **Retries:** try each mapped key once per pinentry process, even across RESET.
  Subsequent requests and requests with `SETERROR` go to the normal pinentry.
- **Missing mappings, symmetric operations, new passphrases, confirmations and
  protocol extensions:** delegate to the fallback. A persistent fallback receives
  all prompt state and handles inquiries such as passphrase-quality checks.
- **CLI cancellation or failure:** `op` exits with the same status whether you
  cancel its prompt, the 1Password app is not running, or the lookup fails for
  another reason, and its human-readable error text is deliberately not parsed.
  So `on_lookup_failure` decides what happens when `op` exits unsuccessfully or
  times out:
  - `"cancel"` (default): return a cancellation error. Cancelling the
    1Password prompt never opens a second prompt, but nor does a 1Password app
    that is not running.
  - `"prompt"`: open the fallback pinentry instead, so you can type the
    passphrase when 1Password is unavailable. Cancelling the 1Password prompt
    then also leads to a manual prompt.
- **CLI unavailable or unusable secret:** if `op` cannot be started, or succeeds
  but returns an empty secret, a NUL byte or more than 64 KiB, the request goes
  to the fallback prompt. The user declined nothing in these cases.
- **Timeout:** kill the `op` process group (including any helpers) and reap `op`
  after `timeout_seconds`, or an accepted positive `SETTIMEOUT` value if shorter.
  The fallback controls its own UI timeout.
- **Exact secret bytes:** use `op read --no-newline`; preserve whitespace and
  encode `%`, CR and LF.

The fallback is a required dependency and starts for every pinentry session,
including sessions serviced entirely by 1Password. It is never auto-approved on
your behalf. Point it directly to a trusted real pinentry executable; do not
point it back at this wrapper or an indirect wrapper that invokes it.

## Secret handling and limitations

`op` is launched directly with separate arguments and no shell. Passphrases never
appear in command arguments, files or application logs. CLI stderr is discarded
and failures produce a generic diagnostic. Secret buffers owned by the wrapper
use `zeroize`, including the pipe read buffer and encoded response buffer. This
is best-effort memory hygiene: it does not lock memory, erase OS/standard-library
I/O buffers, or control memory inside `op`, the fallback, or GnuPG. There is no
additional passphrase cache in this wrapper; GnuPG and the fallback retain their
own configured caching policies.

1Password authorization happens through its official CLI integration. A
background `gpg-agent` may have a different authorization context from your
terminal. Working terminal CLI access does not guarantee agent access; verify
the actual decryption and signing flows. This wrapper does not implement biometric UI or
manage service-account tokens. It currently has no vault item picker, automatic
key discovery, secret updates, or Windows support.

## Releasing

Releases are built by [dist](https://opensource.axo.dev/cargo-dist/) in
`.github/workflows/release.yml` and configured in `dist-workspace.toml`.

1. In `CHANGELOG.md`, move the **Unreleased** entries under a new
   `## [X.Y.Z] - YYYY-MM-DD` heading and update the comparison links at the
   bottom. The workflow uses that section as the GitHub release notes; preview
   them with `dist plan --tag vX.Y.Z --output-format=json`.
2. Update `version` in `Cargo.toml`, run `cargo build` to refresh `Cargo.lock`,
   and commit.
3. Tag and push: `git tag -a vX.Y.Z -m "pinentry-op X.Y.Z" && git push origin vX.Y.Z`.

The workflow builds archives for macOS and Linux (x86_64 and ARM64), creates the
GitHub release, and pushes the updated formula to
[codegeek/homebrew-tap](https://github.com/codegeek/homebrew-tap) using the
`HOMEBREW_TAP_TOKEN` repository secret. After changing `dist-workspace.toml`,
run `dist generate` to update the workflow, and `dist plan` to preview a release.

The Arch package is maintained separately from the release workflow. After the
GitHub release exists, on an Arch system:

1. In `packaging/aur/PKGBUILD`, set `pkgver` to the new version and `pkgrel=1`.
2. Run `updpkgsums` to record the release tarball's checksum, then
   `makepkg --cleanbuild` to build and test, and
   `makepkg --printsrcinfo > .SRCINFO`.
3. Commit both files here. Once the package is published on the AUR, also copy
   them into your clone of `ssh://aur@aur.archlinux.org/pinentry-op.git`,
   commit and push.

## References

- [Pinentry protocol](https://github.com/gpg/pinentry/blob/master/doc/pinentry.texi)
- [Assuan responses](https://www.gnupg.org/documentation/manuals/assuan/Server-responses.html)
- [1Password CLI read](https://developer.1password.com/docs/cli/reference/commands/read/)
- [1Password desktop integration](https://developer.1password.com/docs/cli/app-integration/)

MIT licensed.
