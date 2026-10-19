# pinentry-op

A Rust pinentry bridge that supplies GPG key passphrases from the official
1Password CLI. Built for public-key decryption on macOS, with a normal pinentry
handling manual entry and other interactions. Unix platforms only.

```text
gpg → gpg-agent → pinentry-op → op read → 1Password
                        └──→ pinentry-mac (manual prompts)
```

GnuPG keeps your private keys and performs encryption/decryption. This program
retrieves only their passphrases. Public-key encryption ordinarily needs no
passphrase. Symmetric passphrases use the fallback prompt.

## Requirements

- Rust 1.85 or newer to build (latest stable recommended).
- GnuPG, the official `op` CLI, and a fallback pinentry such as `pinentry-mac`.
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

For a real encryption/decryption roundtrip, first run `cargo build`, then:

```sh
python3 tests/gpg_smoke.py
```

This creates an isolated, disposable GPG keyring with an encryption subkey, clears
its agent cache, and decrypts through pinentry-op with the fake CLI. It does not
test actual 1Password desktop authentication; verify that separately after setup.

## Configure

Find your installed executable paths and keygrips:

```sh
command -v op
command -v pinentry-mac
gpg --with-keygrip --list-secret-keys
```

Copy `config.example.toml` to `~/.config/pinentry-op/config.toml`. Replace the
executable paths and example keygrip. Each keygrip is a 40-character uppercase
hex string. Use the **encryption subkey's keygrip**, which differs from the primary
keygrip and from the OpenPGP fingerprint. Multiple keygrips may reference the
same password field.

```toml
op_program = "/opt/homebrew/bin/op"
fallback_program = "/opt/homebrew/bin/pinentry-mac"
timeout_seconds = 120
# account = "YOUR_ACCOUNT_ID"

[keys]
"0123456789ABCDEF0123456789ABCDEF01234567" = "op://VAULT_ID/ITEM_ID/password"
```

These paths are examples for Apple Silicon Homebrew. Executables must use
absolute paths, without shell substitutions. Prefer vault and item IDs in secret
references to survive renames. The configuration contains references, not secrets;
keep it writable only by your user. Unknown TOML fields are rejected.

`--config PATH` (or `--config=PATH`) overrides `PINENTRY_OP_CONFIG`, which overrides the default path
`~/.config/pinentry-op/config.toml`. The program does not depend on shell startup
files or a shell PATH to find `op` or the fallback. The default config path uses
the HOME inherited by the agent. To avoid agent environment propagation issues,
use the default location.

Install the release executable at a stable path of your choice. Back up
`~/.gnupg/gpg-agent.conf`, then update its `pinentry-program` line:

```text
pinentry-program /absolute/path/to/pinentry-op
```

Restart the agent to use the change:

```sh
gpgconf --kill gpg-agent
```

This clears the agent's in-memory passphrase cache. A mapped decryption should
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
- **CLI cancellation or failure:** if `op` exits unsuccessfully or times out,
  return a cancellation error rather than opening a second prompt, because a
  cancelled 1Password request cannot be told apart from other failures. CLI
  failures are deliberately not classified from human-readable error text.
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
the actual decryption flow. This wrapper does not implement biometric UI or
manage service-account tokens. It currently has no vault item picker, automatic
key discovery, secret updates, or Windows support.

## References

- [Pinentry protocol](https://github.com/gpg/pinentry/blob/master/doc/pinentry.texi)
- [Assuan responses](https://www.gnupg.org/documentation/manuals/assuan/Server-responses.html)
- [1Password CLI read](https://developer.1password.com/docs/cli/reference/commands/read/)
- [1Password desktop integration](https://developer.1password.com/docs/cli/app-integration/)

MIT licensed.
