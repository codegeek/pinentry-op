#[cfg(not(unix))]
compile_error!("pinentry-op currently supports Unix platforms only");

mod config;
mod fallback;
mod protocol;
mod secret;

use config::Config;
use fallback::Fallback;
use protocol::{read_line, send, send_secret, split, State, CANCELED};
use std::{ffi::OsString, io, path::PathBuf};

fn main() {
    if let Err(error) = run() {
        eprintln!("pinentry-op: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args_os().skip(1);
    let mut config_path = std::env::var_os("PINENTRY_OP_CONFIG").map(PathBuf::from);
    let mut fallback_args: Vec<OsString> = Vec::new();
    while let Some(arg) = arguments.next() {
        if arg == "--help" || arg == "-h" {
            println!("pinentry-op {}\nUsage: pinentry-op [--config PATH] [pinentry options]\nConfiguration: PINENTRY_OP_CONFIG or ~/.config/pinentry-op/config.toml\nAll remaining options are passed to the configured fallback pinentry.", env!("CARGO_PKG_VERSION"));
            return Ok(());
        } else if arg == "--version" {
            println!("pinentry-op {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        } else if arg == "--config" {
            config_path = Some(arguments.next().ok_or("--config requires a path")?.into());
        } else {
            fallback_args.push(arg);
        }
    }
    let config_path = config_path
        .or_else(|| {
            std::env::var_os("HOME")
                .map(|home| PathBuf::from(home).join(".config/pinentry-op/config.toml"))
        })
        .ok_or("cannot determine configuration path; use --config")?;
    let config = Config::load(&config_path)?;
    let mut fallback = Fallback::start(&config.fallback_program, &fallback_args)?;
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut input = stdin.lock();
    let mut output = stdout.lock();
    let mut state = State::default();
    send(&mut output, b"OK pinentry-op ready")?;
    while let Some(line) = read_line(&mut input)? {
        let text = std::str::from_utf8(&line).map_err(|_| "non-UTF-8 command")?;
        let (command, argument) = split(text);
        if command.is_empty() || command.starts_with('#') {
            continue;
        }
        if command == "GETPIN" {
            let key = state.lookup_key().map(str::to_owned);
            if let Some(key) = key {
                if let Some(reference) = config.keys.get(&key) {
                    state.mark_attempted(key);
                    match secret::read(&config, reference, state.timeout) {
                        Ok(secret) => {
                            send(&mut output, b"S PASSWORD_FROM_CACHE")?;
                            send_secret(&mut output, &secret)?;
                        }
                        Err(_) => {
                            // CLI failures cannot reliably distinguish cancellation
                            // across versions: fail closed rather than open a new UI.
                            eprintln!("pinentry-op: 1Password lookup failed or was cancelled");
                            send(&mut output, CANCELED.as_bytes())?;
                        }
                    }
                    continue;
                }
            }
        }
        if fallback.transact(&line, &mut input, &mut output)? {
            state.accepted(command, argument);
        }
        if command == "BYE" {
            break;
        }
    }
    Ok(())
}
