use std::{
    collections::HashSet,
    io::{self, BufRead, Read, Write},
};
use zeroize::Zeroizing;

pub const CANCELED: &str = "ERR 83886179 Operation cancelled";

// Assuan lines are limited to 1000 bytes including the terminating newline.
const MAX_LINE: usize = 1000;
// Data lines stay well below MAX_LINE; each secret byte encodes to at most 3 bytes.
const MAX_DATA_LINE: usize = 900;
const MAX_ENCODED_BYTE: usize = 3;

pub fn read_line(input: &mut impl BufRead) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
    let mut line = Zeroizing::new(Vec::with_capacity(MAX_LINE));
    let n = input
        .take(MAX_LINE as u64 + 1)
        .read_until(b'\n', &mut line)?;
    if n == 0 {
        return Ok(None);
    }
    if n > MAX_LINE || line.last() != Some(&b'\n') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid Assuan line length",
        ));
    }
    line.pop();
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    Ok(Some(line))
}

pub fn send(output: &mut impl Write, line: &[u8]) -> io::Result<()> {
    output.write_all(line)?;
    output.write_all(b"\n")?;
    output.flush()
}

pub fn send_secret(output: &mut impl Write, secret: &[u8]) -> io::Result<()> {
    let mut encoded = Zeroizing::new(Vec::with_capacity(MAX_DATA_LINE));
    encoded.extend_from_slice(b"D ");
    for &byte in secret {
        if encoded.len() + MAX_ENCODED_BYTE > MAX_DATA_LINE {
            send(output, &encoded)?;
            // Wipe before reusing the allocation, rather than only shortening its length.
            use zeroize::Zeroize;
            encoded.zeroize();
            encoded.extend_from_slice(b"D ");
        }
        match byte {
            b'%' => encoded.extend_from_slice(b"%25"),
            b'\r' => encoded.extend_from_slice(b"%0D"),
            b'\n' => encoded.extend_from_slice(b"%0A"),
            _ => encoded.push(byte),
        }
    }
    send(output, &encoded)?;
    send(output, b"OK")
}

// Splits on the first space. Bytes are not assumed to be UTF-8: only the
// command verb must be text, and arguments pass through to the fallback unchanged.
pub fn split(line: &[u8]) -> (&[u8], &[u8]) {
    match line.iter().position(|&b| b == b' ') {
        Some(i) => (&line[..i], &line[i + 1..]),
        None => (line, b""),
    }
}

#[derive(Default)]
pub struct State {
    allow_cache: bool,
    key: Option<String>,
    error: bool,
    repeat: bool,
    attempted: HashSet<String>,
    pub timeout: Option<u64>,
}

impl State {
    // Only update state after the real pinentry has accepted a command.
    pub fn accepted(&mut self, command: &str, argument: &str) {
        match command {
            "OPTION" if argument == "allow-external-password-cache" => self.allow_cache = true,
            "SETKEYINFO" => {
                self.key = argument
                    .strip_prefix("n/")
                    .filter(|grip| grip.len() == 40 && grip.bytes().all(|c| c.is_ascii_hexdigit()))
                    .map(str::to_ascii_uppercase);
            }
            "SETERROR" => self.error = !argument.is_empty(),
            "SETREPEAT" => self.repeat = !argument.is_empty(),
            "SETTIMEOUT" => self.timeout = argument.parse().ok().filter(|&value| value > 0),
            "RESET" => {
                let allow_cache = self.allow_cache;
                let timeout = self.timeout;
                let attempted = std::mem::take(&mut self.attempted);
                *self = Self::default();
                self.allow_cache = allow_cache;
                self.timeout = timeout;
                self.attempted = attempted;
            }
            "GETPIN" | "CONFIRM" => self.error = false,
            _ => {}
        }
    }

    pub fn lookup_key(&self) -> Option<&str> {
        self.key.as_deref().filter(|key| {
            self.allow_cache && !self.error && !self.repeat && !self.attempted.contains(*key)
        })
    }

    pub fn mark_attempted(&mut self, key: String) {
        self.attempted.insert(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const GRIP: &str = "0123456789ABCDEF0123456789ABCDEF01234567";

    #[test]
    fn preserves_whitespace_and_escapes_protocol_delimiters() {
        let mut out = Vec::new();
        send_secret(&mut out, b" space %\r\n ").unwrap();
        assert_eq!(out, b"D  space %25%0D%0A \nOK\n");
    }

    #[test]
    fn long_secrets_use_bounded_data_lines() {
        let mut out = Vec::new();
        send_secret(&mut out, &vec![b'%'; 65536]).unwrap();
        assert!(out.split(|&b| b == b'\n').all(|line| line.len() < 1000));
        assert_eq!(out.iter().filter(|&&b| b == b'%').count(), 65536);
    }

    #[test]
    fn data_lines_fill_up_to_the_limit() {
        let mut out = Vec::new();
        send_secret(&mut out, &vec![b'x'; 2000]).unwrap();
        let lines: Vec<_> = out.split(|&b| b == b'\n').collect();
        assert!(lines[0].len() > MAX_DATA_LINE - MAX_ENCODED_BYTE);
        assert!(lines.iter().all(|line| line.len() <= MAX_DATA_LINE));
    }

    #[test]
    fn splits_non_utf8_arguments() {
        assert_eq!(
            split(b"SETDESC caf\xe9 x"),
            (&b"SETDESC"[..], &b"caf\xe9 x"[..])
        );
        assert_eq!(split(b"GETPIN"), (&b"GETPIN"[..], &b""[..]));
    }

    #[test]
    fn rejects_oversized_and_unterminated_lines() {
        assert!(read_line(&mut &vec![b'x'; 1001][..]).is_err());
        assert!(read_line(&mut &b"GETPIN"[..]).is_err());
        assert_eq!(
            &*read_line(&mut &b"GETPIN\r\n"[..]).unwrap().unwrap(),
            b"GETPIN"
        );
    }

    #[test]
    fn requires_opt_in_normal_key_and_only_tries_once() {
        let mut state = State::default();
        state.accepted("SETKEYINFO", &format!("n/{GRIP}"));
        assert_eq!(state.lookup_key(), None);
        state.accepted("OPTION", "allow-external-password-cache");
        assert_eq!(state.lookup_key(), Some(GRIP));
        state.mark_attempted(GRIP.into());
        assert_eq!(state.lookup_key(), None);
        state.accepted("RESET", "");
        assert_eq!(state.lookup_key(), None);
        state.accepted("SETKEYINFO", &format!("n/{GRIP}"));
        assert_eq!(state.lookup_key(), None);
        state.accepted("SETKEYINFO", &format!("u/{GRIP}"));
        assert_eq!(state.lookup_key(), None);
    }

    #[test]
    fn errors_and_new_passphrases_disable_lookup() {
        let mut state = State::default();
        state.accepted("OPTION", "allow-external-password-cache");
        state.accepted("SETKEYINFO", &format!("n/{GRIP}"));
        state.accepted("SETERROR", "Bad passphrase");
        assert_eq!(state.lookup_key(), None);
        state.accepted("SETERROR", "");
        state.accepted("SETREPEAT", "Repeat:");
        assert_eq!(state.lookup_key(), None);
    }
}
