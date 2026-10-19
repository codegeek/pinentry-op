use crate::protocol::{read_line, send};
use std::{
    ffi::OsString,
    io::{self, BufRead, BufReader, Write},
    path::Path,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
};

// A persistent real pinentry handles protocol extensions, prompt state and UI.
// All commands except intercepted GETPIN requests pass through unchanged.
pub struct Fallback {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}

impl Fallback {
    pub fn start(program: &Path, args: &[OsString]) -> io::Result<Self> {
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let input = child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("missing fallback input"))?;
        let output = BufReader::new(
            child
                .stdout
                .take()
                .ok_or_else(|| io::Error::other("missing fallback output"))?,
        );
        let mut fallback = Self {
            child,
            input,
            output,
        };
        loop {
            let line = read_line(&mut fallback.output)?
                .ok_or_else(|| io::Error::other("fallback closed before greeting"))?;
            if line.starts_with(b"#") {
                continue;
            }
            if line.as_slice() == b"OK" || line.starts_with(b"OK ") {
                return Ok(fallback);
            }
            return Err(io::Error::other("invalid fallback greeting"));
        }
    }

    pub fn transact(
        &mut self,
        command: &[u8],
        client: &mut impl BufRead,
        output: &mut impl Write,
    ) -> io::Result<bool> {
        send(&mut self.input, command)?;
        loop {
            let line = read_line(&mut self.output)?
                .ok_or_else(|| io::Error::other("fallback closed during command"))?;
            send(output, &line)?;
            if line.as_slice() == b"OK" || line.starts_with(b"OK ") {
                return Ok(true);
            }
            if line.as_slice() == b"ERR" || line.starts_with(b"ERR ") {
                return Ok(false);
            }
            if line.as_slice() == b"INQUIRE" || line.starts_with(b"INQUIRE ") {
                // Relay inquiries (e.g. passphrase quality) rather than consuming
                // the next agent command as though it were a new transaction.
                loop {
                    let reply = read_line(client)?
                        .ok_or_else(|| io::Error::other("client closed during inquiry"))?;
                    let terminal = reply.as_slice() == b"END" || reply.as_slice() == b"CAN";
                    if !terminal && !reply.starts_with(b"D ") && reply.as_slice() != b"D" {
                        return Err(io::Error::other("invalid inquiry response"));
                    }
                    send(&mut self.input, &reply)?;
                    if terminal {
                        break;
                    }
                }
            }
        }
    }
}

impl Drop for Fallback {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
