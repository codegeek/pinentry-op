use crate::config::Config;
use std::{
    io::{self, Read},
    os::fd::AsRawFd,
    process::{Command, Stdio},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const MAX_SECRET: usize = 65536;

// Keep the pipe nonblocking so authentication cannot hold the agent forever.
// stderr is deliberately discarded: CLI errors can contain sensitive metadata.
pub fn read(
    config: &Config,
    reference: &str,
    timeout: Option<u64>,
) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut command = Command::new(&config.op_program);
    command.args(["read", "--no-newline", reference]);
    if let Some(account) = &config.account {
        command.args(["--account", account]);
    }
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let result = (|| {
        let mut stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("missing CLI pipe"))?;
        let fd = stdout.as_raw_fd();
        // SAFETY: fd is an open pipe owned by stdout; F_GETFL and F_SETFL do not take pointers.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let seconds = timeout
            .unwrap_or(config.timeout_seconds)
            .min(config.timeout_seconds);
        let deadline = Instant::now() + Duration::from_secs(seconds);
        let mut secret = Zeroizing::new(Vec::with_capacity(MAX_SECRET));
        let mut buffer = Zeroizing::new([0u8; 4096]);
        let mut eof = false;
        loop {
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "1Password lookup timed out",
                ));
            }
            if !eof {
                match stdout.read(buffer.as_mut()) {
                    Ok(0) => eof = true,
                    Ok(n) => {
                        if secret.len() + n > MAX_SECRET {
                            return Err(io::Error::other("secret exceeds size limit"));
                        }
                        secret.extend_from_slice(&buffer[..n]);
                    }
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                        ) => {}
                    Err(e) => return Err(e),
                }
            }
            if eof {
                if let Some(status) = child.try_wait()? {
                    if !status.success() || secret.contains(&0) {
                        return Err(io::Error::other("1Password lookup failed"));
                    }
                    return Ok(secret);
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    })();
    // Kill and reap on every error, including timeout and pipe setup failure.
    if result.is_err() {
        let _ = child.kill();
    }
    let _ = child.wait();
    result
}
