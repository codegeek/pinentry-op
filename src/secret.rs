use crate::config::Config;
use std::{
    io::{self, Read},
    os::{fd::AsRawFd, unix::process::CommandExt},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const MAX_SECRET: usize = 65536;

pub enum LookupError {
    // The CLI could not run or produced no usable secret; the user did not
    // decline anything, so a manual prompt is appropriate.
    Unavailable,
    // The CLI failed or timed out. Its exit status cannot reliably
    // distinguish cancellation across versions, so the caller fails closed.
    Failed,
}

// Keep the pipe nonblocking so authentication cannot hold the agent forever.
// stderr is deliberately discarded: CLI errors can contain sensitive metadata.
pub fn read(
    config: &Config,
    reference: &str,
    timeout: Option<u64>,
) -> Result<Zeroizing<Vec<u8>>, LookupError> {
    let mut command = Command::new(&config.op_program);
    command.args(["read", "--no-newline", reference]);
    if let Some(account) = &config.account {
        command.args(["--account", account]);
    }
    // A dedicated process group lets a timeout also kill any helpers the CLI spawned.
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .map_err(|_| LookupError::Unavailable)?;
    let seconds = timeout
        .unwrap_or(config.timeout_seconds)
        .min(config.timeout_seconds);
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let result = collect(&mut child, deadline);
    // Kill and reap on every error, including timeout and pipe setup failure,
    // and when output is truncated because the CLI may still be writing.
    if result
        .as_ref()
        .map_or(true, |secret| secret.len() > MAX_SECRET)
    {
        // SAFETY: kill takes no pointers; the negative pid names the child's own group.
        unsafe { libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL) };
        let _ = child.kill();
    }
    let _ = child.wait();
    let secret = result.map_err(|_| LookupError::Failed)?;
    if secret.is_empty() || secret.len() > MAX_SECRET || secret.contains(&0) {
        return Err(LookupError::Unavailable);
    }
    Ok(secret)
}

// Returns at most MAX_SECRET + 1 bytes, so oversized output is detectable
// without buffering it all.
fn collect(child: &mut Child, deadline: Instant) -> io::Result<Zeroizing<Vec<u8>>> {
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
    let mut secret = Zeroizing::new(Vec::with_capacity(MAX_SECRET + 1));
    let mut buffer = Zeroizing::new([0u8; 4096]);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(timed_out());
        }
        let mut pollfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let millis = remaining.as_millis().clamp(1, libc::c_int::MAX as u128) as libc::c_int;
        // SAFETY: pollfd is a valid, initialized array of length 1 for the duration of the call.
        if unsafe { libc::poll(&mut pollfd, 1, millis) } < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        // Drain everything available before polling again.
        loop {
            match stdout.read(buffer.as_mut()) {
                Ok(0) => return wait_for_exit(child, deadline).map(|()| secret),
                Ok(n) => {
                    let take = n.min(MAX_SECRET + 1 - secret.len());
                    secret.extend_from_slice(&buffer[..take]);
                    if secret.len() > MAX_SECRET {
                        return Ok(secret);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }
    }
}

// The CLI normally exits as soon as it closes stdout, so a short sleep loop suffices.
fn wait_for_exit(child: &mut Child, deadline: Instant) -> io::Result<()> {
    loop {
        if let Some(status) = child.try_wait()? {
            return if status.success() {
                Ok(())
            } else {
                Err(io::Error::other("1Password lookup failed"))
            };
        }
        if Instant::now() >= deadline {
            return Err(timed_out());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "1Password lookup timed out")
}
