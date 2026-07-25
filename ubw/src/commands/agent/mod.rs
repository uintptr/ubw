use std::{fmt::Display, sync::mpsc::Sender};

use log::warn;

mod credentials;
pub mod server;
mod ssh;
mod storage;

/// Why the daemon is coming down.
///
/// Every listener and client thread holds a [`Sender`], so whichever one
/// notices first gets the main thread moving again.
#[derive(Debug)]
pub enum ShutdownReason {
    /// A signal asked us to stop.
    Signal(&'static str),
    /// A client sent `ChannelRequest::Stop`, i.e. `ubw agent --stop`.
    StopRequested,
    /// A listener gave up. The daemon is useless without it.
    ListenerFailed(&'static str),
}

impl Display for ShutdownReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Signal(name) => write!(f, "received {name}"),
            Self::StopRequested => write!(f, "a client requested a shutdown"),
            Self::ListenerFailed(listener) => write!(f, "the {listener} listener failed"),
        }
    }
}

/// Ask the daemon to shut down.
///
/// Best effort: a closed channel means the main thread already moved on, which
/// is exactly what we were trying to tell it.
pub fn signal_shutdown(shutdown: &Sender<ShutdownReason>, reason: ShutdownReason) {
    if let Err(e) = shutdown.send(reason) {
        warn!("shutdown already in progress ({e})");
    }
}
