//! Synchronous TLS connection wrapping a `Read + Write` transport.

mod client;
mod server;

pub use client::TlsClientConnection;
pub use server::TlsServerConnection;

/// Connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConnectionState {
    Handshaking,
    Connected,
    Closed,
    Error,
}

#[cfg(test)]
mod tests;
