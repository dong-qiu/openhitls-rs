//! Synchronous TLS 1.2 connection wrapping a `Read + Write` transport.
//!
//! Provides `Tls12ClientConnection` and `Tls12ServerConnection` implementing
//! the `TlsConnection` trait for TLS 1.2 ECDHE-GCM cipher suites.

mod client;
mod server;

pub use client::Tls12ClientConnection;
pub use server::Tls12ServerConnection;

/// Connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConnectionState {
    Handshaking,
    Connected,
    Renegotiating,
    Closed,
    Error,
}

#[cfg(test)]
mod tests;
