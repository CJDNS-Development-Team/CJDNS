//! Errors.

use std::time::Duration;

use thiserror::Error;
use tokio::io;

use crate::ConnectionOptions;

// This wrapper is needed because underlying `ConnectionOptions` is not intended to be made public type.
// It is only useful to be printed on the screen.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ConnOptions(ConnectionOptions);

impl ConnOptions {
    pub(crate) fn wrap(opts: &ConnectionOptions) -> Self {
        ConnOptions(opts.clone())
    }

    fn descr(&self) -> String {
        let ConnOptions(opts) = self;

        match opts {
            ConnectionOptions::Socket(s) => s.clone(),
            ConnectionOptions::Udp(opts) => {
                let mut msg = format!("({}:{})", opts.addr, opts.port);

                if let Some(ref config_file) = opts.used_config_file {
                    msg += &format!(" using cjdnsadmin file at [{}]", config_file);
                }

                msg
            }
        }
    }
}

/// Error type for all cjdns admin operations.
#[derive(Error, Debug)]
pub enum Error {
    /// Connection error - check the remote IP address and port.
    #[error("Could not find cjdns {}, see: https://github.com/cjdelisle/cjdnsadmin#connecting", .0.descr())]
    ConnectError(ConnOptions),

    /// Authentication error - check the password.
    #[error("Could not authenticate with CJDNS {}, see: https://github.com/cjdelisle/cjdnsadmin#authentication-issues", .0.descr())]
    AuthError(ConnOptions),

    /// Failed to read cjdnsadmin config file (`~/.cjdnsadmin` by default).
    #[error("Error reading config file: {0}")]
    ConfigFileRead(#[source] io::Error),

    /// Error parsing cjdnsadmin config file (`~/.cjdnsadmin` by default) - must be a valid JSON file.
    #[error("Bad config file: JSON parse error: {0}")]
    BadConfigFile(#[source] serde_json::Error),

    /// Failed to parse IPv4/IPv6 address.
    #[error("Address parse error: {0}")]
    BadNetworkAddress(#[source] std::net::AddrParseError),

    /// Network I/O error.
    #[error("UDP error: {0}")]
    NetworkOperation(#[source] io::Error),

    /// Failed to serialize/deserialize protocol message (using *bencode*).
    #[error("Encoding error: {0}")]
    Protocol(#[source] bencode::Error),

    /// Remote invocation failed and returned `error` message.
    #[error("Remote call error: {0}")]
    RemoteError(String),

    /// Unexpected transaction id during message exchange. Supposed to be internal error.
    #[allow(missing_docs)]
    #[error("Broken txid: sent {sent_txid} but received {received_txid}")]
    BrokenTx { sent_txid: String, received_txid: String },

    /// Network timeout error.
    #[error("Timeout occured: {0:?}")]
    TimeOut(Duration),
}
