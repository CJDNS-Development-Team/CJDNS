//! Errors.

use std::fmt;

use tokio::io;

use crate::ConnectionOptions;

// This wrapper is needed because underlying `ConnectionOptions` is not intended to be made public type.
// It is only useful to be printed on the screen.
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct ConnOptions(ConnectionOptions);

impl ConnOptions {
    pub(crate) fn wrap(opts: &ConnectionOptions) -> Self {
        ConnOptions(opts.clone())
    }
}

/// Error type for all cjdns admin operations.
#[derive(Debug)]
pub enum Error {
    /// Connection error - check the remote IP address and port.
    ConnectError(ConnOptions),

    /// Authentication error - check the password.
    AuthError(ConnOptions),

    /// Failed to read cjdnsadmin config file (`~/.cjdnsadmin` by default).
    ConfigFileRead(io::Error),

    /// Error parsing cjdnsadmin config file (`~/.cjdnsadmin` by default) - must be a valid JSON file.
    BadConfigFile(serde_json::Error),

    /// Failed to parse IPv4/IPv6 address.
    BadNetworkAddress(std::net::AddrParseError),

    /// Network I/O error.
    NetworkOperation(io::Error),

    /// Failed to serialize/deserialize protocol message (using *bencode*).
    Protocol(bendy::serde::Error),

    /// Remote invocation failed and returned `error` message.
    RemoteError(String),

    /// Unexpected transaction id during message exchange. Supposed to be internal error.
    #[allow(missing_docs)]
    BrokenTx { sent_txid: String, received_txid: String },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let used_config_str = |config: &Option<String>| {
            if let Some(config_file) = config {
                format!(" using cjdnsadmin file at [{}]", config_file)
            } else {
                "".to_string()
            }
        };

        match self {
            Error::ConnectError(ConnOptions(opts)) => {
                write!(
                    f,
                    "Could not find cjdns ({}:{}){} see: https://github.com/cjdelisle/cjdnsadmin#connecting",
                    opts.addr, opts.port, used_config_str(&opts.used_config_file)
                )
            }
            Error::AuthError(ConnOptions(opts)) => {
                write!(
                    f,
                    "Could not authenticate with CJDNS ({}:{}){} see: https://github.com/cjdelisle/cjdnsadmin#authentication-issues",
                    opts.addr, opts.port, used_config_str(&opts.used_config_file)
                )
            }
            Error::ConfigFileRead(e) => write!(f, "File error: {}", e),
            Error::BadConfigFile(e) => write!(f, "JSON parse error: {}", e),
            Error::BadNetworkAddress(e) => write!(f, "Address parse error: {}", e),
            Error::NetworkOperation(e) => write!(f, "UDP error: {}", e),
            Error::Protocol(e) => write!(f, "Encoding error: {}", e),
            Error::RemoteError(msg) => write!(f, "Remote call error: {}", msg),
            Error::BrokenTx { sent_txid, received_txid } => write!(f, "Broken txid: sent {} but received {}", sent_txid, received_txid),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::ConnectError { .. } => None,
            Error::AuthError { .. } => None,
            Error::ConfigFileRead(e) => Some(e),
            Error::BadConfigFile(e) => Some(e),
            Error::BadNetworkAddress(e) => Some(e),
            Error::NetworkOperation(e) => Some(e),
            Error::Protocol(e) => Some(e),
            Error::RemoteError(_) => None,
            Error::BrokenTx { .. } => None,
        }
    }
}
