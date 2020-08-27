//! CJDNS Admin lib

#![deny(missing_docs)]

pub use self::config::Opts;
pub use self::conn::Connection;
pub use self::errors::Error;

mod config;
mod conn;
mod errors;
mod txid;
pub mod func_args;
pub mod func_list;
pub mod func_ret;
pub mod msgs;

#[derive(Clone, Default, PartialEq, Eq, Debug)]
struct ConnectionOptions {
    addr: String,
    port: u16,
    password: String,
    used_config_file: Option<String>,
}

/// Connect to the running cjdns router instance.
/// If `opts` is not provided, the default config file is read.
/// or only specified config file name,
/// the corresponding config file is read.
pub async fn connect(opts: Option<Opts>) -> Result<Connection, Error> {
    let opts = opts.unwrap_or_default().into_connection_options().await?;
    conn::Connection::new(opts).await
}