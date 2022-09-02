//! CJDNS Admin lib

#![deny(missing_docs)]

extern crate cjdns_bencode as bencode;

pub use crate::config::Opts;
pub use crate::conn::Connection;
pub use crate::errors::Error;
pub use crate::func_args::{ArgName, ArgValue, ArgValues};
pub use crate::func_list::{Arg, ArgType, Args, Func, Funcs};
pub use crate::func_ret::ReturnValue;
use std::sync::Arc;

mod config;
mod conn;
mod errors;
mod func_args;
mod func_list;
mod func_ret;
pub mod msgs;
mod txid;

#[derive(Clone, Default, PartialEq, Eq, Debug)]
struct ConnectionOptions {
    addr: Arc<String>,
    port: u16,
    password: Arc<String>,
    used_config_file: Option<String>,
}

/// Connect to the running cjdns router instance.
/// If `opts` is not provided, the default config file is read.
/// or only specified config file name,
/// the corresponding config file is read.
pub async fn connect(opts: Option<Opts>) -> Result<Connection, Error> {
    let opts = opts.unwrap_or_default().into_connection_options().await?;
    Connection::new(opts).await
}

/// Helper macro to easily invoke remote function with arguments.
///
/// Examples:
/// ```no_run
/// # use cjdns_admin::cjdns_invoke;
/// # async fn test() -> Result<(), Box<dyn std::error::Error>> {
/// # let mut conn = cjdns_admin::connect(None).await?;
/// let res = cjdns_invoke!(conn, "FuncName").await?;
/// let res = cjdns_invoke!(conn, "FuncName", "arg1" = 42, "arg2" = "foobar").await?;
/// # Ok(())}
/// ```
#[macro_export]
macro_rules! cjdns_invoke {
    ($cjdns:expr, $fn_name:literal) => {
        $cjdns.invoke::<_, $crate::msgs::GenericResponsePayload>($fn_name, $crate::ArgValues::new())
    };
    ($cjdns:expr, $fn_name:literal, $( $arg_name:literal = $arg_value:expr ),*) => {
        $cjdns.invoke::<_, $crate::msgs::GenericResponsePayload>($fn_name, $crate::ArgValues::new() $( .add($arg_name, $arg_value) )*)
    };
}
