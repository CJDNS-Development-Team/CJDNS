//! CJDNS Admin lib

#![deny(missing_docs)]

pub use self::config::Opts;
pub use self::conn::Connection;
pub use self::errors::Error;

#[derive(Clone, Default, PartialEq, Eq, Debug)]
struct ConnectionOptions {
    addr: String,
    port: u16,
    password: String,
    used_config_file: Option<String>,
}

mod errors {
    use std;
    use std::fmt;

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
        ConfigFileRead(std::io::Error),

        /// Error parsing cjdnsadmin config file (`~/.cjdnsadmin` by default) - must be a valid JSON file.
        BadConfigFile(serde_json::Error),

        /// Failed to parse IPv4/IPv6 address.
        BadNetworkAddress(std::net::AddrParseError),

        /// Network I/O error.
        NetworkOperation(std::io::Error),

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
}

mod config {
    use std::fs;
    use std::io;
    use std::path::{Path, PathBuf};

    use serde::Deserialize;

    use crate::ConnectionOptions;
    use crate::errors::Error;

    const DEFAULT_ADDR: &'static str = "127.0.0.1";
    const DEFAULT_PORT: u16 = 11234;
    const DEFAULT_PASSWORD: &'static str = "NONE";
    const DEFAULT_CONFIG_FILE_NAME: &'static str = ".cjdnsadmin";

    /// Connection options. Can be loaded from a config file.
    #[derive(Clone, Default, PartialEq, Eq, Debug, Deserialize)]
    pub struct Opts {
        /// Remote IP address (either IPv4 or IPv6).
        #[serde(rename = "addr")]
        pub addr: Option<String>,

        /// Remote UDP port.
        #[serde(rename = "port")]
        pub port: Option<u16>,

        /// Password for authentication. If `None`, default "NONE" password is used.
        #[serde(rename = "password")]
        pub password: Option<String>,

        /// Optional path to config file (`~/.cjdnsadmin` used by default).
        #[serde(rename = "cjdnsadminPath")]
        pub config_file_path: Option<String>,

        /// Anonymous connection - do not use password.
        #[serde(rename = "anon", default)]
        pub anon: bool,
    }

    impl Opts {
        pub(super) fn into_connection_options(self) -> Result<ConnectionOptions, Error> {
            // Do we need to try to read config file?
            let is_configured = (self.addr.is_some() || self.port.is_some() || self.password.is_some()) && self.config_file_path.is_none();

            // Options to use
            let mut opts = self;
            let mut conf_file = None;

            // Try to read config file
            if !is_configured {
                if let Some(config_file) = opts.get_config_file_location() {
                    if let Some(config) = Self::read_optional_config_file(&config_file)? {
                        opts = config;
                        conf_file = Some(config_file);
                    }
                }
            }

            // Build resulting options
            Ok(Self::build_connection_options(opts, conf_file))
        }

        fn build_connection_options(self, conf_file: Option<PathBuf>) -> ConnectionOptions {
            ConnectionOptions {
                addr: self.addr.as_ref().map_or(DEFAULT_ADDR, |s| &s).to_string(),
                port: self.port.unwrap_or(DEFAULT_PORT),
                password: self.password.as_ref().map_or_else(|| if self.anon { "" } else { DEFAULT_PASSWORD }, |s| &s).to_string(),
                used_config_file: conf_file.map(|path| path.to_string_lossy().into_owned()),
            }
        }

        fn get_config_file_location(&self) -> Option<PathBuf> {
            if let Some(ref cfg_file) = self.config_file_path {
                return Some(PathBuf::from(cfg_file));
            }

            if let Some(mut path) = dirs::home_dir() {
                path.push(DEFAULT_CONFIG_FILE_NAME);
                return Some(path);
            }

            None // Unable to locate HOME dir - unsupported platform?
        }

        fn parse_config(json: &[u8]) -> Result<Self, Error> {
            serde_json::from_slice(json).map_err(|e| Error::BadConfigFile(e))
        }

        fn read_config_file(file_path: &Path) -> Result<Self, Error> {
            let json = fs::read(file_path).map_err(|e| Error::ConfigFileRead(e))?;
            Self::parse_config(&json)
        }

        fn read_optional_config_file(file_path: &Path) -> Result<Option<Self>, Error> {
            match Self::read_config_file(file_path) {
                Ok(conf) => Ok(Some(conf)),
                Err(Error::ConfigFileRead(err)) if err.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(err) => Err(err),
            }
        }
    }

    #[test]
    fn test_build_connection_options() {
        let s = |s: &str| -> String { s.to_string() };
        let ss = |s: &str| -> Option<String> { Some(s.to_string()) };

        assert_eq!(
            Opts::default().build_connection_options(None),
            ConnectionOptions {
                addr: s("127.0.0.1"),
                port: 11234,
                password: s("NONE"),
                used_config_file: None,
            }
        );

        assert_eq!(
            Opts { anon: true, ..Opts::default() }.build_connection_options(None),
            ConnectionOptions {
                addr: s("127.0.0.1"),
                port: 11234,
                password: s(""),
                used_config_file: None,
            }
        );

        assert_eq!(
            Opts { addr: ss("192.168.1.1"), ..Opts::default() }.build_connection_options(None),
            ConnectionOptions {
                addr: s("192.168.1.1"),
                port: 11234,
                password: s("NONE"),
                used_config_file: None,
            }
        );

        assert_eq!(
            Opts { port: Some(1234), ..Opts::default() }.build_connection_options(None),
            ConnectionOptions {
                addr: s("127.0.0.1"),
                port: 1234,
                password: s("NONE"),
                used_config_file: None,
            }
        );

        assert_eq!(
            Opts { password: ss("secret"), ..Opts::default() }.build_connection_options(None),
            ConnectionOptions {
                addr: s("127.0.0.1"),
                port: 11234,
                password: s("secret"),
                used_config_file: None,
            }
        );
    }

    #[test]
    fn test_parse_config() {
        let s = |s: &str| -> Option<String> { Some(s.to_string()) };
        let c = |json: &str| -> Opts { Opts::parse_config(json.as_bytes()).expect("bad test config") };

        assert_eq!(c(r#"{}"#), Opts::default());

        assert_eq!(c(r#"{ "unknown": "foo" }"#), Opts::default());

        assert_eq!(c(r#"{ "addr": "192.168.1.1" }"#), Opts { addr: s("192.168.1.1"), ..Opts::default() });
        assert_eq!(c(r#"{ "port": 1234 }"#), Opts { port: Some(1234), ..Opts::default() });
        assert_eq!(c(r#"{ "password": "secret" }"#), Opts { password: s("secret"), ..Opts::default() });

        assert_eq!(
            c(r#"{ "addr": "192.168.1.1", "port": 1234, "password": "secret" }"#),
            Opts { addr: s("192.168.1.1"), port: Some(1234), password: s("secret"), ..Opts::default() }
        );
    }
}

/// Connect to the running cjdns router instance.
/// If `opts` is not provided, the default config file is read.
/// or only specified config file name,
/// the corresponding config file is read.
pub fn connect(opts: Option<Opts>) -> Result<Connection, Error> {
    let opts = opts.unwrap_or_default().into_connection_options()?;
    conn::Connection::new(opts)
}

mod conn {
    use std::net::{IpAddr, SocketAddr, UdpSocket};
    use std::time::Duration;

    use sodiumoxide::crypto::hash::sha256::hash;

    use crate::ConnectionOptions;
    use crate::errors::{ConnOptions, Error};
    use crate::func_list::Funcs;
    use crate::msgs::{self, Empty, Request};
    use crate::txid::Counter;

    const PING_TIMEOUT: Duration = Duration::from_millis(1_000);
    const DEFAULT_TIMEOUT: Duration = Duration::from_millis(10_000);

    /// Admin connection to the CJDNS node.
    pub struct Connection {
        socket: UdpSocket,
        password: String,
        counter: Counter,

        /// List of available remote functions.
        pub functions: Funcs,
    }

    impl Connection {
        pub(super) fn new(opts: ConnectionOptions) -> Result<Self, Error> {
            let mut conn = Connection {
                socket: create_udp_socket_sender(&opts.addr, opts.port)?,
                password: opts.password.clone(),
                counter: Counter::new_random(),
                functions: Funcs::default(),
            };

            conn.probe_connection(opts)?;
            let fns = conn.load_available_functions()?;
            conn.functions = fns;

            Ok(conn)
        }

        fn set_timeout(&self, timeout: Duration) -> Result<(), Error> {
            self.socket.set_read_timeout(Some(timeout)).map_err(|e| Error::NetworkOperation(e))?;
            self.socket.set_write_timeout(Some(timeout)).map_err(|e| Error::NetworkOperation(e))?;
            Ok(())
        }

        fn probe_connection(&self, opts: ConnectionOptions) -> Result<(), Error> {
            self.set_timeout(PING_TIMEOUT)?;
            self.call_func::<(), Empty>("ping", (), true).map_err(|_| Error::ConnectError(ConnOptions::wrap(&opts)))?;

            self.set_timeout(DEFAULT_TIMEOUT)?;
            if !self.password.is_empty() {
                self.call_func::<(), Empty>("AuthorizedPasswords_list", (), false).map_err(|_| Error::AuthError(ConnOptions::wrap(&opts)))?;
            }

            Ok(())
        }

        fn load_available_functions(&self) -> Result<Funcs, Error> {
            let mut res = Funcs::new();

            for i in 0.. {
                let ret: msgs::AvailableFnsResponsePayload = self.call_func("Admin_availableFunctions", msgs::AvailableFnsQueryArg { page: i }, false)?;
                let funcs = ret.available_fns;

                if funcs.is_empty() {
                    break; // Empty answer - no more pages
                }

                res.add_funcs(funcs);
            }

            Ok(res)
        }

        /// Call remote function.
        pub fn call_func<A: msgs::Args, P: msgs::Payload>(&self, remote_fn_name: &str, args: A, disable_auth: bool) -> Result<P, Error> {
            //dbg!(remote_fn_name);

            if disable_auth || self.password.is_empty() {
                self.call_func_no_auth(remote_fn_name, args)
            } else {
                self.call_func_auth(remote_fn_name, args)
            }
        }

        fn call_func_no_auth<A: msgs::Args, P: msgs::Payload>(&self, remote_fn_name: &str, args: A) -> Result<P, Error> {
            let msg = msgs::Query {
                txid: self.counter.next().to_string(),
                q: remote_fn_name.to_string(),
                args,
            };

            let resp: msgs::GenericResponse<P> = self.send_msg(&msg)?;
            check_txid(&msg.txid, &resp.txid)?;
            check_remote_error(&resp.error)?;

            Ok(resp.payload)
        }

        fn call_func_auth<A: msgs::Args, P: msgs::Payload>(&self, remote_fn_name: &str, args: A) -> Result<P, Error> {
            // Ask cjdns for a cookie first
            let new_cookie = {
                let resp: msgs::CookieResponsePayload = self.call_func_no_auth("cookie", ())?;
                resp.cookie
            };

            // Hash password with salt
            let passwd_hash = {
                let cookie_passwd = self.password.clone() + &new_cookie;
                let digest = hash(cookie_passwd.as_bytes());
                hex::encode(digest)
            };

            // Prepare message with initial hash
            let mut msg = msgs::AuthQuery {
                txid: self.counter.next().to_string(),
                q: "auth".to_string(),
                aq: remote_fn_name.to_string(),
                args,
                cookie: new_cookie,
                hash: passwd_hash,
            };

            // Update message's hash
            let msg_hash = {
                let msg_bytes = msg.to_bencode()?;
                let digest = hash(&msg_bytes);
                hex::encode(digest)
            };
            msg.hash = msg_hash;

            // Send/receive
            let resp: msgs::GenericResponse<P> = self.send_msg(&msg)?;
            check_txid(&msg.txid, &resp.txid)?;
            check_remote_error(&resp.error)?;

            Ok(resp.payload)
        }

        fn send_msg<RQ, RS>(&self, req: &RQ) -> Result<RS, Error>
            where RQ: msgs::Request,
                  RS: msgs::Response
        {
            // Send encoded request
            let msg = req.to_bencode()?;
            //dbg!(String::from_utf8_lossy(&msg));
            self.socket.send(&msg).map_err(|e| Error::NetworkOperation(e))?;

            // Limit receive packet lenght to typical Ethernet MTU for now; need to check actual max packet length on CJDNS Node side though.
            let mut buf = [0; 1500];

            // Reseive encoded response synchronously
            let received = self.socket.recv(&mut buf).map_err(|e| Error::NetworkOperation(e))?;
            let response = &buf[..received];
            //dbg!(String::from_utf8_lossy(&response));

            // Decode response
            RS::from_bencode(response)
        }
    }

    #[inline]
    fn create_udp_socket_sender(addr: &str, port: u16) -> Result<UdpSocket, Error> {
        let ip_addr = addr.parse::<IpAddr>().map_err(|e| Error::BadNetworkAddress(e))?;
        let remote_address = SocketAddr::new(ip_addr, port);

        let local_address = "0.0.0.0:0";
        let socket = UdpSocket::bind(local_address).map_err(|e| Error::NetworkOperation(e))?;
        socket.connect(&remote_address).map_err(|e| Error::NetworkOperation(e))?;

        Ok(socket)
    }

    #[inline]
    fn check_txid(sent_txid: &String, received_txid: &String) -> Result<(), Error> {
        if sent_txid == received_txid {
            Ok(())
        } else {
            Err(Error::BrokenTx { sent_txid: sent_txid.clone(), received_txid: received_txid.clone() })
        }
    }

    #[inline]
    fn check_remote_error(remote_error_msg: &str) -> Result<(), Error> {
        if remote_error_msg.is_empty() || remote_error_msg.eq_ignore_ascii_case("none") {
            Ok(())
        } else {
            Err(Error::RemoteError(remote_error_msg.to_string()))
        }
    }
}

/// Transaction counter.
mod txid {
    use std::sync::atomic::{AtomicU64, Ordering};

    use rand::Rng;

    /// Transaction counter.
    pub(super) struct Counter(AtomicU64);

    impl Counter {
        pub(super) fn new_random() -> Self {
            let init = rand::thread_rng().gen_range(0, 4_000_000_000);
            Counter(AtomicU64::new(init))
        }

        pub(super) fn next(&self) -> u64 {
            let Counter(ref counter) = self;
            counter.fetch_add(1, Ordering::Relaxed)
        }
    }
}

/// RPC messages.
pub mod msgs {
    use std::collections::BTreeMap;

    use serde::{de::DeserializeOwned, Deserialize, Serialize};

    use crate::func_ret::ReturnValue;

    pub(crate) use self::internal::*;

    /// Traits and their blanket implementations used internally to encode/decode RPC messages.
    mod internal {
        use serde::{de::DeserializeOwned, Deserialize, Serialize};

        use crate::errors::Error;

        use super::{Args, Payload};

        /// Internal trait for the RPC request type. Implemented by `Query` and `AuthQuery`.
        pub(crate) trait Request: Sized {
            fn to_bencode(&self) -> Result<Vec<u8>, Error>;
        }

        /// Internal trait for the RPC response type. Implemented by `GenericResponse`.
        pub(crate) trait Response: Sized {
            fn from_bencode(bytes: &[u8]) -> Result<Self, Error>;
        }

        // Implements `Request` for `Query` and `QueryAuth`.
        impl<T: Serialize> Request for T {
            fn to_bencode(&self) -> Result<Vec<u8>, Error> {
                bendy::serde::to_bytes(self).map_err(|e| Error::Protocol(e))
            }
        }

        // Implements `Response` for `GenericResponse`.
        impl<T: DeserializeOwned> Response for T {
            fn from_bencode(bytes: &[u8]) -> Result<Self, Error> {
                bendy::serde::from_bytes(bytes).map_err(|e| Error::Protocol(e))
            }
        }

        /// Generic RPC query without authentication.
        #[derive(Serialize, Clone, PartialEq, Eq, Debug)]
        pub(crate) struct Query<A: Args> {
            #[serde(rename = "txid")]
            pub(crate) txid: String,

            #[serde(rename = "q")]
            pub(crate) q: String,

            #[serde(rename = "args")]
            pub(crate) args: A,
        }

        /// Generic RPC query with authentication.
        #[derive(Serialize, Clone, PartialEq, Eq, Debug)]
        pub(crate) struct AuthQuery<A: Args> {
            #[serde(rename = "txid")]
            pub(crate) txid: String,

            #[serde(rename = "q")]
            pub(crate) q: String,

            #[serde(rename = "aq")]
            pub(crate) aq: String,

            #[serde(rename = "args")]
            pub(crate) args: A,

            #[serde(rename = "cookie")]
            pub(crate) cookie: String,

            #[serde(rename = "hash")]
            pub(crate) hash: String,
        }

        /// Generic RPC response.
        #[derive(Deserialize, Clone, PartialEq, Eq, Debug)]
        pub(crate) struct GenericResponse<P: Payload> {
            #[serde(rename = "txid")]
            pub(crate) txid: String,

            #[serde(rename = "error", default)]
            pub(crate) error: String,

            #[serde(flatten, default)]
            #[serde(bound(deserialize = "P: DeserializeOwned"))]
            pub(crate) payload: P,
        }

        #[test]
        fn test_bencode_leading_zeroes() {
            /*
             * Bencode does not allow leading zeroes in encoded integers.
             * Alas, cjdns' original implementation violates this rule,
             * and sometimes encodes ints with leading zeroes.
             * To work around this, bencode library (bendy) should be patched
             * to support this.
             * This test checks that we use correct (patched) library.
             */
            assert_eq!(u8::from_bencode("i042e".as_bytes()).ok(), Some(42_u8));
        }
    }

    /// Trait for RPC query arguments. Can be any serializable type.
    pub trait Args: Serialize {}

    /// Trait for RPC query return value. Can be any deserializable type with `Default`.
    pub trait Payload: DeserializeOwned + Default {}

    // Blanket `Args` impl for any serializable type.
    impl<T: Serialize> Args for T {}

    // Blanket `Payload` impl for any deserializable type with `Default`.
    impl<T: DeserializeOwned + Default> Payload for T {}

    /// Empty payload or arguments.
    #[derive(Deserialize, Serialize, Default, Clone, PartialEq, Eq, Debug)]
    pub struct Empty {}

    /// Generic return value with fields exposed as a map.
    pub type GenericResponsePayload = BTreeMap<String, ReturnValue>;

    /// Return value for `cookie` remote function.
    #[derive(Deserialize, Default, Clone, PartialEq, Eq, Debug)]
    pub(crate) struct CookieResponsePayload {
        #[serde(rename = "cookie")]
        pub(crate) cookie: String
    }

    /// Arguments for `Admin_availableFunctions` remote function.
    #[derive(Serialize, Clone, PartialEq, Eq, Debug)]
    pub(crate) struct AvailableFnsQueryArg {
        #[serde(rename = "page")]
        pub(crate) page: usize
    }

    /// Return value for `Admin_availableFunctions` remote function.
    #[derive(Deserialize, Default, Clone, PartialEq, Eq, Debug)]
    pub(crate) struct AvailableFnsResponsePayload {
        #[serde(rename = "availableFunctions", default)]
        pub(crate) available_fns: RemoteFnDescrs
    }

    /// Map of remote function names to map of arguments.
    pub(crate) type RemoteFnDescrs = BTreeMap<String, RemoteFnArgsDescr>;

    /// Map of function argument names to argument descriptions.
    pub(crate) type RemoteFnArgsDescr = BTreeMap<String, RemoteFnArgDescr>;

    /// Remote function argument description.
    #[derive(Deserialize, Default, Clone, PartialEq, Eq, Debug)]
    pub(crate) struct RemoteFnArgDescr {
        #[serde(rename = "required")]
        pub(crate) required: u8,

        #[serde(rename = "type")]
        pub(crate) typ: String,
    }
}

/// List of remote functions.
pub mod func_list {
    use std::fmt;

    use crate::msgs::{RemoteFnArgsDescr, RemoteFnDescrs};

    /// List of available remote functions.
    #[derive(Clone, Default, PartialEq, Eq, Debug)]
    pub struct Funcs(Vec<Func>);

    /// Remote function description.
    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct Func {
        /// Function name.
        pub name: String,
        /// Function argument descriptions.
        pub args: Args,
    }

    /// Remote function arguments description.
    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct Args(Vec<Arg>);

    /// Remote function argument description.
    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct Arg {
        /// Argument name.
        pub name: String,
        /// Required argument flag.
        pub required: bool,
        /// Argument type.
        pub typ: ArgType,
    }

    /// Remote function argument type.
    #[derive(Clone, PartialEq, Eq, Debug)]
    pub enum ArgType {
        /// Integer argument.
        Int,
        /// String argument.
        String,
        /// Some other type which is not supported directly.
        Other(String),
    }

    impl Funcs {
        #[inline]
        pub(super) fn new() -> Self {
            Funcs(Vec::new())
        }

        pub(super) fn add_funcs(&mut self, fns: RemoteFnDescrs) {
            let Funcs(list) = self;
            for (fn_name, fn_descr) in fns.into_iter() {
                let func = Self::parse_fn(fn_name, fn_descr);
                list.push(func);
            }
            list.sort_by(|a, b| String::cmp(&a.name, &b.name));
        }

        fn parse_fn(fn_name: String, fn_args: RemoteFnArgsDescr) -> Func {
            let mut args = Vec::with_capacity(fn_args.len());
            for (arg_name, arg_descr) in fn_args {
                let arg = Arg {
                    name: arg_name,
                    required: arg_descr.required != 0,
                    typ: arg_descr.typ.into(),
                };
                args.push(arg);
            }
            args.sort_by(|a, b| bool::cmp(&a.required, &b.required).reverse().then(String::cmp(&a.name, &b.name)));

            Func {
                name: fn_name,
                args: Args(args),
            }
        }

        /// Iterator over functions in this list returned in alphabetical order.
        #[inline]
        pub fn iter(&self) -> impl Iterator<Item=&Func> {
            let Funcs(list) = self;
            list.iter()
        }

        /// Find function by name.
        #[inline]
        pub fn find(&self, name: &str) -> Option<&Func> {
            let Funcs(list) = self;
            list.iter().find(|&f| f.name == name)
        }
    }

    impl Args {
        /// Iterator over arguments in this list.
        /// Returns required args first in alphabetical order, then non-required in alphabetical order.
        #[inline]
        pub fn iter(&self) -> impl Iterator<Item=&Arg> {
            let Args(list) = self;
            list.iter()
        }
    }

    impl From<String> for ArgType {
        #[inline]
        fn from(s: String) -> Self {
            match s.as_str() {
                "Int" => Self::Int,
                "String" => Self::String,
                _ => Self::Other(s),
            }
        }
    }

    impl fmt::Display for Funcs {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            let Funcs(list) = self;
            for func in list {
                writeln!(f, "{}", func)?;
            }
            Ok(())
        }
    }

    impl fmt::Display for Func {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{}({})", self.name, self.args)
        }
    }

    impl fmt::Display for Args {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            let Args(list) = self;
            let args: Vec<String> = list.iter().map(Arg::to_string).collect();
            write!(f, "{}", args.join(", "))
        }
    }

    impl fmt::Display for Arg {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            if self.required {
                write!(f, "required ")?;
            }
            write!(f, "{} {}", self.typ, self.name)
        }
    }

    impl fmt::Display for ArgType {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match self {
                ArgType::Int => write!(f, "Int"),
                ArgType::String => write!(f, "String"),
                ArgType::Other(t) => write!(f, "{}", t),
            }
        }
    }
}

/// Remote function argument list.
pub mod func_args {
    use std::collections::BTreeMap;

    use serde::{Serialize, Serializer};
    use serde::ser::SerializeMap;

    /// Argument name (alias to `String`).
    pub type ArgName = String;

    /// Argument value (either integer or string).
    #[derive(Clone, PartialEq, Eq, Debug)]
    pub enum ArgValue {
        /// Integer argument value.
        Int(i64),
        /// String argument value.
        String(String),
    }

    /// Remote function argument values.
    #[derive(Clone, Default, PartialEq, Eq, Debug)]
    pub struct Args(BTreeMap<ArgName, ArgValue>);

    impl Args {
        /// New empty instance.
        #[inline]
        pub fn new() -> Self {
            Args(BTreeMap::new())
        }

        /// Add argument value to list.
        #[inline]
        pub fn add(&mut self, name: ArgName, value: ArgValue) -> &mut Self {
            let Args(map) = self;
            map.insert(name, value);
            self
        }
    }

    impl Serialize for Args {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let Args(map) = self;
            let mut encoder = serializer.serialize_map(Some(map.len()))?;
            for (k, v) in map {
                match v {
                    ArgValue::Int(int_val) => encoder.serialize_entry(k, int_val)?,
                    ArgValue::String(str_val) => encoder.serialize_entry(k, str_val)?,
                }
            }
            encoder.end()
        }
    }

    #[test]
    fn test_args_ser() -> Result<(), Box<dyn std::error::Error>> {
        let mut args = Args::new();
        args.add("foo".to_string(), ArgValue::String("bar".to_string()));
        args.add("boo".to_string(), ArgValue::Int(42));
        args.add("zoo".to_string(), ArgValue::Int(-42));

        let benc = String::from_utf8(bendy::serde::to_bytes(&args)?)?;
        assert_eq!(benc, "d3:booi42e3:foo3:bar3:zooi-42ee");

        Ok(())
    }
}

/// Remote function return values.
pub mod func_ret {
    use std::collections::BTreeMap;
    use std::fmt;

    use serde::{Deserialize, Deserializer};
    use serde::de::{Error, MapAccess, SeqAccess, Unexpected, Visitor};

    /// Remote function return value. Supports json-like data types.
    #[derive(Clone, PartialEq, Eq)]
    pub enum ReturnValue {
        /// Integer return value.
        Int(i64),
        /// String return value.
        String(String),
        /// List return value.
        List(Vec<ReturnValue>),
        /// Map return value.
        Map(BTreeMap<String, ReturnValue>),
    }

    impl<'de> Deserialize<'de> for ReturnValue {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            deserializer.deserialize_any(ReturnValueVisitor)
        }
    }

    struct ReturnValueVisitor;

    impl<'de> Visitor<'de> for ReturnValueVisitor {
        type Value = ReturnValue;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "an integer, byte string, list or map")
        }

        fn visit_i64<E: Error>(self, v: i64) -> Result<Self::Value, E> {
            Ok(ReturnValue::Int(v))
        }

        fn visit_u64<E: Error>(self, v: u64) -> Result<Self::Value, E> {
            if v > i64::MAX as u64 {
                return Err(Error::invalid_value(Unexpected::Unsigned(v), &"64-bit signed integer"));
            }
            Ok(ReturnValue::Int(v as i64))
        }

        fn visit_bytes<E: Error>(self, v: &[u8]) -> Result<Self::Value, E> {
            let s = String::from_utf8(v.to_owned()).map_err(|_| Error::invalid_value(Unexpected::Bytes(v), &"cannot parse byte array as UTF-8 string"))?;
            Ok(ReturnValue::String(s))
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut res = Vec::with_capacity(seq.size_hint().unwrap_or_default());

            while let Some(item) = seq.next_element()? {
                res.push(item)
            }

            Ok(ReturnValue::List(res))
        }

        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            let mut res = BTreeMap::new();

            while let Some((key, value)) = map.next_entry()? {
                res.insert(key, value);
            }

            Ok(ReturnValue::Map(res))
        }
    }

    impl fmt::Debug for ReturnValue {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                ReturnValue::Int(v) => write!(f, "{}", v),
                ReturnValue::String(s) => write!(f, r#""{}""#, s),
                ReturnValue::List(list) => write!(f, "{:?}", list),
                ReturnValue::Map(map) => write!(f, "{:?}", map),
            }
        }
    }
}