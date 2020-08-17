//! CJDNS Admin lib

use std::path::PathBuf;

pub use self::config::Opts;
pub use self::errors::Error;

#[derive(Clone, Default, PartialEq, Eq, Debug)]
struct ConnectionOptions {
    addr: String,
    port: u16,
    password: String,
    used_config_file: Option<PathBuf>,
}

mod errors {
    use std;
    use std::fmt;

    #[derive(Debug)]
    pub enum Error {
        FileError(std::io::Error),
        JsonError(serde_json::Error),
    }

    impl fmt::Display for Error {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match self {
                Error::FileError(e) => write!(f, "File error: {}", e),
                Error::JsonError(e) => write!(f, "JSON parse error: {}", e),
            }
        }
    }

    impl std::error::Error for Error {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                Error::FileError(e) => Some(e),
                Error::JsonError(e) => Some(e),
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

    #[derive(Clone, Default, PartialEq, Eq, Debug, Deserialize)]
    pub struct Opts {
        #[serde(rename = "addr")]
        pub addr: Option<String>,

        #[serde(rename = "port")]
        pub port: Option<u16>,

        #[serde(rename = "password")]
        pub password: Option<String>,

        #[serde(rename = "cjdnsadminPath")]
        pub config_file_path: Option<String>,

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
                used_config_file: conf_file,
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
            serde_json::from_slice(json).map_err(|e| Error::JsonError(e))
        }

        fn read_config_file(file_path: &Path) -> Result<Self, Error> {
            let json = fs::read(file_path).map_err(|e| Error::FileError(e))?;
            Self::parse_config(&json)
        }

        fn read_optional_config_file(file_path: &Path) -> Result<Option<Self>, Error> {
            match Self::read_config_file(file_path) {
                Ok(conf) => Ok(Some(conf)),
                Err(Error::FileError(err)) if err.kind() == io::ErrorKind::NotFound => Ok(None),
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
                used_config_file: None
            }
        );

        assert_eq!(
            Opts { anon: true, ..Opts::default() }.build_connection_options(None),
            ConnectionOptions {
                addr: s("127.0.0.1"),
                port: 11234,
                password: s(""),
                used_config_file: None
            }
        );

        assert_eq!(
            Opts { addr: ss("192.168.1.1"), ..Opts::default() }.build_connection_options(None),
            ConnectionOptions {
                addr: s("192.168.1.1"),
                port: 11234,
                password: s("NONE"),
                used_config_file: None
            }
        );

        assert_eq!(
            Opts { port: Some(1234), ..Opts::default() }.build_connection_options(None),
            ConnectionOptions {
                addr: s("127.0.0.1"),
                port: 1234,
                password: s("NONE"),
                used_config_file: None
            }
        );

        assert_eq!(
            Opts { password: ss("secret"), ..Opts::default() }.build_connection_options(None),
            ConnectionOptions {
                addr: s("127.0.0.1"),
                port: 11234,
                password: s("secret"),
                used_config_file: None
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
pub fn connect(opts: Option<Opts>) -> Result<(), Error> {
    let opts = opts.unwrap_or_default().into_connection_options()?;
    conn::connect(opts)
}

mod conn {
    use crate::ConnectionOptions;
    use crate::errors::Error;

    pub(super) fn connect(_opts: ConnectionOptions) -> Result<(), Error> {
        unimplemented!() //TODO addr, port, pass, usingCjdnsadmin
    }
}