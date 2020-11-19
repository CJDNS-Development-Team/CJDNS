//! Configuration options.

use std::path::{Path, PathBuf};

use log::debug;
use serde::Deserialize;
use tokio::{fs, io};

use crate::errors::Error;
use crate::{ConnectionOptions, UdpConnectionOptions};

const DEFAULT_PATH: &'static str = "/tmp/cjdroute.sock";
const DEFAULT_ADDR: &'static str = "127.0.0.1";
const DEFAULT_PORT: u16 = 11234;
const DEFAULT_PASSWORD: &'static str = "NONE";
const DEFAULT_CONFIG_FILE_NAME: &'static str = ".cjdnsadmin";

/// Connection options. Can be loaded from a config file.
#[derive(Clone, Default, PartialEq, Eq, Debug, Deserialize)]
pub struct Opts {
    /// Path to unix domain socket
    pub path: Option<String>,

    /// If true then we will use the UDP socket rather than the unix domain socket
    #[serde(rename = "useUdp")]
    pub use_udp: Option<bool>,

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

async fn unix_sock_exists(p: &str) -> bool {
    match tokio::net::UnixStream::connect(p).await {
        Ok(_) => true,
        // Maybe we should log something here ?
        Err(e) => {
            debug!("Unable to connect to [{}] because [{}]", p, e);
            false
        }
    }
}

impl Opts {
    pub(super) async fn into_connection_options(self) -> Result<ConnectionOptions, Error> {
        let use_udp = if let Some(u) = self.use_udp { u } else { false };

        if !use_udp {
            if let Some(p) = self.path {
                return Ok(ConnectionOptions::Socket(p));
            }
        }

        // Do we need to try to read config file?
        let is_configured = (self.addr.is_some() || self.port.is_some() || self.password.is_some()) && self.config_file_path.is_none();

        // Options to use
        let mut opts = self;
        let mut conf_file = None;

        // Try to read config file
        if !is_configured {
            if !use_udp && unix_sock_exists(DEFAULT_PATH).await {
                // We didn't ask to use the UDP socket so we should try to use the unix socket path
                return Ok(ConnectionOptions::Socket(DEFAULT_PATH.to_owned()));
            }
            if let Some(config_file) = opts.get_config_file_location() {
                if let Some(config) = Self::read_optional_config_file(&config_file).await? {
                    opts = config;
                    conf_file = Some(config_file);
                }
            }
        }

        // Build resulting options
        Ok(Self::build_connection_options(opts, conf_file))
    }

    fn build_connection_options(self, conf_file: Option<PathBuf>) -> ConnectionOptions {
        ConnectionOptions::Udp(UdpConnectionOptions {
            addr: self.addr.as_ref().map_or(DEFAULT_ADDR, |s| &s).to_string(),
            port: self.port.unwrap_or(DEFAULT_PORT),
            password: self
                .password
                .as_ref()
                .map_or_else(|| if self.anon { "" } else { DEFAULT_PASSWORD }, |s| &s)
                .to_string(),
            used_config_file: conf_file.map(|path| path.to_string_lossy().into_owned()),
        })
    }

    fn get_config_file_location(&self) -> Option<PathBuf> {
        if let Some(ref cfg_file) = self.config_file_path {
            return Some(PathBuf::from(cfg_file));
        }

        if let Some(mut path) = dirs::home_dir() {
            path.push(DEFAULT_CONFIG_FILE_NAME);
            return Some(path.into());
        }

        None // Unable to locate HOME dir - unsupported platform?
    }

    fn parse_config(json: &[u8]) -> Result<Self, Error> {
        serde_json::from_slice(json).map_err(|e| Error::BadConfigFile(e))
    }

    async fn read_config_file(file_path: &Path) -> Result<Self, Error> {
        let json = fs::read(file_path).await.map_err(|e| Error::ConfigFileRead(e))?;
        Self::parse_config(&json)
    }

    async fn read_optional_config_file(file_path: &Path) -> Result<Option<Self>, Error> {
        match Self::read_config_file(file_path).await {
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
        ConnectionOptions::Udp(UdpConnectionOptions {
            addr: s("127.0.0.1"),
            port: 11234,
            password: s("NONE"),
            used_config_file: None,
        })
    );

    assert_eq!(
        Opts { anon: true, ..Opts::default() }.build_connection_options(None),
        ConnectionOptions::Udp(UdpConnectionOptions {
            addr: s("127.0.0.1"),
            port: 11234,
            password: s(""),
            used_config_file: None,
        })
    );

    assert_eq!(
        Opts {
            addr: ss("192.168.1.1"),
            ..Opts::default()
        }
        .build_connection_options(None),
        ConnectionOptions::Udp(UdpConnectionOptions {
            addr: s("192.168.1.1"),
            port: 11234,
            password: s("NONE"),
            used_config_file: None,
        })
    );

    assert_eq!(
        Opts {
            port: Some(1234),
            ..Opts::default()
        }
        .build_connection_options(None),
        ConnectionOptions::Udp(UdpConnectionOptions {
            addr: s("127.0.0.1"),
            port: 1234,
            password: s("NONE"),
            used_config_file: None,
        })
    );

    assert_eq!(
        Opts {
            password: ss("secret"),
            ..Opts::default()
        }
        .build_connection_options(None),
        ConnectionOptions::Udp(UdpConnectionOptions {
            addr: s("127.0.0.1"),
            port: 11234,
            password: s("secret"),
            used_config_file: None,
        })
    );
}

#[test]
fn test_parse_config() {
    let s = |s: &str| -> Option<String> { Some(s.to_string()) };
    let c = |json: &str| -> Opts { Opts::parse_config(json.as_bytes()).expect("bad test config") };

    assert_eq!(c(r#"{}"#), Opts::default());

    assert_eq!(c(r#"{ "unknown": "foo" }"#), Opts::default());

    assert_eq!(
        c(r#"{ "addr": "192.168.1.1" }"#),
        Opts {
            addr: s("192.168.1.1"),
            ..Opts::default()
        }
    );
    assert_eq!(
        c(r#"{ "port": 1234 }"#),
        Opts {
            port: Some(1234),
            ..Opts::default()
        }
    );
    assert_eq!(
        c(r#"{ "password": "secret" }"#),
        Opts {
            password: s("secret"),
            ..Opts::default()
        }
    );

    assert_eq!(
        c(r#"{ "addr": "192.168.1.1", "port": 1234, "password": "secret" }"#),
        Opts {
            addr: s("192.168.1.1"),
            port: Some(1234),
            password: s("secret"),
            ..Opts::default()
        }
    );
}
