//! UDP connection to the CJDNS Router.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use log::{debug, info};
use sodiumoxide::crypto::hash::sha256::hash;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::UdpSocket;
use tokio::net::UnixStream;
use tokio::sync::Mutex;
use tokio::time;

use crate::errors::{ConnOptions, Error};
use crate::func_list::Funcs;
use crate::msgs::{self, Empty, Request};
use crate::txid::Counter;
use crate::ConnectionOptions;

const PING_TIMEOUT: Duration = Duration::from_millis(1_000);
const DEFAULT_TIMEOUT: Duration = Duration::from_millis(10_000);

enum CjdnsSocket {
    Udp(UdpSocket),
    Unix(UnixStream),
}

/// Admin connection to the CJDNS node.
///
/// Cloneable: cloned connection uses same underlying UDP socket and is thread-safe.
#[derive(Clone)]
pub struct Connection {
    socket: Arc<Mutex<CjdnsSocket>>,
    password: String,
    counter: Arc<Counter>,

    /// List of available remote functions.
    pub functions: Funcs,
}

impl Connection {
    pub(super) async fn new(opts: ConnectionOptions) -> Result<Self, Error> {
        let (passwd, socket) = match &opts {
            ConnectionOptions::Udp(uco) => {
                info!("Using UDP connection [{}:{}]", uco.addr, uco.port);
                (uco.password.clone(), CjdnsSocket::Udp(create_udp_socket_sender(&uco.addr, uco.port).await?))
            }
            ConnectionOptions::Socket(path) => {
                info!("Using UNIX Socket connection [{}]", path);
                ("".to_owned(), CjdnsSocket::Unix(create_unix_socket_sender(&path).await?))
            }
        };
        let mut conn = Connection {
            socket: Arc::new(Mutex::new(socket)),
            password: passwd,
            counter: Arc::new(Counter::new_random()),
            functions: Funcs::default(),
        };

        conn.probe_connection(opts).await?;
        let fns = conn.load_available_functions().await?;
        conn.functions = fns;

        Ok(conn)
    }

    async fn probe_connection(&mut self, opts: ConnectionOptions) -> Result<(), Error> {
        self.call_func::<(), Empty>("ping", (), true, PING_TIMEOUT)
            .await
            .map_err(|_| Error::ConnectError(ConnOptions::wrap(&opts)))?;

        if !self.password.is_empty() {
            self.call_func::<(), Empty>("AuthorizedPasswords_list", (), false, DEFAULT_TIMEOUT)
                .await
                .map_err(|_| Error::AuthError(ConnOptions::wrap(&opts)))?;
        }

        Ok(())
    }

    async fn load_available_functions(&mut self) -> Result<Funcs, Error> {
        let mut res = Funcs::new();

        for i in 0.. {
            let ret: msgs::AvailableFnsResponsePayload = self
                .call_func("Admin_availableFunctions", msgs::AvailableFnsQueryArg { page: i }, false, DEFAULT_TIMEOUT)
                .await?;
            let funcs = ret.available_fns;

            if funcs.is_empty() {
                break; // Empty answer - no more pages
            }

            res.add_funcs(funcs);
        }

        Ok(res)
    }

    /// Call remote function on CJDNS router.
    ///
    /// Example:
    /// ```no_run
    /// # use cjdns_admin::cjdns_invoke;
    /// # use cjdns_admin::{ArgValues, msgs::GenericResponsePayload};
    /// # async fn test() -> Result<(), Box<dyn std::error::Error>> {
    /// # let mut conn = cjdns_admin::connect(None).await?;
    /// let res: GenericResponsePayload = conn.invoke("MyFunc", ArgValues::new().add("arg1", 42).add("arg2", "foobar")).await?;
    /// # Ok(())}
    /// ```
    /// or use macro `cjdns_invoke` to make it even more concise:
    /// ```no_run
    /// # use cjdns_admin::cjdns_invoke;
    /// # async fn test() -> Result<(), Box<dyn std::error::Error>> {
    /// # let mut conn = cjdns_admin::connect(None).await?;
    /// let res = cjdns_invoke!(conn, "FuncName", "arg1" = 42, "arg2" = "foobar").await?;
    /// # Ok(())}
    /// ```
    pub async fn invoke<A: msgs::Args, P: msgs::Payload>(&mut self, remote_fn_name: &str, args: A) -> Result<P, Error> {
        self.call_func(remote_fn_name, args, false, DEFAULT_TIMEOUT).await
    }

    async fn call_func<A: msgs::Args, P: msgs::Payload>(&mut self, remote_fn_name: &str, args: A, disable_auth: bool, timeout: Duration) -> Result<P, Error> {
        let call = async {
            if disable_auth || self.password.is_empty() {
                self.call_func_no_auth(remote_fn_name, args).await
            } else {
                self.call_func_auth(remote_fn_name, args).await
            }
        };
        time::timeout(timeout, call).await.map_err(|_| Error::TimeOut(timeout))?
    }

    async fn call_func_no_auth<A: msgs::Args, P: msgs::Payload>(&mut self, remote_fn_name: &str, args: A) -> Result<P, Error> {
        let msg = msgs::Query {
            txid: self.counter.next().to_string(),
            q: remote_fn_name.to_string(),
            args,
        };

        let resp: msgs::GenericResponse<P> = self.send_msg(&msg).await?;
        check_txid(&msg.txid, &resp.txid)?;
        check_remote_error(&resp.error)?;

        Ok(resp.payload)
    }

    async fn call_func_auth<A: msgs::Args, P: msgs::Payload>(&mut self, remote_fn_name: &str, args: A) -> Result<P, Error> {
        // Ask cjdns for a cookie first
        let new_cookie = {
            let resp: msgs::CookieResponsePayload = self.call_func_no_auth("cookie", ()).await?;
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
        let resp: msgs::GenericResponse<P> = self.send_msg(&msg).await?;
        check_txid(&msg.txid, &resp.txid)?;
        check_remote_error(&resp.error)?;

        Ok(resp.payload)
    }

    async fn send_msg<RQ, RS>(&mut self, req: &RQ) -> Result<RS, Error>
    where
        RQ: msgs::Request,
        RS: msgs::Response,
    {
        // Send encoded request
        let msg = req.to_bencode()?;
        //dbg!(String::from_utf8_lossy(&msg));
        let mut socket = self.socket.lock().await;
        debug!("< [{}] {}", msg.len(), String::from_utf8_lossy(&msg));
        match &mut *socket {
            CjdnsSocket::Udp(u) => {
                u.send(&msg).await.map_err(|e| Error::NetworkOperation(e))?;
            }
            CjdnsSocket::Unix(s) => {
                s.write_all(&msg).await.map_err(|e| Error::NetworkOperation(e))?;
            }
        }

        // Use 2**14 (16384) which is the mtu of loopback
        let mut buf = [0; 1 << 14];

        // Receive encoded response synchronously
        // NOTE: reading the unix socket here will fail if we only get a partial read
        let received = match &mut *socket {
            CjdnsSocket::Udp(u) => u.recv(&mut buf).await.map_err(|e| Error::NetworkOperation(e))?,
            CjdnsSocket::Unix(s) => s.read(&mut buf).await.map_err(|e| Error::NetworkOperation(e))?,
        };
        let response = &buf[..received];
        debug!("> [{}] {}", response.len(), String::from_utf8_lossy(&response));
        //dbg!(String::from_utf8_lossy(&response));

        // Decode response
        RS::from_bencode(response)
    }
}

async fn create_unix_socket_sender(path: &str) -> Result<UnixStream, Error> {
    Ok(UnixStream::connect(path).await.map_err(|e| Error::NetworkOperation(e))?)
}

async fn create_udp_socket_sender(addr: &str, port: u16) -> Result<UdpSocket, Error> {
    let ip_addr = addr.parse::<IpAddr>().map_err(|e| Error::BadNetworkAddress(e))?;
    let remote_address = SocketAddr::new(ip_addr, port);

    let local_address = "0.0.0.0:0";
    let socket = UdpSocket::bind(local_address).await.map_err(|e| Error::NetworkOperation(e))?;
    socket.connect(&remote_address).await.map_err(|e| Error::NetworkOperation(e))?;

    Ok(socket)
}

#[inline]
fn check_txid(sent_txid: &String, received_txid: &String) -> Result<(), Error> {
    if sent_txid == received_txid {
        Ok(())
    } else {
        Err(Error::BrokenTx {
            sent_txid: sent_txid.clone(),
            received_txid: received_txid.clone(),
        })
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
