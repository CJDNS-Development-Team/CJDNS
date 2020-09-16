//! Tool to sniff CTRL messages.

use anyhow::{anyhow, Error};
use tokio::{select, signal};

use cjdns_ctrl::{CtrlMessageType, ErrorMessageType};
use cjdns_hdr::ParseError;
use cjdns_sniff::{ContentType, Message, ReceiveError, Sniffer};

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("Error: {}", e);
    }
}

async fn run() -> Result<(), Error> {
    let cjdns = cjdns_admin::connect(None).await?;
    let mut sniffer = Sniffer::sniff_traffic(cjdns, ContentType::Ctrl).await?;

    println!("Started sniffing. Press Ctrl+C to terminate.");
    let receive_error = receive_loop(&mut sniffer).await.err();

    println!("Disconnecting...");
    let disconnect_error = sniffer.disconnect().await.err().map(|e| e.into());

    if let Some(error) = receive_error.or(disconnect_error) {
        return Err(error);
    }

    println!("Done.");
    Ok(())
}

async fn receive_loop(sniffer: &mut Sniffer) -> Result<(), Error> {
    loop {
        select! {
            msg = sniffer.receive() => {
                match msg {
                    Ok(msg) => dump_msg(msg)?,
                    Err(err @ ReceiveError::SocketError(_)) => return Err(err.into()),
                    Err(ReceiveError::ParseError(err, data)) => dump_error(err, data),
                }
            },
            _ = signal::ctrl_c() => break,
        }
    }
    Ok(())
}

fn dump_msg(msg: Message) -> Result<(), Error> {
    let route_header = msg.route_header.as_ref().ok_or_else(|| anyhow!("Bad message: missing route header"))?;
    let content = msg.content.as_ref().ok_or_else(|| anyhow!("Bad message: missing content"))?;

    let mut buf = Vec::new();
    buf.push((if route_header.is_incoming { ">" } else { "<" }).to_string());
    buf.push(route_header.switch_header.label.to_string());
    buf.push(msg_type_str(content.msg_type).to_string());
    match content.msg_type {
        CtrlMessageType::Error => {
            let err_data = content.get_error_data().ok_or_else(|| anyhow!("invalid control error message"))?;
            buf.push(format!("{}", err_type_str(err_data.err_type)));
            buf.push(format!("label_at_err_node: {}", err_data.switch_header.label));
            buf.push(hex::encode(&err_data.additional));
        }
        CtrlMessageType::Ping | CtrlMessageType::Pong | CtrlMessageType::KeyPing | CtrlMessageType::KeyPong => {
            let ping_data = content.get_ping_data().ok_or_else(|| anyhow!("invalid control ping message"))?;
            if content.msg_type == CtrlMessageType::Ping || content.msg_type == CtrlMessageType::Pong {
                buf.push(format!("v{}", ping_data.version));
            }
            if content.msg_type == CtrlMessageType::KeyPing || content.msg_type == CtrlMessageType::KeyPong {
                let key = ping_data.key.as_ref().ok_or_else(|| anyhow!("Bad message: missing key"))?;
                buf.push(format!("{}", key));
            }
        }
        CtrlMessageType::GetSuperNodeQuery | CtrlMessageType::GetSuperNodeResponse => {
            buf.push("<UNSUPPORTED MESSAGE>".to_string());
        }
    }

    let s = buf.join(" ");
    println!("{}", s);
    Ok(())
}

fn msg_type_str(t: CtrlMessageType) -> &'static str {
    match t {
        CtrlMessageType::Error => "ERROR",
        CtrlMessageType::Ping => "PING",
        CtrlMessageType::Pong => "PONG",
        CtrlMessageType::KeyPing => "KEYPING",
        CtrlMessageType::KeyPong => "KEYPONG",
        CtrlMessageType::GetSuperNodeQuery => "GETSNODEQ",
        CtrlMessageType::GetSuperNodeResponse => "GETSNODER",
    }
}

fn err_type_str(t: ErrorMessageType) -> &'static str {
    match t {
        ErrorMessageType::None => "NONE",
        ErrorMessageType::MalformedAddress => "MALFORMED_ADDRESS",
        ErrorMessageType::Flood => "FLOOD",
        ErrorMessageType::LinkLimitExceeded => "LINK_LIMIT_EXCEEDED",
        ErrorMessageType::OversizeMessage => "OVERSIZE_MESSAGE",
        ErrorMessageType::UndersizedMessage => "UNDERSIZE_MESSAGE",
        ErrorMessageType::Authentication => "AUTHENTICATION",
        ErrorMessageType::Invalid => "INVALID",
        ErrorMessageType::Undeliverable => "UNDELIVERABLE",
        ErrorMessageType::LoopRoute => "LOOP_ROUTE",
        ErrorMessageType::ReturnPathInvalid => "RETURN_PATH_INVALID",
        ErrorMessageType::Unrecognized => "<UNRECOGNIZED>",
    }
}

fn dump_error(err: ParseError, data: Vec<u8>) {
    println!("Bad message received:\n{}\n{}", hex::encode(data), anyhow!(err));
}