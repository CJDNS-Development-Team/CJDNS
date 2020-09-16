//! Tool to sniff CTRL messages.

use anyhow::{anyhow, Error};
use tokio::{select, signal};

use cjdns_ctrl::CtrlMessageType;
use cjdns_sniff::{ContentType, Message, Sniffer};

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("Error: {}", e);
    }
}

async fn run() -> Result<(), Error> {
    let cjdns = cjdns_admin::connect(None).await?;
    let mut sniffer = Sniffer::sniff_traffic(cjdns, ContentType::Ctrl).await?;

    println!("Started sniffing.");
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
            msg = sniffer.receive() => dump_msg(msg?)?,
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
    if content.msg_type == CtrlMessageType::Error {
        let err_data = content.get_error_data().ok_or_else(|| anyhow!("invalid control error message"))?;
        buf.push(format!("{}", err_data.err_type));
        buf.push(format!("label_at_err_node: {}", err_data.switch_header.label));
        buf.push(hex::encode(&err_data.additional));
    } else {
        let ping_data = content.get_ping_data().ok_or_else(|| anyhow!("invalid control ping message"))?;
        if content.msg_type == CtrlMessageType::Ping || content.msg_type == CtrlMessageType::Pong {
            buf.push(format!("v{}", ping_data.version));
        }
        if content.msg_type == CtrlMessageType::KeyPing || content.msg_type == CtrlMessageType::KeyPong {
            let key = ping_data.key.as_ref().ok_or_else(|| anyhow!("Bad message: missing key"))?;
            buf.push(format!("{}", key));
        }
    }

    let s = buf.join(" ");
    println!("{}", s);
    Ok(())
}

pub fn msg_type_str(m: CtrlMessageType) -> &'static str {
    match m {
        CtrlMessageType::Error => "ERROR",
        CtrlMessageType::Ping => "PING",
        CtrlMessageType::Pong => "PONG",
        CtrlMessageType::KeyPing => "KEYPING",
        CtrlMessageType::KeyPong => "KEYPONG",
        CtrlMessageType::GetsNodeQ => "GETSNODEQ",
        CtrlMessageType::GetsNodeR => "GETSNODER",
    }
}