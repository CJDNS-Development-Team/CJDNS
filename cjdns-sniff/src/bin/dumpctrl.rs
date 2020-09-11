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
    loop {
        select! {
            msg = sniffer.receive() => println!("{}", dump_msg(msg?)?), //TODO Problem: exit without proper disconnect. Redesign.
            _ = signal::ctrl_c() => break,
        }
    }

    println!("Disconnecting...");
    sniffer.disconnect().await?;

    println!("Done.");
    Ok(())
}

fn dump_msg(msg: Message) -> Result<String, Error> {
    let route_header = msg.route_header.as_ref().ok_or_else(|| anyhow!("Bad message: missing route header"))?;
    let content = msg.content.as_ref().ok_or_else(|| anyhow!("Bad message: missing content"))?;

    let mut buf = Vec::new();
    buf.push((if route_header.is_incoming { ">" } else { "<" }).to_string());
    buf.push(route_header.switch_header.label.to_string());
    buf.push(msg_type_str(content.msg_type).to_string());
    if content.msg_type == CtrlMessageType::Error {
        let err_type = content.err_type.as_ref().ok_or_else(|| anyhow!("Bad message: missing error type"))?;
        buf.push(format!("{}", err_type));
        if let Some(ref switch_header) = content.switch_header {
            buf.push(format!("label_at_err_node: {}", switch_header.label));
        }
        if let Some(ref nonce) = content.nonce {
            buf.push(format!("nonce: {}", nonce));
        }
        buf.push(hex::encode(&content.additional));
    } else {
        if content.msg_type == CtrlMessageType::Ping || content.msg_type == CtrlMessageType::Pong {
            buf.push(format!("v{}", content.version));
        }
        if content.msg_type == CtrlMessageType::KeyPing || content.msg_type == CtrlMessageType::KeyPong {
            let key = content.key.as_ref().ok_or_else(|| anyhow!("Bad message: missing key"))?;
            buf.push(format!("{}", key));
        }
    }

    Ok(buf.join(" "))
}

pub fn msg_type_str(m: CtrlMessageType) -> &'static str {
    match m {
        CtrlMessageType::Error => "ERROR",
        CtrlMessageType::Ping => "PING",
        CtrlMessageType::Pong => "PONG",
        CtrlMessageType::KeyPing => "KEYPING",
        CtrlMessageType::KeyPong => "KEYPONG",
    }
}