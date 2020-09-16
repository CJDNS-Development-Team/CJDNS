//! Tool to sniff CJDHT messages.

use std::convert::TryFrom;

use anyhow::{anyhow, Error};
use tokio::{select, signal};

use cjdns_bencode::BValue;
use cjdns_core::keys::CJDNS_IP6;
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
    let mut sniffer = Sniffer::sniff_traffic(cjdns, ContentType::Cjdht).await?;

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

    let mut buf = Vec::new();
    buf.push((if route_header.is_incoming { ">" } else { "<" }).to_string());
    buf.push(format!("v{}", route_header.version));
    buf.push(route_header.switch_header.label.to_string());
    buf.push(route_header.ip6.as_ref().map(|s| s.to_string()).unwrap_or_default());

    if let Some(benc) = msg.content_benc {
        dump_bencode(benc, &mut buf).map_err(|_| anyhow!("unrecognized bencoded content"))?;
    }

    let s = buf.join(" ");
    println!("{}", s);
    Ok(())
}

fn dump_bencode(benc: BValue, buf: &mut Vec<String>) -> Result<(), ()> {
    if let Some(qb) = benc.get_dict_value("q")? {
        let q = qb.as_string()?;
        let is_fn = q == "fn";
        buf.push(q);
        if is_fn {
            if let Some(tar) = benc.get_dict_value("tar")? {
                let tar = tar.as_bytes()?;
                let tar = CJDNS_IP6::try_from(tar).map_err(|_| ())?;
                buf.push(tar.to_string());
            }
        }
    } else {
        buf.push("reply".to_string())
    }
    Ok(())
}

fn dump_error(err: ParseError, data: Vec<u8>) {
    println!("Bad message received:\n{}\n{}", hex::encode(data), anyhow!(err));
}