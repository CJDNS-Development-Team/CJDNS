//! Tool to sniff CTRL messages.

use anyhow::{anyhow, Error};
use tokio::{select, signal};

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

    let mut buf = Vec::new();
    buf.push((if route_header.is_incoming { ">" } else { "<" }).to_string());
    buf.push(route_header.switch_header.label.to_string());

    /* -- TODO implement when cjdns-ctrl is done
    pr.push(msg.content.type);
    if (msg.content.type === 'ERROR') {
        const content = (msg.content/*:Cjdnsctrl_ErrMsg_t*/);
        pr.push(content.errType);
        console.log(content.switchHeader);
        if (content.switchHeader) {
            pr.push('label_at_err_node:', content.switchHeader.label);
        }
        if (content.nonce) {
            pr.push('nonce:', content.nonce);
        }
        pr.push(content.additional.toString('hex'));
    } else {
        const content = (msg.content/*:Cjdnsctrl_Ping_t*/);
        if (content.type in ['PING', 'PONG']) {
            pr.push('v' + content.version);
        }
        if (content.type in ['KEYPING', 'KEYPONG']) {
            pr.push(content.key);
        }
    }
    */

    Ok(buf.join(" "))
}