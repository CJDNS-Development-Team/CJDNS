//! Tool to sniff CJDHT messages.

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
    let mut sniffer = Sniffer::sniff_traffic(cjdns, ContentType::Cjdht).await?;

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
    buf.push(format!("v{}", route_header.version));
    buf.push(route_header.switch_header.label.to_string());
    buf.push(route_header.ip6.as_ref().map(|s| s.to_string()).unwrap_or_default());

    /* -- TODO implement when Bencode module is propely refactored
    const qb = msg.contentBenc.q;
    if (!qb) {
        pr.push('reply');
    } else {
        const q = qb.toString('utf8');
        pr.push(q);
        if (q === 'fn') {
            if (!msg.contentBenc) { throw new Error(); }
            pr.push(Cjdnskeys.ip6BytesToString(msg.contentBenc.tar));
        }
    }
    */

    Ok(buf.join(" "))
}