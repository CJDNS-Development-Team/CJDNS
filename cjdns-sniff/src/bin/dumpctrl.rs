//! Tool to sniff CTRL messages.

use anyhow::Error;
use tokio::{select, signal};

use cjdns_sniff::{ContentType, Event, Sniffer};

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("Error: {}", e);
    }
}

async fn run() -> Result<(), Error> {
    let cjdns = cjdns_admin::connect(None).await?;
    let mut sniffer = Sniffer::sniff_traffic(cjdns, ContentType::CTRL).await?;

    println!("Started sniffing.");
    loop {
        select! {
            msg = sniffer.receive() => dump_msg(msg?),
            _ = signal::ctrl_c() => break,
        }
    }

    println!("Disconnecting...");
    sniffer.disconnect().await?;

    println!("Done.");
    Ok(())
}

fn dump_msg(msg: Event) {
    let Event(route_header, data_header, data) = msg;
    let route_header = hex::encode(route_header);
    let data_header = data_header.map(|bytes| hex::encode(bytes));
    let data = hex::encode(data);

    //TODO this is a temporary implementation, replace with a proper one when cjdns-ctrl is done
    println!("{} // {:?} // {}", route_header, data_header, data);
}