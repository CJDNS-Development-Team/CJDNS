//! Peer supernode pinging

use std::time::Duration;

use crate::msg;
use crate::peer::Peers;
use crate::utils::task::periodic_async_task;

// Implementation of periodic ping sending
impl Peers {
    const DROP_AFTER: Duration = Duration::from_secs(60);
    const PING_AFTER: Duration = Duration::from_secs(20);
    const PING_CYCLE: Duration = Duration::from_secs(5);

    pub async fn ping_task(&self) {
        periodic_async_task(Self::PING_CYCLE, || self.do_pings()).await;
    }

    async fn do_pings(&self) {
        let (ping_list, drop_list) = self.peers.get_timed_out_peers(Self::DROP_AFTER, Self::PING_AFTER);

        // Ping stale peers
        for mut peer in ping_list {
            let seq = self.msg_id_seq.next();
            let res = peer.send_msg(msg![seq, "PING"]).await;
            if res.is_err() { continue; } // Skip already closed connections
            info!("<PING {}", seq);
        }

        // Drop timed out peers
        for peer in drop_list {
            self.drop_peer(peer);
        }
    }
}

#[test]
fn test_timeouts() {
    assert!(Peers::DROP_AFTER > Peers::PING_AFTER, "ping timeout must be less than drop timeout");
    assert!(Peers::PING_CYCLE < Peers::PING_AFTER, "ping period must be less than ping timeout");
    assert!(Peers::PING_CYCLE < Peers::DROP_AFTER, "ping period must be less than drop timeout");
}
