//! CJDNS supernode implementation.

use anyhow::Result;
use tokio::{task, time, time::Duration};

use crate::config::Config;

pub async fn run(config: Config) -> Result<()> {
    task::spawn(keep_table_clean());
    if config.connect {
        task::spawn(service());
    }
    task::spawn(test_srv());

    todo!("supernode::run()")
}

async fn keep_table_clean() {
    const KEEP_TABLE_CLEAN_CYCLE: Duration = Duration::from_secs(30);
    let mut timer = time::interval(KEEP_TABLE_CLEAN_CYCLE);
    loop {
        timer.tick().await;
        async {
            trace!("keep_table_clean()");
            todo!("keepTableClean()")
        }.await;
    }
}

async fn service() {
    todo!("service()")
}

async fn test_srv() {
    todo!("test_srv()")
}