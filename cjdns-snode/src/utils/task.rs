//! Task utilities

use std::time::Duration;

use std::future::Future;
use tokio::time;

pub async fn periodic_task<T: FnMut()>(period: Duration, mut task: T) {
    loop {
        time::delay_for(period).await;
        task();
    }
}

pub async fn periodic_async_task<F: Future<Output = ()>, T: FnMut() -> F>(period: Duration, mut task: T) {
    loop {
        time::delay_for(period).await;
        task().await;
    }
}
