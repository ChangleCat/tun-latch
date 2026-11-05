//! Own the notification monitor until its native worker has been reaped.

use std::io;
use std::time::Duration;

use tokio::task::JoinHandle;
use tunlatch_platform::events::{NetworkEventControl, NetworkEventMonitor, SubscriptionState};

pub(crate) struct Notifications {
    pub(crate) control: NetworkEventControl,
    owner: Option<JoinHandle<()>>,
}

impl Notifications {
    pub(crate) fn start() -> io::Result<Self> {
        let mut monitor = NetworkEventMonitor::start()?;
        let control = monitor.control();
        // A started blocking owner survives cancellation of the async waiter. It retains the
        // monitor and its native JoinHandle until the native worker is actually reaped.
        let owner = tokio::task::spawn_blocking(move || {
            while !monitor.poll().reaped {
                std::thread::sleep(Duration::from_millis(10));
            }
        });
        Ok(Self {
            control,
            owner: Some(owner),
        })
    }

    pub(crate) async fn ready(&self) -> io::Result<()> {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match self.control.status().0 {
                    SubscriptionState::Running => return Ok(()),
                    SubscriptionState::Starting => {
                        tokio::time::sleep(Duration::from_millis(5)).await
                    }
                    _ => return Err(io::Error::other("native network subscription unavailable")),
                }
            }
        })
        .await
        .map_err(|_| io::Error::other("native network subscription startup timed out"))?
    }

    pub(crate) async fn shutdown(&mut self) -> io::Result<()> {
        self.control.request_stop();
        if let Some(owner) = self.owner.as_mut() {
            // Keep the handle if a deadline is exceeded; do not confuse a stop request with
            // reclamation. As with native enumeration, OS scheduling has no hard deadline.
            match tokio::time::timeout(Duration::from_secs(2), &mut *owner).await {
                Ok(result) => result.map_err(io::Error::other)?,
                Err(_) => {
                    tracing::error!(
                        "native notification worker not yet reaped; retaining ownership"
                    );
                    owner.await.map_err(io::Error::other)?;
                }
            }
        }
        self.owner.take();
        Ok(())
    }
}

impl Drop for Notifications {
    fn drop(&mut self) {
        // The blocking owner continues supervising and reaping even if serve is cancelled.
        self.control.request_stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dropping_the_async_owner_requests_stop_and_the_blocking_owner_reaps() -> io::Result<()>
    {
        let mut notifications = Notifications::start()?;
        notifications.ready().await?;
        let control = notifications.control.clone();
        let owner = notifications
            .owner
            .take()
            .ok_or_else(|| io::Error::other("missing owner"))?;
        drop(notifications);
        tokio::time::timeout(Duration::from_secs(2), owner)
            .await
            .map_err(io::Error::other)?
            .map_err(io::Error::other)?;
        assert_eq!(control.status().0, SubscriptionState::Stopped);
        Ok(())
    }
}
