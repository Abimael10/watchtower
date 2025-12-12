mod console;
mod telegram;

pub use console::ConsoleNotifier;
pub use telegram::TelegramNotifier;

use crate::domain::Alert;
use anyhow::Result;
use tracing::warn;

pub struct NotifierHub {
    console: ConsoleNotifier,
    telegram: Option<TelegramNotifier>,
}

impl NotifierHub {
    pub fn new(console: ConsoleNotifier, telegram: Option<TelegramNotifier>) -> Self {
        Self { console, telegram }
    }

    pub async fn send(&self, alert: &Alert) -> Result<()> {
        self.console.send(alert).await?;

        if let Some(telegram) = &self.telegram {
            if let Err(e) = telegram.send(alert).await {
                warn!("Telegram notification failed: {}", e);
            }
        }

        Ok(())
    }
}
