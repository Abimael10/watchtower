use crate::domain::Alert;
use anyhow::Result;
use tracing::info;

#[derive(Debug, Clone, Default)]
pub struct ConsoleNotifier;

impl ConsoleNotifier {
    pub fn new() -> Self {
        Self
    }

    pub async fn send(&self, alert: &Alert) -> Result<()> {
        println!("⚠️  {} - {}", alert.title, alert.message);
        info!("Alert sent to console: {}", alert.title);
        Ok(())
    }
}
