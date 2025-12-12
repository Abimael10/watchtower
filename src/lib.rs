pub mod alert;
pub mod config;
pub mod domain;
pub mod notifier;
pub mod price;
pub mod token_registry;
pub mod utils;
pub mod watcher;

use alert::AlertEngine;
use config::AppConfig;
use notifier::{ConsoleNotifier, NotifierHub, TelegramNotifier};
use price::CoinGeckoPriceProvider;
use token_registry::TokenRegistry;
use watcher::Watchtower;

use anyhow::Result;
use tracing::info;

pub async fn run() -> Result<()> {
    let config = AppConfig::from_env()?;
    let alert_engine = AlertEngine::new(config.transfer_threshold);
    let token_registry = TokenRegistry::default();
    let price_provider = CoinGeckoPriceProvider::new();

    let console = ConsoleNotifier::new();
    let telegram = TelegramNotifier::maybe_from_config(&config);
    if telegram.is_some() {
        info!("📱 Telegram notifications enabled");
    } else {
        info!("📱 Telegram notifications disabled (no credentials)");
    }
    let notifier = NotifierHub::new(console, telegram);

    let app = Watchtower::new(config, alert_engine, token_registry, price_provider, notifier);
    app.run().await
}
