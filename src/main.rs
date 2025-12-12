use anyhow::Result;
use tracing::{info, warn};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().init();

    match dotenv::dotenv() {
        Ok(path) => info!("📄 Loaded .env from {:?}", path),
        Err(e) => warn!("⚠️  Could not load .env file: {}", e),
    }

    info!("🏗️  Starting Watchtower - Whale Wallet Monitor");
    watchtower::run().await
}
