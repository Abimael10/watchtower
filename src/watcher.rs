use crate::alert::AlertEngine;
use crate::config::AppConfig;
use crate::domain::Transfer;
use crate::notifier::NotifierHub;
use crate::price::CoinGeckoPriceProvider;
use crate::token_registry::TokenRegistry;
use crate::utils::mask_url;
use anyhow::Result;
use chrono::Utc;
use ethers_core::types::{Address, Filter, H256, U256};
use ethers_providers::{Middleware, Provider, StreamExt, Ws};
use tracing::{info, warn};

pub struct Watchtower {
    config: AppConfig,
    alert_engine: AlertEngine,
    token_registry: TokenRegistry,
    price_provider: CoinGeckoPriceProvider,
    notifier: NotifierHub,
}

impl Watchtower {
    pub fn new(
        config: AppConfig,
        alert_engine: AlertEngine,
        token_registry: TokenRegistry,
        price_provider: CoinGeckoPriceProvider,
        notifier: NotifierHub,
    ) -> Self {
        Self {
            config,
            alert_engine,
            token_registry,
            price_provider,
            notifier,
        }
    }

    pub async fn run(&self) -> Result<()> {
        info!("📋 Loaded {} wallet labels", self.config.wallet_labels.len());
        if self.config.wallet_labels.is_empty() {
            warn!("⚠️  WALLET_LABELS not found - addresses will show as 'Unknown'");
        }

        info!("🔌 Connecting to blockchain: {}", mask_url(&self.config.ws_rpc_url));
        let provider = Provider::<Ws>::connect(&self.config.ws_rpc_url).await?;

        info!("👁️  Watching {} whale wallets:", self.config.watch_addresses.len());
        for addr in &self.config.watch_addresses {
            let addr_key = addr.to_lowercase();
            let label = self
                .config
                .wallet_labels
                .get(&addr_key)
                .map(|l| l.as_str())
                .unwrap_or("Unknown");
            info!("   - {} ({})", addr, label);
        }

        // ERC-20 Transfer event signature: keccak256("Transfer(address,address,uint256)")
        let transfer_sig: H256 =
            "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef".parse()?;

        let address_topics: Vec<H256> = self
            .config
            .watch_addresses
            .iter()
            .filter_map(|addr| address_to_topic(addr))
            .collect();

        // Subscribe to Transfer events FROM monitored addresses
        let filter = Filter::new().topic0(transfer_sig).topic1(address_topics);
        let mut stream = provider.subscribe_logs(&filter).await?;

        info!("✅ Connected! Listening for whale token transfers (known tokens only)...");

        while let Some(log) = stream.next().await {
            let token_address = format!("{:#x}", log.address);
            let from_addr = format!(
                "{:#x}",
                Address::from_slice(&log.topics[1].as_bytes()[12..])
            );
            let to_addr = format!(
                "{:#x}",
                Address::from_slice(&log.topics[2].as_bytes()[12..])
            );

            if let Some(token) = self.token_registry.get_token_info(&token_address) {
                if log.data.len() >= 32 {
                    let amount_raw = U256::from_big_endian(&log.data);
                    let divisor = 10_u64.pow(token.decimals as u32) as f64;
                    let token_amount = amount_raw.as_u128() as f64 / divisor;

                    if let Some(price_usd) = self.price_provider.price_usd(&token_address).await {
                        let usd = token_amount * price_usd;

                        let from_label = self
                            .config
                            .wallet_labels
                            .get(&from_addr.to_lowercase())
                            .map(|l| l.as_str())
                            .unwrap_or("Unknown");
                        let to_label = self
                            .config
                            .wallet_labels
                            .get(&to_addr.to_lowercase())
                            .map(|l| l.as_str())
                            .unwrap_or("Unknown");

                        info!(
                            "💰 {:.2} {} @ ${:.2} = ${:.2} from {} to {}",
                            token_amount, token.symbol, price_usd, usd, from_label, to_label
                        );

                        let transfer = Transfer {
                            from: format!("{from_addr} [{from_label}]"),
                            to: format!("{to_addr} [{to_label}]"),
                            amount: usd,
                            token: token.symbol.to_string(),
                            block_number: log.block_number.map(|n| n.as_u64()).unwrap_or(0),
                            timestamp: Utc::now(),
                        };

                        if let Some(alert) = self.alert_engine.should_alert(&transfer) {
                            self.notifier.send(&alert).await?;
                        }
                    } else {
                        warn!(
                            "⚠️  Skipping {} transfer - could not fetch real-time price",
                            token.symbol
                        );
                    }
                }
            }
            // Unknown tokens are silently skipped
        }

        Ok(())
    }
}

fn address_to_topic(addr: &str) -> Option<H256> {
    addr.parse::<Address>().ok().map(|address| {
        let mut padded = [0u8; 32];
        padded[12..32].copy_from_slice(address.as_bytes());
        H256::from(padded)
    })
}

#[cfg(test)]
mod tests {
    use super::address_to_topic;
    use ethers_core::types::Address;

    #[test]
    fn converts_address_to_topic() {
        let addr_str = "0xF977814e90dA44bFA03b6295A0616a897441aceC";
        let topic = address_to_topic(addr_str).expect("should convert");
        let mut padded = [0u8; 32];
        padded[12..32].copy_from_slice(addr_str.parse::<Address>().unwrap().as_bytes());
        assert_eq!(topic, padded.into());
    }
}
