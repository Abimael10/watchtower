use std::collections::HashMap;
use std::env;

use anyhow::{anyhow, Result};

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub ws_rpc_url: String,
    pub watch_addresses: Vec<String>,
    pub wallet_labels: HashMap<String, String>,
    pub transfer_threshold: f64,
    pub telegram_bot_token: Option<String>,
    pub telegram_chat_id: Option<String>,
}

impl AppConfig {
    pub fn from_env() -> Result<Self> {
        let ws_rpc_url = env::var("WS_RPC_URL").map_err(|_| anyhow!("WS_RPC_URL must be set in .env"))?;
        let watch_addresses_raw =
            env::var("WATCH_ADDRESSES").map_err(|_| anyhow!("WATCH_ADDRESSES must be set in .env"))?;

        let watch_addresses: Vec<String> = watch_addresses_raw
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        if watch_addresses.is_empty() {
            return Err(anyhow!("WATCH_ADDRESSES cannot be empty"));
        }

        let wallet_labels_raw = env::var("WALLET_LABELS").unwrap_or_default();
        let wallet_labels = parse_wallet_labels(&wallet_labels_raw);

        let transfer_threshold = env::var("TRANSFER_THRESHOLD")
            .unwrap_or_else(|_| "100000.0".to_string())
            .parse()
            .unwrap_or(100000.0);

        let telegram_bot_token = env::var("TELEGRAM_BOT_TOKEN").ok();
        let telegram_chat_id = env::var("TELEGRAM_CHAT_ID").ok();

        Ok(Self {
            ws_rpc_url,
            watch_addresses,
            wallet_labels,
            transfer_threshold,
            telegram_bot_token,
            telegram_chat_id,
        })
    }
}

pub fn parse_wallet_labels(raw: &str) -> HashMap<String, String> {
    raw.split(',')
        .filter_map(|pair| {
            let parts: Vec<&str> = pair.split('=').collect();
            if parts.len() == 2 {
                let key = parts[0].trim();
                let value = parts[1].trim();
                if !key.is_empty() && !value.is_empty() {
                    return Some((key.to_lowercase(), value.to_string()));
                }
            }
            None
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::parse_wallet_labels;

    #[test]
    fn parses_single_entry() {
        let input = "0xF977814e90dA44bFA03b6295A0616a897441aceC=Binance-Hot-8";
        let labels = parse_wallet_labels(input);
        assert_eq!(labels.len(), 1);
        assert_eq!(
            labels.get("0xf977814e90da44bfa03b6295a0616a897441acec"),
            Some(&"Binance-Hot-8".to_string())
        );
    }

    #[test]
    fn parses_multiple_entries_and_trims() {
        let input =
            " 0xABC123 = Coinbase , 0xDEF456 = Kraken , malformed , 0x = empty,0xGHI= ";
        let labels = parse_wallet_labels(input);
        assert_eq!(labels.len(), 2);
        assert_eq!(labels.get("0xabc123"), Some(&"Coinbase".to_string()));
        assert_eq!(labels.get("0xdef456"), Some(&"Kraken".to_string()));
    }

    #[test]
    fn handles_empty_input() {
        let labels = parse_wallet_labels("");
        assert!(labels.is_empty());
    }
}
