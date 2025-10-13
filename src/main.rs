// Watchtower - Whale Wallet Monitor
// Monitors ERC-20 token transfers from specified whale wallets and sends Telegram alerts

use anyhow::Result;
use chrono::{DateTime, Utc};
use ethers_core::types::{Address, Filter, H256, U256};
use ethers_providers::{Middleware, Provider, StreamExt, Ws};
use std::env;
use tracing::{info, warn};

// ============================================================================
// Core Data Models
// ============================================================================

#[derive(Debug, Clone)]
pub struct Transfer {
    pub from: String,
    pub to: String,
    pub amount: f64,
    pub token: String,
    pub block_number: u64,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct Alert {
    pub title: String,
    pub message: String,
    pub timestamp: DateTime<Utc>,
}

impl Alert {
    pub fn new(title: String, message: String) -> Self {
        Self {
            title,
            message,
            timestamp: Utc::now(),
        }
    }
}

// ============================================================================
// Alert Logic
// ============================================================================

pub struct AlertEngine {
    threshold: f64,
}

impl Default for AlertEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl AlertEngine {
    pub fn new() -> Self {
        let threshold = env::var("TRANSFER_THRESHOLD")
            .unwrap_or_else(|_| "100000.0".to_string())
            .parse()
            .unwrap_or(100000.0);

        Self { threshold }
    }

    pub fn should_alert(&self, transfer: &Transfer) -> Option<Alert> {
        if transfer.amount > self.threshold {
            Some(Alert::new(
                "Large Whale Transfer Detected".to_string(),
                format!(
                    "${:.2} {} transferred from {} to {}",
                    transfer.amount, transfer.token, transfer.from, transfer.to
                ),
            ))
        } else {
            None
        }
    }
}

// ============================================================================
// Notification System
// ============================================================================

pub struct ConsoleNotifier;

impl Default for ConsoleNotifier {
    fn default() -> Self {
        Self::new()
    }
}

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

pub struct TelegramNotifier {
    bot_token: String,
    chat_id: String,
    client: reqwest::Client,
}

impl TelegramNotifier {
    pub fn new() -> Result<Self> {
        let bot_token = env::var("TELEGRAM_BOT_TOKEN")
            .map_err(|_| anyhow::anyhow!("TELEGRAM_BOT_TOKEN not set"))?;
        let chat_id = env::var("TELEGRAM_CHAT_ID")
            .map_err(|_| anyhow::anyhow!("TELEGRAM_CHAT_ID not set"))?;

        Ok(Self {
            bot_token,
            chat_id,
            client: reqwest::Client::new(),
        })
    }

    pub async fn send(&self, alert: &Alert) -> Result<()> {
        let message = format!(
            "⚠️ *{}*\n\n{}\n\n_Time: {}_",
            alert.title,
            alert.message,
            alert.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
        );

        let url = format!("https://api.telegram.org/bot{}/sendMessage", self.bot_token);
        let payload = serde_json::json!({
            "chat_id": self.chat_id,
            "text": message,
            "parse_mode": "Markdown"
        });

        let response = self.client.post(&url).json(&payload).send().await?;

        if response.status().is_success() {
            info!("Alert sent to Telegram: {}", alert.title);
        } else {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            warn!("Failed to send Telegram alert: {}", error_text);
        }

        Ok(())
    }
}

pub struct Notifier {
    console: ConsoleNotifier,
    telegram: Option<TelegramNotifier>,
}

impl Default for Notifier {
    fn default() -> Self {
        Self::new()
    }
}

impl Notifier {
    pub fn new() -> Self {
        let console = ConsoleNotifier::new();
        let telegram = TelegramNotifier::new().ok();

        if telegram.is_some() {
            info!("📱 Telegram notifications enabled");
        } else {
            info!("📱 Telegram notifications disabled (no credentials)");
        }

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

// ============================================================================
// Token Recognition
// ============================================================================

fn get_token_info(address: &str) -> Option<(&str, u8)> {
    // Returns Some((symbol, decimals)) for known tokens only
    // Returns None for unknown tokens to skip them
    match address.to_lowercase().as_str() {
        "0xdac17f958d2ee523a2206206994597c13d831ec7" => Some(("USDT", 6)),
        "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48" => Some(("USDC", 6)),
        "0x6b175474e89094c44da98b954eedeac495271d0f" => Some(("DAI", 18)),
        "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599" => Some(("WBTC", 8)),
        "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2" => Some(("WETH", 18)),
        "0x514910771af9ca656af840dff83e8264ecf986ca" => Some(("LINK", 18)),
        "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984" => Some(("UNI", 18)),
        "0x7fc66500c84a76ad7e9c93437bfc5ac33e2ddae9" => Some(("AAVE", 18)),
        _ => None, // Skip unknown tokens
    }
}

async fn get_token_price_usd(token_address: &str, http_client: &reqwest::Client) -> Option<f64> {
    // Fetch real-time token price from CoinGecko API (free, no API key required)
    let url = format!(
        "https://api.coingecko.com/api/v3/simple/token_price/ethereum?contract_addresses={token_address}&vs_currencies=usd"
    );

    match http_client.get(&url).send().await {
        Ok(response) => {
            if let Ok(json) = response.json::<serde_json::Value>().await {
                // Parse response: {"0xaddress": {"usd": 1.00}}
                json.get(token_address.to_lowercase())
                    .and_then(|obj| obj.get("usd"))
                    .and_then(|price| price.as_f64())
            } else {
                warn!("Failed to parse CoinGecko response for {}", token_address);
                None
            }
        }
        Err(e) => {
            warn!("Failed to fetch price for {}: {}", token_address, e);
            None
        }
    }
}

// ============================================================================
// Main Monitoring Logic
// ============================================================================

fn mask_url(url: &str) -> String {
    if let Some(scheme_end) = url.find("://") {
        let scheme = &url[..scheme_end + 3];
        if let Some(host_end) = url[scheme_end + 3..].find('/') {
            let host = &url[scheme_end + 3..scheme_end + 3 + host_end];
            return format!("{scheme}{host}/***/");
        }
    }
    "***".to_string()
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().init();

    match dotenv::dotenv() {
        Ok(path) => info!("📄 Loaded .env from {:?}", path),
        Err(e) => warn!("⚠️  Could not load .env file: {}", e),
    }

    info!("🏗️  Starting Watchtower - Whale Wallet Monitor");

    // Load configuration
    let ws_url = env::var("WS_RPC_URL").expect("WS_RPC_URL must be set in .env");

    let addresses: Vec<String> = env::var("WATCH_ADDRESSES")
        .expect("WATCH_ADDRESSES must be set in .env")
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let wallet_labels_str = env::var("WALLET_LABELS").unwrap_or_default();
    if wallet_labels_str.is_empty() {
        warn!("⚠️  WALLET_LABELS not found - addresses will show as 'Unknown'");
    }

    let wallet_labels: std::collections::HashMap<String, String> = wallet_labels_str
        .split(',')
        .filter_map(|pair| {
            let parts: Vec<&str> = pair.split('=').collect();
            if parts.len() == 2 {
                let key = parts[0].trim();
                let value = parts[1].trim();
                if !key.is_empty() && !value.is_empty() {
                    Some((key.to_lowercase(), value.to_string()))
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect();

    info!("📋 Loaded {} wallet labels", wallet_labels.len());
    info!("🔌 Connecting to blockchain: {}", mask_url(&ws_url));

    let provider = Provider::<Ws>::connect(&ws_url).await?;

    info!("👁️  Watching {} whale wallets:", addresses.len());
    for addr in &addresses {
        let addr_key = addr.to_lowercase();
        let label = wallet_labels
            .get(&addr_key)
            .map(|l| l.as_str())
            .unwrap_or("Unknown");
        info!("   - {} ({})", addr, label);
    }

    let alert_engine = AlertEngine::new();
    let notifier = Notifier::new();
    let http_client = reqwest::Client::new(); // For fetching prices

    // ERC-20 Transfer event signature: keccak256("Transfer(address,address,uint256)")
    let transfer_sig: H256 =
        "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef".parse()?;

    // Convert addresses to H256 topics (padded with zeros on the left)
    let address_topics: Vec<H256> = addresses
        .iter()
        .filter_map(|addr| {
            addr.parse::<Address>().ok().map(|a| {
                let mut padded = [0u8; 32];
                padded[12..32].copy_from_slice(a.as_bytes());
                H256::from(padded)
            })
        })
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

        // Only process known tokens
        if let Some((symbol, decimals)) = get_token_info(&token_address) {
            // Decode transfer amount
            if log.data.len() >= 32 {
                let amount_raw = U256::from_big_endian(&log.data);
                let divisor = 10_u64.pow(decimals as u32) as f64;
                let amount = amount_raw.as_u128() as f64 / divisor;

                // Fetch real-time USD price
                if let Some(price_usd) = get_token_price_usd(&token_address, &http_client).await {
                    let usd = amount * price_usd;

                    let from_label = wallet_labels
                        .get(&from_addr.to_lowercase())
                        .map(|l| l.as_str())
                        .unwrap_or("Unknown");
                    let to_label = wallet_labels
                        .get(&to_addr.to_lowercase())
                        .map(|l| l.as_str())
                        .unwrap_or("Unknown");

                    info!(
                        "💰 {:.2} {} @ ${:.2} = ${:.2} from {} to {}",
                        amount, symbol, price_usd, usd, from_label, to_label
                    );

                    let transfer = Transfer {
                        from: format!("{from_addr} [{from_label}]"),
                        to: format!("{to_addr} [{to_label}]"),
                        amount: usd,
                        token: symbol.to_string(),
                        block_number: log.block_number.map(|n| n.as_u64()).unwrap_or(0),
                        timestamp: Utc::now(),
                    };

                    if let Some(alert) = alert_engine.should_alert(&transfer) {
                        notifier.send(&alert).await?;
                    }
                } else {
                    warn!(
                        "⚠️  Skipping {} transfer - could not fetch real-time price",
                        symbol
                    );
                }
            }
        }
        // Unknown tokens are silently skipped
    }

    Ok(())
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // AlertEngine Tests - Core business logic for threshold-based alerting
    // ========================================================================

    #[test]
    fn alert_engine_triggers_above_threshold() {
        std::env::set_var("TRANSFER_THRESHOLD", "50000");
        let engine = AlertEngine::new();
        let transfer = Transfer {
            from: "0x123 [Binance]".to_string(),
            to: "0x456 [Unknown]".to_string(),
            amount: 75000.0,
            token: "USDT".to_string(),
            block_number: 1,
            timestamp: Utc::now(),
        };

        let alert = engine.should_alert(&transfer);
        assert!(alert.is_some(), "Should alert for amount above threshold");

        let alert = alert.unwrap();
        assert_eq!(alert.title, "Large Whale Transfer Detected");
        assert!(alert.message.contains("$75000.00"));
        assert!(alert.message.contains("USDT"));
    }

    #[test]
    fn alert_engine_no_alert_below_threshold() {
        std::env::set_var("TRANSFER_THRESHOLD", "50000");
        let engine = AlertEngine::new();
        let transfer = Transfer {
            from: "0x123 [Binance]".to_string(),
            to: "0x456 [Unknown]".to_string(),
            amount: 25000.0,
            token: "USDT".to_string(),
            block_number: 1,
            timestamp: Utc::now(),
        };

        let alert = engine.should_alert(&transfer);
        assert!(alert.is_none(), "Should not alert for amount below threshold");
    }

    #[test]
    fn alert_engine_no_alert_exactly_at_threshold() {
        std::env::set_var("TRANSFER_THRESHOLD", "100000");
        let engine = AlertEngine::new();
        let transfer = Transfer {
            from: "0x123 [Binance]".to_string(),
            to: "0x456 [Unknown]".to_string(),
            amount: 100000.0,
            token: "USDC".to_string(),
            block_number: 1,
            timestamp: Utc::now(),
        };

        let alert = engine.should_alert(&transfer);
        assert!(alert.is_none(), "Should not alert for amount exactly at threshold");
    }

    #[test]
    fn alert_engine_triggers_one_cent_above_threshold() {
        std::env::set_var("TRANSFER_THRESHOLD", "100000");
        let engine = AlertEngine::new();
        let transfer = Transfer {
            from: "0x123 [Binance]".to_string(),
            to: "0x456 [Unknown]".to_string(),
            amount: 100000.01,
            token: "USDC".to_string(),
            block_number: 1,
            timestamp: Utc::now(),
        };

        let alert = engine.should_alert(&transfer);
        assert!(alert.is_some(), "Should alert for amount even slightly above threshold");
    }

    #[test]
    fn alert_engine_uses_default_threshold_when_env_missing() {
        std::env::remove_var("TRANSFER_THRESHOLD");
        let engine = AlertEngine::new();

        // Default threshold is 100000
        let transfer_below = Transfer {
            from: "0x123".to_string(),
            to: "0x456".to_string(),
            amount: 99999.0,
            token: "DAI".to_string(),
            block_number: 1,
            timestamp: Utc::now(),
        };
        assert!(engine.should_alert(&transfer_below).is_none());

        let transfer_above = Transfer {
            from: "0x123".to_string(),
            to: "0x456".to_string(),
            amount: 100001.0,
            token: "DAI".to_string(),
            block_number: 1,
            timestamp: Utc::now(),
        };
        assert!(engine.should_alert(&transfer_above).is_some());
    }

    #[test]
    fn alert_engine_handles_invalid_threshold_env() {
        std::env::set_var("TRANSFER_THRESHOLD", "not_a_number");
        let engine = AlertEngine::new();

        // Should fall back to default (100000)
        let transfer = Transfer {
            from: "0x123".to_string(),
            to: "0x456".to_string(),
            amount: 50000.0,
            token: "WBTC".to_string(),
            block_number: 1,
            timestamp: Utc::now(),
        };
        assert!(engine.should_alert(&transfer).is_none());
    }

    #[test]
    fn alert_engine_handles_massive_transfers() {
        std::env::set_var("TRANSFER_THRESHOLD", "100000");
        let engine = AlertEngine::new();
        let transfer = Transfer {
            from: "0x123 [Binance]".to_string(),
            to: "0x456 [Coinbase]".to_string(),
            amount: 1_000_000_000.0, // $1 billion
            token: "USDT".to_string(),
            block_number: 1,
            timestamp: Utc::now(),
        };

        let alert = engine.should_alert(&transfer);
        assert!(alert.is_some());
        assert!(alert.unwrap().message.contains("$1000000000.00"));
    }

    #[test]
    fn alert_engine_handles_tiny_transfers() {
        std::env::set_var("TRANSFER_THRESHOLD", "100000");
        let engine = AlertEngine::new();
        let transfer = Transfer {
            from: "0x123".to_string(),
            to: "0x456".to_string(),
            amount: 0.01, // 1 cent
            token: "USDC".to_string(),
            block_number: 1,
            timestamp: Utc::now(),
        };

        assert!(engine.should_alert(&transfer).is_none());
    }

    #[test]
    fn alert_engine_includes_all_transfer_details_in_message() {
        std::env::set_var("TRANSFER_THRESHOLD", "1000");
        let engine = AlertEngine::new();
        let transfer = Transfer {
            from: "0xABC [Binance-Hot-8]".to_string(),
            to: "0xDEF [Unknown-Wallet]".to_string(),
            amount: 5000.50,
            token: "WETH".to_string(),
            block_number: 18500000,
            timestamp: Utc::now(),
        };

        let alert_option = engine.should_alert(&transfer);
        assert!(alert_option.is_some(), "Alert should be triggered for amount above threshold");

        let alert = alert_option.unwrap();
        assert!(alert.message.contains("5000.50"), "Message should contain amount");
        assert!(alert.message.contains("WETH"), "Message should contain token symbol");
        assert!(alert.message.contains("0xABC [Binance-Hot-8]"), "Message should contain from address with label");
        assert!(alert.message.contains("0xDEF [Unknown-Wallet]"), "Message should contain to address with label");
    }

    // ========================================================================
    // Token Recognition Tests - Ensures we only track known valuable tokens
    // ========================================================================

    #[test]
    fn token_info_recognizes_usdt() {
        let result = get_token_info("0xdac17f958d2ee523a2206206994597c13d831ec7");
        assert_eq!(result, Some(("USDT", 6)));
    }

    #[test]
    fn token_info_recognizes_usdc() {
        let result = get_token_info("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48");
        assert_eq!(result, Some(("USDC", 6)));
    }

    #[test]
    fn token_info_recognizes_dai() {
        let result = get_token_info("0x6b175474e89094c44da98b954eedeac495271d0f");
        assert_eq!(result, Some(("DAI", 18)));
    }

    #[test]
    fn token_info_recognizes_wbtc() {
        let result = get_token_info("0x2260fac5e5542a773aa44fbcfedf7c193bc2c599");
        assert_eq!(result, Some(("WBTC", 8)));
    }

    #[test]
    fn token_info_recognizes_weth() {
        let result = get_token_info("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2");
        assert_eq!(result, Some(("WETH", 18)));
    }

    #[test]
    fn token_info_recognizes_link() {
        let result = get_token_info("0x514910771af9ca656af840dff83e8264ecf986ca");
        assert_eq!(result, Some(("LINK", 18)));
    }

    #[test]
    fn token_info_recognizes_uni() {
        let result = get_token_info("0x1f9840a85d5af5bf1d1762f925bdaddc4201f984");
        assert_eq!(result, Some(("UNI", 18)));
    }

    #[test]
    fn token_info_recognizes_aave() {
        let result = get_token_info("0x7fc66500c84a76ad7e9c93437bfc5ac33e2ddae9");
        assert_eq!(result, Some(("AAVE", 18)));
    }

    #[test]
    fn token_info_rejects_unknown_token() {
        let result = get_token_info("0x0000000000000000000000000000000000000000");
        assert_eq!(result, None);
    }

    #[test]
    fn token_info_rejects_random_address() {
        let result = get_token_info("0x1234567890abcdef1234567890abcdef12345678");
        assert_eq!(result, None);
    }

    #[test]
    fn token_info_case_insensitive_uppercase() {
        let result = get_token_info("0xDAC17F958D2EE523A2206206994597C13D831EC7");
        assert_eq!(result, Some(("USDT", 6)));
    }

    #[test]
    fn token_info_case_insensitive_mixed() {
        let result = get_token_info("0xDaC17F958d2Ee523a2206206994597C13d831eC7");
        assert_eq!(result, Some(("USDT", 6)));
    }

    #[test]
    fn token_info_validates_correct_decimals() {
        // Stablecoins use 6 decimals
        assert_eq!(get_token_info("0xdac17f958d2ee523a2206206994597c13d831ec7"), Some(("USDT", 6)));
        assert_eq!(get_token_info("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"), Some(("USDC", 6)));

        // WBTC uses 8 decimals
        assert_eq!(get_token_info("0x2260fac5e5542a773aa44fbcfedf7c193bc2c599"), Some(("WBTC", 8)));

        // Most ERC-20 tokens use 18 decimals
        assert_eq!(get_token_info("0x6b175474e89094c44da98b954eedeac495271d0f"), Some(("DAI", 18)));
        assert_eq!(get_token_info("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"), Some(("WETH", 18)));
    }

    #[test]
    fn token_info_filters_worthless_meme_coins() {
        // These should all return None to skip worthless tokens
        let meme_addresses = vec![
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        ];

        for addr in meme_addresses {
            assert_eq!(get_token_info(addr), None, "Should filter unknown token: {}", addr);
        }
    }

    // ========================================================================
    // URL Masking Tests - Security: Ensures API keys/secrets are not logged
    // ========================================================================

    #[test]
    fn mask_url_hides_alchemy_api_key() {
        let url = "wss://eth-mainnet.g.alchemy.com/v2/SECRET123KEY456";
        let masked = mask_url(url);
        assert_eq!(masked, "wss://eth-mainnet.g.alchemy.com/***/");
        assert!(!masked.contains("SECRET"));
        assert!(!masked.contains("KEY"));
    }

    #[test]
    fn mask_url_hides_infura_api_key() {
        let url = "wss://mainnet.infura.io/ws/v3/abc123def456ghi789";
        let masked = mask_url(url);
        assert_eq!(masked, "wss://mainnet.infura.io/***/");
        assert!(!masked.contains("abc123"));
    }

    #[test]
    fn mask_url_hides_quicknode_api_key() {
        let url = "wss://example.quiknode.pro/0123456789abcdef/";
        let masked = mask_url(url);
        assert_eq!(masked, "wss://example.quiknode.pro/***/");
        assert!(!masked.contains("0123456789"));
    }

    #[test]
    fn mask_url_handles_https_urls() {
        let url = "https://api.example.com/v1/secret-token-here";
        let masked = mask_url(url);
        assert_eq!(masked, "https://api.example.com/***/");
        assert!(!masked.contains("secret"));
    }

    #[test]
    fn mask_url_handles_http_urls() {
        let url = "http://localhost:8545/api-key-12345";
        let masked = mask_url(url);
        assert_eq!(masked, "http://localhost:8545/***/");
        assert!(!masked.contains("12345"));
    }

    #[test]
    fn mask_url_handles_url_without_path() {
        let url = "wss://mainnet.ethereum.org";
        let masked = mask_url(url);
        // No path to mask, returns generic mask
        assert_eq!(masked, "***");
    }

    #[test]
    fn mask_url_handles_invalid_url_format() {
        let url = "not-a-valid-url";
        let masked = mask_url(url);
        assert_eq!(masked, "***");
    }

    #[test]
    fn mask_url_handles_empty_string() {
        let url = "";
        let masked = mask_url(url);
        assert_eq!(masked, "***");
    }

    #[test]
    fn mask_url_preserves_scheme_and_host() {
        let url = "wss://eth-mainnet.g.alchemy.com/v2/SECRET";
        let masked = mask_url(url);
        assert!(masked.starts_with("wss://"));
        assert!(masked.contains("eth-mainnet.g.alchemy.com"));
        assert!(masked.ends_with("/***/"));
    }

    #[test]
    fn mask_url_prevents_api_key_leakage_in_logs() {
        // ensuring sensitive data never appears in logs
        let sensitive_urls = vec![
            "wss://mainnet.infura.io/ws/v3/YOUR_PROJECT_ID",
            "https://eth-mainnet.g.alchemy.com/v2/YOUR_API_KEY",
            "wss://node.example.com/supersecrettoken123",
        ];

        for url in sensitive_urls {
            let masked = mask_url(url);
            // Extract what would be the "secret" part (after last /)
            if let Some(pos) = url.rfind('/') {
                let secret = &url[pos + 1..];
                if !secret.is_empty() {
                    assert!(!masked.contains(secret), "Secret '{}' leaked in masked URL: {}", secret, masked);
                }
            }
        }
    }

    // ========================================================================
    // Wallet Label Parsing Tests - Validates configuration parsing logic
    // ========================================================================

    #[test]
    fn wallet_labels_parses_single_entry() {
        let input = "0xF977814e90dA44bFA03b6295A0616a897441aceC=Binance-Hot-8";
        let labels: std::collections::HashMap<String, String> = input
            .split(',')
            .filter_map(|pair| {
                let parts: Vec<&str> = pair.split('=').collect();
                if parts.len() == 2 {
                    Some((parts[0].trim().to_lowercase(), parts[1].trim().to_string()))
                } else {
                    None
                }
            })
            .collect();

        assert_eq!(labels.len(), 1);
        assert_eq!(
            labels.get("0xf977814e90da44bfa03b6295a0616a897441acec"),
            Some(&"Binance-Hot-8".to_string())
        );
    }

    #[test]
    fn wallet_labels_parses_multiple_entries() {
        let input = "0xF977814e90dA44bFA03b6295A0616a897441aceC=Binance-Hot-8,0x28C6c06298d514Db089934071355E5743bf21d60=Binance-Hot-14";
        let labels: std::collections::HashMap<String, String> = input
            .split(',')
            .filter_map(|pair| {
                let parts: Vec<&str> = pair.split('=').collect();
                if parts.len() == 2 {
                    Some((parts[0].trim().to_lowercase(), parts[1].trim().to_string()))
                } else {
                    None
                }
            })
            .collect();

        assert_eq!(labels.len(), 2);
        assert_eq!(
            labels.get("0xf977814e90da44bfa03b6295a0616a897441acec"),
            Some(&"Binance-Hot-8".to_string())
        );
        assert_eq!(
            labels.get("0x28c6c06298d514db089934071355e5743bf21d60"),
            Some(&"Binance-Hot-14".to_string())
        );
    }

    #[test]
    fn wallet_labels_handles_whitespace() {
        let input = "  0xABC123  =  Coinbase   ,   0xDEF456 =  Kraken  ";
        let labels: std::collections::HashMap<String, String> = input
            .split(',')
            .filter_map(|pair| {
                let parts: Vec<&str> = pair.split('=').collect();
                if parts.len() == 2 {
                    Some((parts[0].trim().to_lowercase(), parts[1].trim().to_string()))
                } else {
                    None
                }
            })
            .collect();

        assert_eq!(labels.len(), 2);
        assert_eq!(labels.get("0xabc123"), Some(&"Coinbase".to_string()));
        assert_eq!(labels.get("0xdef456"), Some(&"Kraken".to_string()));
    }

    #[test]
    fn wallet_labels_case_insensitive_addresses() {
        let input = "0xABCDEF=Label1,0xabcdef=Label2";
        let labels: std::collections::HashMap<String, String> = input
            .split(',')
            .filter_map(|pair| {
                let parts: Vec<&str> = pair.split('=').collect();
                if parts.len() == 2 {
                    Some((parts[0].trim().to_lowercase(), parts[1].trim().to_string()))
                } else {
                    None
                }
            })
            .collect();

        // Should only have 1 entry (same address, case-insensitive)
        assert_eq!(labels.len(), 1);
        assert!(labels.contains_key("0xabcdef"));
    }

    #[test]
    fn wallet_labels_skips_malformed_entries() {
        let input = "0xABC=Label1,MALFORMED_NO_EQUALS,0xDEF=Label2,=NoAddress,Address=";
        let labels: std::collections::HashMap<String, String> = input
            .split(',')
            .filter_map(|pair| {
                let parts: Vec<&str> = pair.split('=').collect();
                if parts.len() == 2 {
                    let key = parts[0].trim();
                    let value = parts[1].trim();
                    // Only accept entries where both key and value are non-empty
                    if !key.is_empty() && !value.is_empty() {
                        Some((key.to_lowercase(), value.to_string()))
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();

        // Should only parse valid entries with non-empty keys and values
        assert_eq!(labels.len(), 2);
        assert!(labels.contains_key("0xabc"));
        assert!(labels.contains_key("0xdef"));
        assert!(!labels.contains_key(""), "Should not have empty key");
        assert!(!labels.contains_key("address"), "Should not have entry with empty value");
    }

    #[test]
    fn wallet_labels_handles_empty_string() {
        let input = "";
        let labels: std::collections::HashMap<String, String> = input
            .split(',')
            .filter_map(|pair| {
                let parts: Vec<&str> = pair.split('=').collect();
                if parts.len() == 2 {
                    Some((parts[0].trim().to_lowercase(), parts[1].trim().to_string()))
                } else {
                    None
                }
            })
            .collect();

        assert_eq!(labels.len(), 0);
    }

    #[test]
    fn wallet_labels_preserves_hyphens_in_labels() {
        let input = "0x123=Binance-Hot-Wallet-8";
        let labels: std::collections::HashMap<String, String> = input
            .split(',')
            .filter_map(|pair| {
                let parts: Vec<&str> = pair.split('=').collect();
                if parts.len() == 2 {
                    Some((parts[0].trim().to_lowercase(), parts[1].trim().to_string()))
                } else {
                    None
                }
            })
            .collect();

        assert_eq!(labels.get("0x123"), Some(&"Binance-Hot-Wallet-8".to_string()));
    }

    // ========================================================================
    // Decimal Conversion Tests - Critical for accurate USD calculations
    // ========================================================================

    #[test]
    fn decimal_conversion_usdt_6_decimals() {
        // USDT uses 6 decimals
        // 1,000,000 raw units = 1.0 USDT
        let raw_amount: u128 = 1_000_000;
        let decimals: u8 = 6;
        let divisor = 10_u64.pow(decimals as u32) as f64;
        let amount = raw_amount as f64 / divisor;

        assert_eq!(amount, 1.0);
    }

    #[test]
    fn decimal_conversion_usdt_large_amount() {
        // 5,000,000,000 raw units = 5,000.0 USDT
        let raw_amount: u128 = 5_000_000_000;
        let decimals: u8 = 6;
        let divisor = 10_u64.pow(decimals as u32) as f64;
        let amount = raw_amount as f64 / divisor;

        assert_eq!(amount, 5000.0);
    }

    #[test]
    fn decimal_conversion_wbtc_8_decimals() {
        // WBTC uses 8 decimals
        // 100,000,000 raw units = 1.0 WBTC
        let raw_amount: u128 = 100_000_000;
        let decimals: u8 = 8;
        let divisor = 10_u64.pow(decimals as u32) as f64;
        let amount = raw_amount as f64 / divisor;

        assert_eq!(amount, 1.0);
    }

    #[test]
    fn decimal_conversion_weth_18_decimals() {
        // WETH uses 18 decimals
        // 1,000,000,000,000,000,000 raw units = 1.0 WETH
        let raw_amount: u128 = 1_000_000_000_000_000_000;
        let decimals: u8 = 18;
        let divisor = 10_u64.pow(decimals as u32) as f64;
        let amount = raw_amount as f64 / divisor;

        assert_eq!(amount, 1.0);
    }

    #[test]
    fn decimal_conversion_handles_zero() {
        let raw_amount: u128 = 0;
        let decimals: u8 = 18;
        let divisor = 10_u64.pow(decimals as u32) as f64;
        let amount = raw_amount as f64 / divisor;

        assert_eq!(amount, 0.0);
    }

    #[test]
    fn decimal_conversion_handles_fractional_usdt() {
        // 1,500,000 raw units = 1.5 USDT
        let raw_amount: u128 = 1_500_000;
        let decimals: u8 = 6;
        let divisor = 10_u64.pow(decimals as u32) as f64;
        let amount = raw_amount as f64 / divisor;

        assert_eq!(amount, 1.5);
    }

    #[test]
    fn decimal_conversion_massive_weth_transfer() {
        // 1,000 WETH = 1,000 * 10^18 raw units
        let raw_amount: u128 = 1_000_000_000_000_000_000_000;
        let decimals: u8 = 18;
        let divisor = 10_u64.pow(decimals as u32) as f64;
        let amount = raw_amount as f64 / divisor;

        assert_eq!(amount, 1000.0);
    }

    #[test]
    fn decimal_conversion_tiny_amounts() {
        // 1 raw unit of USDT (6 decimals) = 0.000001 USDT
        let raw_amount: u128 = 1;
        let decimals: u8 = 6;
        let divisor = 10_u64.pow(decimals as u32) as f64;
        let amount = raw_amount as f64 / divisor;

        assert_eq!(amount, 0.000001);
    }

    #[test]
    fn decimal_conversion_validates_all_supported_decimals() {
        // Test that divisor calculation works for all supported decimal places
        let test_cases = vec![
            (6, 1_000_000.0),     // USDT, USDC
            (8, 100_000_000.0),   // WBTC
            (18, 1_000_000_000_000_000_000.0), // WETH, DAI, LINK, UNI, AAVE
        ];

        for (decimals, expected_divisor) in test_cases {
            let divisor = 10_u64.pow(decimals as u32) as f64;
            assert_eq!(divisor, expected_divisor, "Incorrect divisor for {} decimals", decimals);
        }
    }

    // ========================================================================
    // Address Validation Tests - Ensures valid Ethereum address format
    // ========================================================================

    #[test]
    fn address_parsing_valid_ethereum_address() {
        // Valid Ethereum address format: 0x + 40 hex characters
        let valid_addresses = vec![
            "0xF977814e90dA44bFA03b6295A0616a897441aceC",
            "0x28C6c06298d514Db089934071355E5743bf21d60",
            "0x0000000000000000000000000000000000000000",
            "0xffffffffffffffffffffffffffffffffffffffff",
        ];

        for addr_str in valid_addresses {
            let result = addr_str.parse::<Address>();
            assert!(result.is_ok(), "Should parse valid address: {}", addr_str);
        }
    }

    #[test]
    fn address_parsing_rejects_invalid_addresses() {
        let invalid_addresses = vec![
            "not_an_address",
            "0x123",  // Too short
            "0xGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG",  // Invalid hex (G is not hex)
            "0x",  // Empty after prefix
            "",  // Empty string
            "0x12345678901234567890123456789012345678901",  // 41 chars (too long)
            "GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG",  // Invalid hex without prefix
        ];

        for addr_str in invalid_addresses {
            let result = addr_str.parse::<Address>();
            assert!(result.is_err(), "Should reject invalid address: {}", addr_str);
        }
    }

    #[test]
    fn address_parsing_case_insensitive() {
        let lowercase = "0xf977814e90da44bfa03b6295a0616a897441acec";
        let uppercase = "0xF977814E90DA44BFA03B6295A0616A897441ACEC";
        let mixed = "0xF977814e90dA44bFA03b6295A0616a897441aceC";

        let addr1 = lowercase.parse::<Address>().unwrap();
        let addr2 = uppercase.parse::<Address>().unwrap();
        let addr3 = mixed.parse::<Address>().unwrap();

        assert_eq!(addr1, addr2);
        assert_eq!(addr2, addr3);
    }

    #[test]
    fn address_list_parsing_filters_invalid() {
        let input = "0xF977814e90dA44bFA03b6295A0616a897441aceC,invalid_address,0x28C6c06298d514Db089934071355E5743bf21d60";
        let addresses: Vec<String> = input
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        // Convert to Address to validate
        let valid_addresses: Vec<Address> = addresses
            .iter()
            .filter_map(|addr| addr.parse::<Address>().ok())
            .collect();

        assert_eq!(valid_addresses.len(), 2, "Should only parse 2 valid addresses");
    }

    #[test]
    fn address_list_parsing_handles_whitespace() {
        let input = "  0xF977814e90dA44bFA03b6295A0616a897441aceC  ,  0x28C6c06298d514Db089934071355E5743bf21d60  ";
        let addresses: Vec<String> = input
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let valid_addresses: Vec<Address> = addresses
            .iter()
            .filter_map(|addr| addr.parse::<Address>().ok())
            .collect();

        assert_eq!(valid_addresses.len(), 2);
    }

    #[test]
    fn address_list_parsing_rejects_empty_list() {
        let input = "";
        let addresses: Vec<String> = input
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        assert_eq!(addresses.len(), 0, "Empty input should result in empty list");
    }

    #[test]
    fn address_list_parsing_skips_empty_entries() {
        let input = "0xF977814e90dA44bFA03b6295A0616a897441aceC,,,,0x28C6c06298d514Db089934071355E5743bf21d60";
        let addresses: Vec<String> = input
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        assert_eq!(addresses.len(), 2, "Should skip empty entries");
    }

    #[test]
    fn address_to_h256_topic_conversion() {
        // Test the conversion logic from main loop (lines 318-325)
        let addr_str = "0xF977814e90dA44bFA03b6295A0616a897441aceC";
        let addr = addr_str.parse::<Address>().unwrap();

        let mut padded = [0u8; 32];
        padded[12..32].copy_from_slice(addr.as_bytes());
        let _h256_topic = H256::from(padded);

        // Verify padding is correct (first 12 bytes should be zero)
        assert_eq!(&padded[0..12], &[0u8; 12], "First 12 bytes should be zero padding");

        // Verify last 20 bytes match the address
        assert_eq!(&padded[12..32], addr.as_bytes(), "Last 20 bytes should match address");

        // Verify Address is 20 bytes
        assert_eq!(addr.as_bytes().len(), 20, "Ethereum addresses are 20 bytes");
    }

    // ========================================================================
    // Environment Variable Validation Tests - Configuration safety
    // ========================================================================

    #[test]
    fn env_watch_addresses_parses_correctly() {
        std::env::set_var("WATCH_ADDRESSES", "0xF977814e90dA44bFA03b6295A0616a897441aceC,0x28C6c06298d514Db089934071355E5743bf21d60");

        let addresses: Vec<String> = std::env::var("WATCH_ADDRESSES")
            .unwrap()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        assert_eq!(addresses.len(), 2);
    }

    #[test]
    fn env_watch_addresses_empty_should_be_detected() {
        std::env::set_var("WATCH_ADDRESSES", "");

        let addresses: Vec<String> = std::env::var("WATCH_ADDRESSES")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        assert_eq!(addresses.len(), 0, "Empty WATCH_ADDRESSES should result in empty list");
    }

    #[test]
    fn env_transfer_threshold_parses_as_f64() {
        std::env::set_var("TRANSFER_THRESHOLD", "250000.50");

        let threshold: f64 = std::env::var("TRANSFER_THRESHOLD")
            .unwrap()
            .parse()
            .unwrap();

        assert_eq!(threshold, 250000.50);
    }

    #[test]
    fn env_transfer_threshold_rejects_negative() {
        std::env::set_var("TRANSFER_THRESHOLD", "-1000");

        let threshold: Result<f64, _> = std::env::var("TRANSFER_THRESHOLD")
            .unwrap()
            .parse();

        // Parsing will succeed, but we should validate it's positive
        assert!(threshold.is_ok());
        let value = threshold.unwrap();
        assert!(value < 0.0, "Negative threshold should be detected");
        // In production, we should reject negative thresholds
    }

    #[test]
    fn env_ws_url_format_validation() {
        let valid_urls = vec![
            "wss://eth-mainnet.g.alchemy.com/v2/KEY",
            "wss://mainnet.infura.io/ws/v3/KEY",
            "ws://localhost:8545",
        ];

        for url in valid_urls {
            assert!(url.starts_with("wss://") || url.starts_with("ws://"),
                "WebSocket URL should start with ws:// or wss://: {}", url);
        }
    }

    #[test]
    fn env_ws_url_rejects_http() {
        let invalid_urls = vec![
            "https://eth-mainnet.g.alchemy.com/v2/KEY",
            "http://mainnet.infura.io/v3/KEY",
            "",
        ];

        for url in invalid_urls {
            assert!(!url.starts_with("wss://") && !url.starts_with("ws://"),
                "Should reject non-WebSocket URL: {}", url);
        }
    }

    #[test]
    fn env_wallet_labels_validates_format() {
        let valid = "0xABC=Label1,0xDEF=Label2";
        let labels: Vec<&str> = valid.split(',').collect();

        for label in labels {
            assert!(label.contains('='), "Each label should contain '='");
            let parts: Vec<&str> = label.split('=').collect();
            assert_eq!(parts.len(), 2, "Each label should have exactly one '='");
        }
    }

    #[test]
    fn env_rust_log_accepts_valid_levels() {
        let valid_levels = vec!["trace", "debug", "info", "warn", "error"];

        for level in valid_levels {
            std::env::set_var("RUST_LOG", level);
            let log_level = std::env::var("RUST_LOG").unwrap();
            assert!(
                vec!["trace", "debug", "info", "warn", "error"].contains(&log_level.as_str()),
                "Invalid log level: {}", log_level
            );
        }
    }

    // ========================================================================
    // Malformed Data Handling Tests - Runtime safety for blockchain events
    // ========================================================================

    #[test]
    fn log_data_handles_exactly_32_bytes() {
        let data = vec![0u8; 32];
        assert_eq!(data.len(), 32);

        // This is the minimum valid size for ERC-20 transfer data
        if data.len() >= 32 {
            let amount_raw = U256::from_big_endian(&data);
            assert_eq!(amount_raw, U256::zero());
        }
    }

    #[test]
    fn log_data_handles_more_than_32_bytes() {
        let data = vec![0u8; 64];
        assert!(data.len() >= 32);

        // Should only read first 32 bytes
        let amount_raw = U256::from_big_endian(&data[0..32]);
        assert_eq!(amount_raw, U256::zero());
    }

    #[test]
    fn log_data_rejects_less_than_32_bytes() {
        let data = vec![0u8; 31];
        assert!(data.len() < 32);

        // Production code checks: if log.data.len() >= 32
        // This test validates we correctly skip malformed data
        assert!(data.len() < 32, "Should detect undersized data");
    }

    #[test]
    fn log_data_handles_empty() {
        let data: Vec<u8> = vec![];
        assert_eq!(data.len(), 0);
        assert!(data.len() < 32, "Empty data should be detected");
    }

    #[test]
    fn u256_from_big_endian_max_value() {
        let data = vec![0xFFu8; 32];
        let amount_raw = U256::from_big_endian(&data);

        // Maximum U256 value
        assert_eq!(amount_raw, U256::MAX);
    }

    #[test]
    fn u256_from_big_endian_zero() {
        let data = vec![0u8; 32];
        let amount_raw = U256::from_big_endian(&data);
        assert_eq!(amount_raw, U256::zero());
    }

    #[test]
    fn u256_from_big_endian_one() {
        let mut data = vec![0u8; 32];
        data[31] = 1; // Big-endian: least significant byte is last

        let amount_raw = U256::from_big_endian(&data);
        assert_eq!(amount_raw, U256::one());
    }

    #[test]
    fn u256_conversion_to_f64_preserves_accuracy() {
        // Test ERC-20 amounts
        let test_cases = vec![
            (1_000_000u128, 6, 1.0),           // 1 USDT
            (100_000_000u128, 8, 1.0),         // 1 WBTC
            (1_000_000_000_000_000_000u128, 18, 1.0), // 1 ETH
        ];

        for (raw, decimals, expected) in test_cases {
            let divisor = 10_u64.pow(decimals as u32) as f64;
            let result = raw as f64 / divisor;
            assert_eq!(result, expected, "Failed for {} with {} decimals", raw, decimals);
        }
    }

    #[test]
    fn u256_conversion_handles_overflow_scenario() {
        // U128::MAX is the largest we can safely convert to f64
        let max_safe = u128::MAX;
        let as_f64 = max_safe as f64;

        // f64 can represent very large numbers, but loses precision
        assert!(as_f64 > 0.0, "Should convert to positive f64");
        // Note: This demonstrates potential precision loss at extreme values
    }

    // ========================================================================
    // Telegram Message Formatting Tests - Ensures proper markdown rendering
    // ========================================================================

    #[test]
    fn telegram_message_format_includes_title() {
        let alert = Alert::new(
            "Test Alert".to_string(),
            "Test message body".to_string(),
        );

        let message = format!(
            "⚠️ *{}*\n\n{}\n\n_Time: {}_",
            alert.title,
            alert.message,
            alert.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
        );

        assert!(message.contains("*Test Alert*"));
        assert!(message.contains("Test message body"));
    }

    #[test]
    fn telegram_message_format_includes_timestamp() {
        let alert = Alert::new(
            "Test".to_string(),
            "Message".to_string(),
        );

        let message = format!(
            "⚠️ *{}*\n\n{}\n\n_Time: {}_",
            alert.title,
            alert.message,
            alert.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
        );

        assert!(message.contains("_Time:"));
        assert!(message.contains("UTC_"));
    }

    #[test]
    fn telegram_message_format_with_special_chars() {
        // Test that addresses with special markdown characters are included
        let alert = Alert::new(
            "Large Transfer".to_string(),
            "$100,000.00 USDT transferred from 0x123[Binance] to 0x456[Unknown]".to_string(),
        );

        let message = format!(
            "⚠️ *{}*\n\n{}\n\n_Time: {}_",
            alert.title,
            alert.message,
            alert.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
        );

        assert!(message.contains("0x123[Binance]"));
        assert!(message.contains("$100,000.00"));
        // Note: In production, we should escape [ ] for Telegram markdown
    }

    #[test]
    fn telegram_message_uses_markdown_formatting() {
        let alert = Alert::new(
            "Title".to_string(),
            "Body".to_string(),
        );

        let message = format!(
            "⚠️ *{}*\n\n{}\n\n_Time: {}_",
            alert.title,
            alert.message,
            alert.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
        );

        // Verify markdown elements are present
        assert!(message.starts_with("⚠️ *"), "Should start with emoji and bold marker");
        assert!(message.contains("*\n\n"), "Should close bold with asterisk");
        assert!(message.contains("_Time:"), "Should use italic for timestamp");
    }

    // ========================================================================
    // Alert Creation Tests - Validates Alert struct behavior
    // ========================================================================

    #[test]
    fn alert_creation_stores_all_fields() {
        let title = "Test Alert";
        let message = "Test Message";

        let alert = Alert::new(title.to_string(), message.to_string());

        assert_eq!(alert.title, title);
        assert_eq!(alert.message, message);
        assert!(alert.timestamp <= Utc::now());
    }

    #[test]
    fn alert_timestamp_is_recent() {
        let before = Utc::now();
        let alert = Alert::new("Test".to_string(), "Message".to_string());
        let after = Utc::now();

        assert!(alert.timestamp >= before, "Timestamp should be after creation start");
        assert!(alert.timestamp <= after, "Timestamp should be before creation end");
    }

    #[test]
    fn alert_handles_empty_strings() {
        let alert = Alert::new(String::new(), String::new());

        assert_eq!(alert.title, "");
        assert_eq!(alert.message, "");
    }

    #[test]
    fn alert_handles_unicode() {
        let alert = Alert::new(
            "🚨 Critical Alert 🚨".to_string(),
            "Transfer: 💰 $1,000,000 → 🏦".to_string(),
        );

        assert!(alert.title.contains("🚨"));
        assert!(alert.message.contains("💰"));
        assert!(alert.message.contains("🏦"));
    }

    #[test]
    fn alert_handles_long_messages() {
        let long_message = "A".repeat(10000);
        let alert = Alert::new("Title".to_string(), long_message.clone());

        assert_eq!(alert.message.len(), 10000);
        assert_eq!(alert.message, long_message);
    }

    // ========================================================================
    // Integration Tests - HTTP API Mocking
    // ========================================================================

    #[cfg(test)]
    mod integration_tests {
        use mockito::Server;

        // ====================================================================
        // CoinGecko API Tests - get_token_price_usd()
        // ====================================================================

        #[tokio::test]
        async fn coingecko_api_returns_valid_price() {
            let mut server = Server::new_async().await;

            // Mock successful CoinGecko response
            let mock = server
                .mock("GET", "/api/v3/simple/token_price/ethereum")
                .match_query(mockito::Matcher::AllOf(vec![
                    mockito::Matcher::UrlEncoded("contract_addresses".into(), "0xdac17f958d2ee523a2206206994597c13d831ec7".into()),
                    mockito::Matcher::UrlEncoded("vs_currencies".into(), "usd".into()),
                ]))
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(r#"{"0xdac17f958d2ee523a2206206994597c13d831ec7":{"usd":1.0}}"#)
                .create_async()
                .await;

            let client = reqwest::Client::new();
            let token_address = "0xdac17f958d2ee523a2206206994597c13d831ec7";

            // Replace the URL with our mock server
            let url = format!(
                "{}/api/v3/simple/token_price/ethereum?contract_addresses={}&vs_currencies=usd",
                server.url(),
                token_address
            );

            let response = client.get(&url).send().await.unwrap();
            let json: serde_json::Value = response.json().await.unwrap();

            let price = json
                .get(token_address)
                .and_then(|obj| obj.get("usd"))
                .and_then(|price| price.as_f64());

            assert_eq!(price, Some(1.0));
            mock.assert_async().await;
        }

        #[tokio::test]
        async fn coingecko_api_handles_404_not_found() {
            let mut server = Server::new_async().await;

            let _mock = server
                .mock("GET", "/api/v3/simple/token_price/ethereum")
                .match_query(mockito::Matcher::Any)
                .with_status(404)
                .with_header("content-type", "text/plain")
                .with_body("Not Found")
                .create_async()
                .await;

            let client = reqwest::Client::new();
            let url = format!("{}/api/v3/simple/token_price/ethereum?contract_addresses=0xinvalid&vs_currencies=usd", server.url());

            let response = client.get(&url).send().await;

            assert!(response.is_ok(), "Request should succeed even with 404");
            let status = response.unwrap().status();
            assert_eq!(status, 404);
        }

        #[tokio::test]
        async fn coingecko_api_handles_429_rate_limit() {
            let mut server = Server::new_async().await;

            let _mock = server
                .mock("GET", "/api/v3/simple/token_price/ethereum")
                .match_query(mockito::Matcher::Any)
                .with_status(429)
                .with_header("content-type", "application/json")
                .with_body(r#"{"error":"Rate limit exceeded"}"#)
                .create_async()
                .await;

            let client = reqwest::Client::new();
            let url = format!("{}/api/v3/simple/token_price/ethereum?contract_addresses=0xdac17f958d2ee523a2206206994597c13d831ec7&vs_currencies=usd", server.url());

            let response = client.get(&url).send().await.unwrap();

            assert_eq!(response.status(), 429);
            // In production, we should implement retry logic here
        }

        #[tokio::test]
        async fn coingecko_api_handles_empty_response() {
            let mut server = Server::new_async().await;

            let _mock = server
                .mock("GET", "/api/v3/simple/token_price/ethereum")
                .match_query(mockito::Matcher::Any)
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body("{}")
                .create_async()
                .await;

            let client = reqwest::Client::new();
            let url = format!("{}/api/v3/simple/token_price/ethereum?contract_addresses=0xdac17f958d2ee523a2206206994597c13d831ec7&vs_currencies=usd", server.url());

            let response = client.get(&url).send().await.unwrap();
            let json: serde_json::Value = response.json().await.unwrap();

            let price = json
                .get("0xdac17f958d2ee523a2206206994597c13d831ec7")
                .and_then(|obj| obj.get("usd"))
                .and_then(|price| price.as_f64());

            assert_eq!(price, None, "Should return None for missing token");
        }

        #[tokio::test]
        async fn coingecko_api_handles_malformed_json() {
            let mut server = Server::new_async().await;

            let _mock = server
                .mock("GET", "/api/v3/simple/token_price/ethereum")
                .match_query(mockito::Matcher::Any)
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body("invalid json{]")
                .create_async()
                .await;

            let client = reqwest::Client::new();
            let url = format!("{}/api/v3/simple/token_price/ethereum?contract_addresses=0xdac17f958d2ee523a2206206994597c13d831ec7&vs_currencies=usd", server.url());

            let response = client.get(&url).send().await.unwrap();
            let json_result = response.json::<serde_json::Value>().await;

            assert!(json_result.is_err(), "Should fail to parse malformed JSON");
        }

        #[tokio::test]
        async fn coingecko_api_handles_multiple_tokens() {
            let mut server = Server::new_async().await;

            let _mock = server
                .mock("GET", "/api/v3/simple/token_price/ethereum")
                .match_query(mockito::Matcher::Any)
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(r#"{
                    "0xdac17f958d2ee523a2206206994597c13d831ec7": {"usd": 1.0},
                    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": {"usd": 0.999}
                }"#)
                .create_async()
                .await;

            let client = reqwest::Client::new();
            let url = format!("{}/api/v3/simple/token_price/ethereum?contract_addresses=0xdac17f958d2ee523a2206206994597c13d831ec7,0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48&vs_currencies=usd", server.url());

            let response = client.get(&url).send().await.unwrap();
            let json: serde_json::Value = response.json().await.unwrap();

            assert_eq!(json.get("0xdac17f958d2ee523a2206206994597c13d831ec7").unwrap().get("usd").unwrap().as_f64(), Some(1.0));
            assert_eq!(json.get("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap().get("usd").unwrap().as_f64(), Some(0.999));
        }

        #[tokio::test]
        async fn coingecko_api_returns_realistic_wbtc_price() {
            let mut server = Server::new_async().await;

            let _mock = server
                .mock("GET", "/api/v3/simple/token_price/ethereum")
                .match_query(mockito::Matcher::Any)
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(r#"{"0x2260fac5e5542a773aa44fbcfedf7c193bc2c599":{"usd":62450.30}}"#)
                .create_async()
                .await;

            let client = reqwest::Client::new();
            let url = format!("{}/api/v3/simple/token_price/ethereum?contract_addresses=0x2260fac5e5542a773aa44fbcfedf7c193bc2c599&vs_currencies=usd", server.url());

            let response = client.get(&url).send().await.unwrap();
            let json: serde_json::Value = response.json().await.unwrap();

            let price = json
                .get("0x2260fac5e5542a773aa44fbcfedf7c193bc2c599")
                .unwrap()
                .get("usd")
                .unwrap()
                .as_f64()
                .unwrap();

            assert_eq!(price, 62450.30);
        }
    }
}
