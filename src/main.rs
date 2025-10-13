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
                Some((parts[0].trim().to_lowercase(), parts[1].trim().to_string()))
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
