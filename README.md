# Watchtower

**Real-time whale wallet monitor** - Get instant Telegram alerts when crypto whales move large amounts of tokens with accurate, real-time USD values.

## What It Does

Monitors ERC-20 token transfers from whale wallets (exchanges, funds, large holders) in real-time. Fetches live prices from CoinGecko API and sends alerts only for known valuable tokens.

## Quick Start

```bash
# 1. Configure
cp .env.example .env
nano .env  # Add your RPC URL and wallets to watch

# 2. Run
./run.sh
```

## Setup

### 1. Get Blockchain Access (Free)

Sign up for a free RPC provider:
- [Alchemy](https://alchemy.com) (Recommended)
- [Infura](https://infura.io)
- [QuickNode](https://quicknode.com)

Create an Ethereum Mainnet app and copy the **WebSocket URL** (starts with `wss://`).

### 2. Configure Watchtower

Edit `.env`:

```bash
# Required: Your blockchain WebSocket URL
WS_RPC_URL=wss://eth-mainnet.g.alchemy.com/v2/YOUR-API-KEY

# Required: Whale wallets to monitor (comma-separated)
WATCH_ADDRESSES=0xF977814e90dA44bFA03b6295A0616a897441aceC,0x28C6c06298d514Db089934071355E5743bf21d60

# Optional: Labels for identification (use hyphens, must be quoted)
WALLET_LABELS="0xF977814e90dA44bFA03b6295A0616a897441aceC=Binance-Hot-8,0x28C6c06298d514Db089934071355E5743bf21d60=Binance-Hot-14"

# Optional: Alert threshold (default: $100k)
TRANSFER_THRESHOLD=100000
```

### 3. Telegram Alerts (Optional)

1. Create bot: Message [@BotFather](https://t.me/BotFather) on Telegram → `/newbot`
2. Get chat ID: Message your bot, then visit:
   ```
   https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getUpdates
   ```
   Find `"chat":{"id":123456789}`

3. Add to `.env`:
   ```bash
   TELEGRAM_BOT_TOKEN=123456789:ABCdefGHIjklMNOpqrsTUVwxyz
   TELEGRAM_CHAT_ID=123456789
   ```

## Monitored Tokens

**Only known valuable tokens are monitored** (unknown tokens silently skipped):
- **Stablecoins**: USDT, USDC, DAI
- **Wrapped Assets**: WBTC, WETH
- **DeFi Tokens**: LINK, UNI, AAVE

All prices fetched in real-time from CoinGecko API (free, no API key required).

## Example Output

```
💰 5000.00 USDT @ $1.00 = $5000.00 from Binance-Hot-8 to Unknown
💰 0.5 WBTC @ $62,450.30 = $31,225.15 from Coinbase-Hot-Wallet to Unknown
⚠️ Large Whale Transfer Detected - $250,000.00 USDC transferred from...
```

Telegram notification:
```
⚠️ Large Whale Transfer Detected

$250,000.00 USDC transferred from
0xF97...aceC [Binance-Hot-8] to
0x742...bEb [Unknown]

Time: 2025-10-13 08:30:45 UTC
```

## Finding Whale Wallets

Major exchange hot wallets (very active):
- **Binance**: `0xF977814e90dA44bFA03b6295A0616a897441aceC`
- **Coinbase**: `0x71660c4005BA85c37ccec55d0C4493E66Fe775d3`
- **Kraken**: `0x267be1C1D684F78cb4F6a176C4911b741E4Ffdc0`

Find more on [Etherscan's Top Accounts](https://etherscan.io/accounts).

## Running 24/7

### Option 1: tmux (Recommended)
```bash
tmux new -s watchtower
./run.sh
# Detach: Ctrl+B then D
# Reattach: tmux attach -t watchtower
```

### Option 2: Background Process
```bash
nohup ./run.sh > watchtower.log 2>&1 &
tail -f watchtower.log  # View logs
pkill watchtower        # Stop
```

## Project Structure

```
watchtower/
├── src/main.rs      # Complete application (~350 lines)
├── Cargo.toml       # Dependencies
├── .env.example     # Configuration template
├── .env             # Your configuration (git-ignored)
├── run.sh           # Start script
├── README.md        # This file
```

## How It Works

1. Connects to Ethereum via WebSocket
2. Subscribes to ERC-20 Transfer events from monitored addresses
3. Filters to only known valuable tokens
4. Fetches real-time USD price from CoinGecko API
5. Sends Telegram alert if transfer exceeds threshold

**Simple, accurate, efficient.**

## Troubleshooting

**"WS_RPC_URL not set"**
- Verify `.env` file exists
- Use `./run.sh`, not `cargo run`

**"Failed to connect"**
- Check URL is WebSocket (`wss://` not `https://`)
- Verify API key is valid

**No transfers detected**
- Whale wallets may not be actively trading
- Try lowering `TRANSFER_THRESHOLD` temporarily
- Verify wallet addresses are correct

**Labels not showing**
- `WALLET_LABELS` must be quoted in `.env`
- Use hyphens instead of spaces: `Binance-Hot-Wallet`
- Must use `./run.sh` to load environment properly

**"Skipping transfer - could not fetch real-time price"**
- CoinGecko API rate limit (50 calls/minute on free tier)
- Network connectivity issue
- Transfer will be logged but not alerted

## Cost

**$0** - Everything is free:
- RPC providers offer generous free tiers
- CoinGecko API is free (no key required)
- Telegram is free
- Watchtower is open source

Perfect for personal whale watching.

## Adding New Tokens

Edit `src/main.rs` function `get_token_info()`:

```rust
fn get_token_info(address: &str) -> Option<(&str, u8)> {
    match address.to_lowercase().as_str() {
        "0xYourTokenAddress" => Some(("SYMBOL", decimals)),
        // ... existing tokens
        _ => None,
    }
}
```

Real-time prices are fetched automatically from CoinGecko.
