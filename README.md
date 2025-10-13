# Watchtower

A **security guard for your crypto investments** that watches the blockchain 24/7 and alerts you when important things happen.

## The Problem & Solution

**Problem**: Crypto moves fast while you sleep - collateral drops, large transfers happen, liquidations occur.

**Solution**: Watchtower monitors blockchain events and sends instant alerts with clear explanations.

## Quick Start

```bash
# Test with fake data
cargo run

# Test with realistic timing
SIMULATION_MODE=true cargo run

# Run all tests
./test.sh
```

## Alert Types

### 🚨 Critical (Urgent)
- Collateral below 120% (liquidation risk)
- Any liquidation event

### ⚠️ Warning (Watch)
- Collateral 120-150% (getting risky)
- Transfers over $100,000

### Example Output
```
🚨 Low Collateralization - CRITICAL - Vault vault_001 has ratio 118.00% (threshold: 150.00%)
⚠️ Large Transfer Detected - Transfer of 250000.00 from 0x1234... to 0x5678...
```

## How It Works

1. **Listens** to blockchain events
2. **Applies** simple rules (ratio < 150%, amount > $100k, etc.)
3. **Sends** clear alerts with context

## Configuration

Set environment variables to customize thresholds:

```bash
# .env file
COLLATERAL_THRESHOLD=1.5    # 150% minimum ratio
TRANSFER_THRESHOLD=100000   # $100k transfer alert
SIMULATION_MODE=false       # Use mock or simulation mode
```

## Project Structure

```
watchtower/
├── src/main.rs          # Complete program (one file)
├── Cargo.toml           # Dependencies
├── README.md            # This file
├── HOW_IT_WORKS.md      # Detailed guide
├── test.sh              # Test runner
└── .env.example         # Configuration template
```

## Code Organization

- **Events**: VaultUpdate, Transfer, Liquidation
- **Rules**: Simple if-then logic for alerts
- **Alerts**: Critical, Warning, Info with emojis
- **Testing**: Mock mode (instant) and Simulation mode (realistic)

## Extending

**Add new rules**: Modify the `process_event()` function
**Change thresholds**: Update environment variables
**Add notifications**: Implement new notifier types

## Success Indicators

✅ Tests pass  
✅ Alerts are clear and actionable  
✅ You understand what each alert means  
✅ You can customize thresholds  

**Bottom line**: Get notified only when something important happens, with clear explanations of what it means.
