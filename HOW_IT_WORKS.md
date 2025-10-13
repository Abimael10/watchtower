# How Watchtower Works - Detailed Guide

## What Happens When You Run It

### 1. Startup
```
🏗️ Starting Watchtower
🧪 Running in mock mode
🚀 Starting event monitoring...
```

### 2. Event Processing
```
📥 Processing event: VaultUpdate { vault_id: "vault_001", ratio: 1.18 }
```
**Translation**: Someone's vault has 118% collateral ratio (1000 ÷ 850)

### 3. Rule Check
- Rule: "If ratio < 150%, alert"
- Check: "118% < 150%? YES"
- Decision: "Send critical alert (below 120%)"

### 4. Alert Output
```
🚨 Low Collateralization - CRITICAL - Vault vault_001 has ratio 118.00% (threshold: 150.00%)
```

## Understanding the Numbers

### Collateral Ratios
Think car loan: $15k collateral for $10k loan = 150% ratio

**Alert Levels**:
- **Above 150%**: ✅ Safe
- **120-150%**: ⚠️ Risky  
- **Below 120%**: 🚨 Danger

### Transfer Amounts
- Small ($100): Normal activity
- Large ($100k+): Market-moving events

## Testing Modes

### Mock Mode (Default)
```bash
cargo run
```
- 3 pre-made events
- Instant results
- 6-second demo

### Simulation Mode
```bash
SIMULATION_MODE=true cargo run
```
- Realistic timing
- 3-second delays
- Blockchain-like experience

## Code Structure

**5 Main Parts**:
1. **Events**: VaultUpdate, Transfer, Liquidation
2. **Alerts**: Critical, Warning, Info with emojis
3. **Rules**: Simple if-then logic
4. **Generator**: Creates test events
5. **Notifier**: Displays alerts

## Real Examples

### Dangerous Vault (118% ratio)
**Input**: `VaultUpdate { ratio: 1.18 }`
**Logic**: 118% < 120% = Critical
**Output**: `🚨 Low Collateralization - CRITICAL`
**Meaning**: Liquidation risk

### Large Transfer ($250k)
**Input**: `Transfer { amount: 250000.0 }`
**Logic**: $250k > $100k = Warning
**Output**: `⚠️ Large Transfer Detected`
**Meaning**: Market impact possible

## Learning Path

1. **Run it**: `cargo run` → see alerts
2. **Read code**: Find "PART 3: RULE ENGINE"
3. **Customize**: Change threshold numbers
4. **Extend**: Add new event types

## Key Patterns in Code

```rust
// Rule checking
if *ratio < self.collateral_threshold {
    // Create alert
}

// Alert creation
Alert::critical("Title", "Message")

// Event matching
match event {
    Event::VaultUpdate { ... } => { /* vault rules */ }
    Event::Transfer { ... } => { /* transfer rules */ }
}
```

**Bottom line**: Watch blockchain → Apply rules → Send clear alerts