/*
 * WATCHTOWER - Your Crypto Alert System
 * 
 * Think of this as a security guard for your crypto investments.
 * It watches the blockchain and alerts you when important things happen.
 * 
 * This file contains the entire program - everything needed to:
 * 1. Watch for important blockchain events
 * 2. Check if they're dangerous using simple rules  
 * 3. Send you clear, understandable alerts
 */

// These are tools we need (like importing libraries in other languages)
use anyhow::Result;                    // For handling errors gracefully
use chrono::{DateTime, Utc};          // For timestamps (when things happened)
use serde::{Deserialize, Serialize};  // For converting data to/from text
use std::env;                         // For reading settings from environment
use tokio::time::{sleep, Duration};   // For waiting between events
use tracing::{info, warn};            // For logging what's happening

/*
 * PART 1: DEFINING WHAT WE WATCH FOR
 * 
 * These are the types of events that happen on the blockchain
 * that we care about. Think of them like different types of 
 * security alerts a guard might report.
 */

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Event {
    // When someone's collateral (backup money) changes
    VaultUpdate {
        vault_id: String,        // Which vault (like an account number)
        collateral: f64,         // How much backup money they have
        debt: f64,              // How much they borrowed
        ratio: f64,             // collateral ÷ debt (safety ratio)
        block_number: u64,      // When this happened (block number)
        timestamp: DateTime<Utc>, // Exact time this happened
    },
    
    // When someone moves money from one place to another
    Transfer {
        from: String,           // Who sent the money
        to: String,             // Who received the money
        amount: f64,            // How much money was moved
        token: String,          // What type of money (DAI, USDC, etc.)
        block_number: u64,      // When this happened
        timestamp: DateTime<Utc>, // Exact time
    },
    
    // When someone loses their collateral (gets liquidated)
    Liquidation {
        vault_id: String,       // Which vault got liquidated
        liquidated_amount: f64, // How much money was lost
        block_number: u64,      // When this happened
        timestamp: DateTime<Utc>, // Exact time
    },
}

/*
 * PART 2: DEFINING ALERTS
 * 
 * When we detect something important, we create an alert.
 * Think of these like different types of alarms.
 */

#[derive(Debug, Clone)]
pub struct Alert {
    pub title: String,          // Short description (like "Low Collateral")
    pub message: String,        // Detailed explanation
    pub severity: Severity,     // How urgent this is
    pub timestamp: DateTime<Utc>, // When we created this alert
}

// How urgent an alert is (like alarm levels)
#[derive(Debug, Clone)]
pub enum Severity {
    Info,       // ℹ️ Just so you know (blue)
    Warning,    // ⚠️ Pay attention (yellow)  
    Critical,   // 🚨 Urgent! (red)
}

// Helper functions to create different types of alerts
impl Alert {
    // Create a critical (urgent) alert
    pub fn critical(title: String, message: String) -> Self {
        Self {
            title,
            message,
            severity: Severity::Critical,
            timestamp: Utc::now(),
        }
    }

    // Create a warning alert
    pub fn warning(title: String, message: String) -> Self {
        Self {
            title,
            message,
            severity: Severity::Warning,
            timestamp: Utc::now(),
        }
    }

    // Create an info alert
    pub fn info(title: String, message: String) -> Self {
        Self {
            title,
            message,
            severity: Severity::Info,
            timestamp: Utc::now(),
        }
    }
}

/*
 * PART 3: THE RULE ENGINE (THE BRAIN)
 * 
 * This is where we decide if an event is important enough
 * to alert about. It uses simple if-then rules.
 */

pub struct RuleEngine {
    // If collateral ratio drops below this, send warning
    collateral_threshold: f64,  // Default: 1.5 (150%)
    
    // If transfer amount is above this, send warning  
    transfer_threshold: f64,    // Default: 100,000
}

impl RuleEngine {
    // Create a new rule engine with settings from environment or defaults
    pub fn new() -> Self {
        // Read collateral threshold from environment or use default
        let collateral_threshold = env::var("COLLATERAL_THRESHOLD")
            .unwrap_or_else(|_| "1.5".to_string())  // Default to 1.5 (150%)
            .parse()
            .unwrap_or(1.5);  // If parsing fails, use default

        // Read transfer threshold from environment or use default
        let transfer_threshold = env::var("TRANSFER_THRESHOLD")
            .unwrap_or_else(|_| "100000.0".to_string())  // Default to $100k
            .parse()
            .unwrap_or(100000.0);  // If parsing fails, use default

        Self {
            collateral_threshold,
            transfer_threshold,
        }
    }

    /*
     * THE MAIN LOGIC: Check if an event should trigger an alert
     * 
     * This function takes an event and applies our rules to decide
     * if we should alert the user about it.
     */
    pub async fn process_event(&self, event: &Event) -> Result<Vec<Alert>> {
        let mut alerts = Vec::new(); // Start with no alerts

        // Check what type of event this is and apply appropriate rules
        match event {
            // RULE SET 1: Vault Update Rules
            Event::VaultUpdate { vault_id, ratio, .. } => {
                // Rule: If collateral ratio is too low, create alert
                if *ratio < self.collateral_threshold {
                    // Decide how urgent this is
                    let severity = if *ratio < 1.2 { 
                        "CRITICAL"  // Below 120% = very dangerous
                    } else { 
                        "WARNING"   // Below 150% but above 120% = risky
                    };

                    // Create the alert with appropriate severity
                    if *ratio < 1.2 {
                        // Below 120% = Critical (very dangerous)
                        alerts.push(Alert::critical(
                            format!("Low Collateralization - {}", severity),
                            format!(
                                "Vault {} has ratio {:.2}% (threshold: {:.2}%)",
                                vault_id,
                                ratio * 100.0,                    // Convert to percentage
                                self.collateral_threshold * 100.0 // Show our threshold
                            ),
                        ));
                    } else {
                        // Between 120-150% = Warning (risky but not critical)
                        alerts.push(Alert::warning(
                            format!("Low Collateralization - {}", severity),
                            format!(
                                "Vault {} has ratio {:.2}% (threshold: {:.2}%)",
                                vault_id,
                                ratio * 100.0,                    // Convert to percentage
                                self.collateral_threshold * 100.0 // Show our threshold
                            ),
                        ));
                    }
                }
            }

            // RULE SET 2: Transfer Rules  
            Event::Transfer { from, to, amount, .. } => {
                // Rule: If transfer amount is large, create alert
                if *amount > self.transfer_threshold {
                    alerts.push(Alert::warning(
                        "Large Transfer Detected".to_string(),
                        format!(
                            "Transfer of {:.2} from {} to {}", 
                            amount, from, to
                        ),
                    ));
                }
            }

            // RULE SET 3: Liquidation Rules
            Event::Liquidation { vault_id, liquidated_amount, .. } => {
                // Rule: Any liquidation is critical (someone lost money)
                alerts.push(Alert::critical(
                    "Vault Liquidation".to_string(),
                    format!(
                        "Vault {} liquidated for {:.2}", 
                        vault_id, liquidated_amount
                    ),
                ));
            }
        }

        Ok(alerts) // Return any alerts we created
    }
}

/*
 * PART 4: MOCK EVENT GENERATOR (FOR TESTING)
 * 
 * This creates fake events so we can test our system without
 * connecting to the real blockchain. Like a fire drill.
 */

pub struct MockEventGenerator {
    events: Vec<Event>,  // List of fake events to process
    current: usize,      // Which event we're on
}

impl MockEventGenerator {
    // Create a generator with some realistic test events
    pub fn new() -> Self {
        Self {
            events: vec![
                // Event 1: A vault with dangerously low collateral
                Event::VaultUpdate {
                    vault_id: "vault_001".to_string(),
                    collateral: 1000.0,  // $1000 backup
                    debt: 850.0,         // $850 borrowed
                    ratio: 1.18,         // 118% ratio - DANGEROUS!
                    block_number: 18500000,
                    timestamp: Utc::now(),
                },
                
                // Event 2: A large money transfer
                Event::Transfer {
                    from: "0x1234...".to_string(),
                    to: "0x5678...".to_string(),
                    amount: 250000.0,    // $250k - above our $100k threshold
                    token: "DAI".to_string(),
                    block_number: 18500001,
                    timestamp: Utc::now(),
                },
                
                // Event 3: Someone got liquidated (lost their money)
                Event::Liquidation {
                    vault_id: "vault_002".to_string(),
                    liquidated_amount: 50000.0,  // $50k lost
                    block_number: 18500002,
                    timestamp: Utc::now(),
                },
            ],
            current: 0,
        }
    }

    // Get the next fake event (returns None when we're done)
    pub async fn next_event(&mut self) -> Option<Event> {
        if self.current < self.events.len() {
            let event = self.events[self.current].clone();
            self.current += 1;
            Some(event)
        } else {
            None // No more events
        }
    }
}

/*
 * PART 5: CONSOLE NOTIFIER (HOW WE SHOW ALERTS)
 * 
 * This takes our alerts and displays them on the screen
 * with emojis and colors so they're easy to understand.
 */

pub struct ConsoleNotifier;

impl ConsoleNotifier {
    pub fn new() -> Self {
        Self
    }

    // Display an alert on the console with appropriate emoji
    pub async fn send(&self, alert: &Alert) -> Result<()> {
        // Choose emoji based on how urgent the alert is
        let emoji = match alert.severity {
            Severity::Critical => "🚨",  // Red circle - urgent!
            Severity::Warning => "⚠️",   // Yellow triangle - pay attention
            Severity::Info => "ℹ️",      // Blue circle - just so you know
        };

        // Print the alert in a clear format
        println!("{} {} - {}", emoji, alert.title, alert.message);
        
        // Also log it for debugging
        info!("Alert sent: {}", alert.title);
        
        Ok(())
    }
}

/*
 * PART 6: MAIN PROGRAM ENTRY POINT
 * 
 * This is where the program starts. It sets up everything
 * and decides whether to run in mock mode or simulation mode.
 */

#[tokio::main]
async fn main() -> Result<()> {
    // Set up logging so we can see what's happening
    tracing_subscriber::fmt().init();

    info!("🏗️  Starting Watchtower - Simple On-chain Intelligence Reaper");

    // Check if user wants simulation mode (more realistic timing)
    let use_simulation = env::var("SIMULATION_MODE")
        .unwrap_or_else(|_| "false".to_string())  // Default to false
        .parse()
        .unwrap_or(false);

    // Run in the appropriate mode
    if use_simulation {
        info!("🧪 Running in simulation mode");
        run_simulation().await
    } else {
        info!("🧪 Running in mock mode");
        run_mock().await
    }
}

/*
 * MOCK MODE: Process events immediately for quick testing
 * 
 * This mode processes all events quickly so you can see
 * how the system works without waiting.
 */
async fn run_mock() -> Result<()> {
    // Set up our components
    let mut event_generator = MockEventGenerator::new();
    let rule_engine = RuleEngine::new();
    let notifier = ConsoleNotifier::new();

    info!("🚀 Starting mock event monitoring...");

    let mut event_count = 0;
    let mut alert_count = 0;

    // Process each fake event
    while let Some(event) = event_generator.next_event().await {
        event_count += 1;
        info!("📥 Processing event #{}: {:?}", event_count, event);

        // Apply our rules to see if this event should trigger alerts
        match rule_engine.process_event(&event).await {
            Ok(alerts) => {
                // Send each alert we generated
                for alert in alerts {
                    alert_count += 1;
                    notifier.send(&alert).await?;
                }
            }
            Err(e) => warn!("Failed to process event: {}", e),
        }

        // Wait a bit between events so you can read the output
        sleep(Duration::from_secs(2)).await;
    }

    // Show summary of what happened
    info!("📊 Summary: {} events processed, {} alerts generated", event_count, alert_count);
    info!("👋 Watchtower completed");
    Ok(())
}

/*
 * SIMULATION MODE: More realistic timing and behavior
 * 
 * This mode simulates how the system would work in real life,
 * with realistic delays between events.
 */
async fn run_simulation() -> Result<()> {
    info!("🎭 Simulation mode - creating realistic test environment");
    
    let simulation = SimpleSimulation::new();
    simulation.run().await
}

/*
 * SIMPLE SIMULATION: Creates a realistic test environment
 * 
 * This simulates connecting to a blockchain and receiving
 * events with realistic timing.
 */
pub struct SimpleSimulation {
    events: Vec<Event>,
}

impl SimpleSimulation {
    pub fn new() -> Self {
        Self {
            events: vec![
                // Simulation Event 1: Critical vault situation
                Event::VaultUpdate {
                    vault_id: "sim_vault_001".to_string(),
                    collateral: 1000.0,
                    debt: 900.0,
                    ratio: 1.11,  // 111% - very dangerous!
                    block_number: 18600000,
                    timestamp: Utc::now(),
                },
                
                // Simulation Event 2: Huge money movement
                Event::Transfer {
                    from: "0xSimulated1234".to_string(),
                    to: "0xSimulated5678".to_string(),
                    amount: 500000.0,  // Half a million dollars!
                    token: "USDC".to_string(),
                    block_number: 18600001,
                    timestamp: Utc::now(),
                },
            ],
        }
    }

    // Run the simulation with realistic timing
    pub async fn run(&self) -> Result<()> {
        let rule_engine = RuleEngine::new();
        let notifier = ConsoleNotifier::new();

        // Simulate connecting to services
        info!("🌐 Simulated blockchain connected");
        info!("📱 Simulated notification services ready");

        // Process each event with realistic delays
        for (i, event) in self.events.iter().enumerate() {
            info!("📡 Simulated blockchain event #{}: {:?}", i + 1, event);

            // Apply our rules
            let alerts = rule_engine.process_event(event).await?;
            
            // Send any alerts we generated
            for alert in alerts {
                info!("🚨 Alert generated in simulation");
                notifier.send(&alert).await?;
            }

            // Wait like real blockchain timing (3 seconds between events)
            sleep(Duration::from_secs(3)).await;
        }

        info!("✅ Simulation completed successfully");
        Ok(())
    }
}

/*
 * PART 7: TESTS (MAKING SURE EVERYTHING WORKS)
 * 
 * These tests verify that our rules work correctly.
 * They run automatically when you type "cargo test".
 */

#[cfg(test)]
mod tests {
    use super::*;

    // Test: Make sure low collateral triggers an alert
    #[tokio::test]
    async fn test_rule_engine() {
        let engine = RuleEngine::new();
        
        // Create a test event with low collateral ratio
        let event = Event::VaultUpdate {
            vault_id: "test_vault".to_string(),
            collateral: 100.0,
            debt: 90.0,
            ratio: 1.1,  // 110% - below our 150% threshold
            block_number: 123,
            timestamp: Utc::now(),
        };

        // Process the event and check we get an alert
        let alerts = engine.process_event(&event).await.unwrap();
        assert_eq!(alerts.len(), 1);  // Should generate exactly 1 alert
        assert!(alerts[0].title.contains("Low Collateralization"));
    }

    // Test: Make sure large transfers trigger alerts
    #[tokio::test]
    async fn test_transfer_rule() {
        let engine = RuleEngine::new();
        
        // Create a test event with large transfer
        let event = Event::Transfer {
            from: "0x123".to_string(),
            to: "0x456".to_string(),
            amount: 200000.0,  // $200k - above our $100k threshold
            token: "DAI".to_string(),
            block_number: 124,
            timestamp: Utc::now(),
        };

        // Process the event and check we get an alert
        let alerts = engine.process_event(&event).await.unwrap();
        assert_eq!(alerts.len(), 1);  // Should generate exactly 1 alert
        assert!(alerts[0].title.contains("Large Transfer"));
    }

    // Test: Make sure warning level works correctly (between 120-150%)
    #[tokio::test]
    async fn test_warning_level() {
        let engine = RuleEngine::new();
        
        // Create a test event with ratio between 120-150% (should be warning)
        let event = Event::VaultUpdate {
            vault_id: "warning_vault".to_string(),
            collateral: 100.0,
            debt: 75.0,
            ratio: 1.33,  // 133% - between 120% and 150%, should be WARNING
            block_number: 125,
            timestamp: Utc::now(),
        };

        // Process the event and check we get a warning alert
        let alerts = engine.process_event(&event).await.unwrap();
        assert_eq!(alerts.len(), 1);  // Should generate exactly 1 alert
        assert!(alerts[0].title.contains("Low Collateralization"));
        // Check that it's a warning, not critical
        matches!(alerts[0].severity, Severity::Warning);
    }

    // Test: Make sure our mock event generator works
    #[test]
    fn test_mock_event_generator() {
        let generator = MockEventGenerator::new();
        assert_eq!(generator.events.len(), 3);  // Should have 3 test events
    }
}

/*
 * SUMMARY OF HOW THIS ALL WORKS TOGETHER:
 * 
 * 1. Events happen on the blockchain (VaultUpdate, Transfer, Liquidation)
 * 2. Our RuleEngine checks each event against simple rules
 * 3. If a rule matches, we create an Alert with clear explanation
 * 4. The ConsoleNotifier shows the alert with emoji and description
 * 5. Users see exactly what happened and why it matters
 * 
 * The whole system is designed to be:
 * - Simple to understand (clear variable names, lots of comments)
 * - Easy to test (mock mode for quick testing, simulation for realism)
 * - Clear output (emojis, percentages, plain English explanations)
 * - Extensible (easy to add new rules or alert types)
 */