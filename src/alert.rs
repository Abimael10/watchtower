use crate::domain::{Alert, Transfer};

#[derive(Debug, Clone)]
pub struct AlertEngine {
    threshold: f64,
}

impl AlertEngine {
    pub fn new(threshold: f64) -> Self {
        Self { threshold }
    }

    pub fn should_alert(&self, transfer: &Transfer) -> Option<Alert> {
        if transfer.amount > self.threshold {
            Some(Alert::new(
                "Large Whale Transfer Detected",
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

#[cfg(test)]
mod tests {
    use super::AlertEngine;
    use crate::domain::Transfer;
    use chrono::Utc;

    #[test]
    fn triggers_above_threshold() {
        let engine = AlertEngine::new(50_000.0);
        let transfer = Transfer {
            from: "0x123 [Binance]".to_string(),
            to: "0x456 [Unknown]".to_string(),
            amount: 75_000.0,
            token: "USDT".to_string(),
            block_number: 1,
            timestamp: Utc::now(),
        };

        assert!(engine.should_alert(&transfer).is_some());
    }

    #[test]
    fn ignores_below_threshold() {
        let engine = AlertEngine::new(50_000.0);
        let transfer = Transfer {
            from: "0x123 [Binance]".to_string(),
            to: "0x456 [Unknown]".to_string(),
            amount: 25_000.0,
            token: "USDT".to_string(),
            block_number: 1,
            timestamp: Utc::now(),
        };

        assert!(engine.should_alert(&transfer).is_none());
    }

    #[test]
    fn ignores_exactly_at_threshold() {
        let engine = AlertEngine::new(100_000.0);
        let transfer = Transfer {
            from: "0x123 [Binance]".to_string(),
            to: "0x456 [Unknown]".to_string(),
            amount: 100_000.0,
            token: "USDC".to_string(),
            block_number: 1,
            timestamp: Utc::now(),
        };

        assert!(engine.should_alert(&transfer).is_none());
    }
}
