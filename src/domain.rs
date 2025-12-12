use chrono::{DateTime, Utc};

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
    pub fn new(title: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            message: message.into(),
            timestamp: Utc::now(),
        }
    }
}
