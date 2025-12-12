use crate::config::AppConfig;
use crate::domain::Alert;
use anyhow::{anyhow, Result};
use tracing::{info, warn};

#[derive(Debug, Clone)]
pub struct TelegramNotifier {
    bot_token: String,
    chat_id: String,
    client: reqwest::Client,
}

impl TelegramNotifier {
    pub fn new(bot_token: String, chat_id: String) -> Self {
        Self {
            bot_token,
            chat_id,
            client: reqwest::Client::new(),
        }
    }

    pub fn maybe_from_config(config: &AppConfig) -> Option<Self> {
        match (&config.telegram_bot_token, &config.telegram_chat_id) {
            (Some(token), Some(chat_id)) if !token.is_empty() && !chat_id.is_empty() => {
                Some(Self::new(token.clone(), chat_id.clone()))
            }
            _ => None,
        }
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
            Ok(())
        } else {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            warn!("Failed to send Telegram alert: {}", error_text);
            Err(anyhow!("Failed to send Telegram alert"))
        }
    }
}
