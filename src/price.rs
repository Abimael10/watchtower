use tracing::warn;

pub struct CoinGeckoPriceProvider {
    client: reqwest::Client,
}

impl CoinGeckoPriceProvider {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }

    pub async fn price_usd(&self, token_address: &str) -> Option<f64> {
        let url = format!(
            "https://api.coingecko.com/api/v3/simple/token_price/ethereum?contract_addresses={token_address}&vs_currencies=usd"
        );

        match self.client.get(&url).send().await {
            Ok(response) => {
                if let Ok(json) = response.json::<serde_json::Value>().await {
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
}
