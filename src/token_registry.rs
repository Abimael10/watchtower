#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenInfo {
    pub symbol: &'static str,
    pub decimals: u8,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct TokenRegistry;

impl TokenRegistry {
    pub fn get_token_info(&self, address: &str) -> Option<TokenInfo> {
        match address.to_lowercase().as_str() {
            "0xdac17f958d2ee523a2206206994597c13d831ec7" => Some(TokenInfo {
                symbol: "USDT",
                decimals: 6,
            }),
            "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48" => Some(TokenInfo {
                symbol: "USDC",
                decimals: 6,
            }),
            "0x6b175474e89094c44da98b954eedeac495271d0f" => Some(TokenInfo {
                symbol: "DAI",
                decimals: 18,
            }),
            "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599" => Some(TokenInfo {
                symbol: "WBTC",
                decimals: 8,
            }),
            "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2" => Some(TokenInfo {
                symbol: "WETH",
                decimals: 18,
            }),
            "0x514910771af9ca656af840dff83e8264ecf986ca" => Some(TokenInfo {
                symbol: "LINK",
                decimals: 18,
            }),
            "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984" => Some(TokenInfo {
                symbol: "UNI",
                decimals: 18,
            }),
            "0x7fc66500c84a76ad7e9c93437bfc5ac33e2ddae9" => Some(TokenInfo {
                symbol: "AAVE",
                decimals: 18,
            }),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{TokenInfo, TokenRegistry};

    #[test]
    fn recognizes_known_tokens() {
        let registry = TokenRegistry;
        assert_eq!(
            registry.get_token_info("0xdac17f958d2ee523a2206206994597c13d831ec7"),
            Some(TokenInfo {
                symbol: "USDT",
                decimals: 6
            })
        );
        assert_eq!(
            registry.get_token_info("0x2260fac5e5542a773aa44fbcfedf7c193bc2c599"),
            Some(TokenInfo {
                symbol: "WBTC",
                decimals: 8
            })
        );
    }

    #[test]
    fn is_case_insensitive() {
        let registry = TokenRegistry;
        assert_eq!(
            registry.get_token_info("0xDAC17F958D2EE523A2206206994597C13D831EC7"),
            Some(TokenInfo {
                symbol: "USDT",
                decimals: 6
            })
        );
    }

    #[test]
    fn rejects_unknown_tokens() {
        let registry = TokenRegistry;
        assert_eq!(registry.get_token_info("0x0000000000000000000000000000000000000000"), None);
    }
}
