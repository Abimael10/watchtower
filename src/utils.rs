pub fn mask_url(url: &str) -> String {
    if let Some(scheme_end) = url.find("://") {
        let scheme = &url[..scheme_end + 3];
        if let Some(host_end) = url[scheme_end + 3..].find('/') {
            let host = &url[scheme_end + 3..scheme_end + 3 + host_end];
            return format!("{scheme}{host}/***/");
        }
    }
    "***".to_string()
}

#[cfg(test)]
mod tests {
    use super::mask_url;

    #[test]
    fn masks_ws_urls() {
        let url = "wss://eth-mainnet.g.alchemy.com/v2/SECRET";
        let masked = mask_url(url);
        assert_eq!(masked, "wss://eth-mainnet.g.alchemy.com/***/");
        assert!(!masked.contains("SECRET"));
    }

    #[test]
    fn masks_http_urls() {
        let url = "http://localhost:8545/api-key-12345";
        let masked = mask_url(url);
        assert_eq!(masked, "http://localhost:8545/***/");
    }

    #[test]
    fn returns_generic_for_invalid_url() {
        let url = "not-a-valid-url";
        let masked = mask_url(url);
        assert_eq!(masked, "***");
    }
}
