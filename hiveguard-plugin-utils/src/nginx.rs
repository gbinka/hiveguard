//! nginx access-log helpers shared by `source-file` and `source-syslog`.

/// Extract the virtual host from the text that follows the `combined` part
/// of an nginx access-log line.
///
/// Many deployments append `"$host"` (or `"$server_name"`) as the **last**
/// quoted field, e.g.
/// `... "GET /x HTTP/1.1" 200 5 "-" "UA" "site-a.example.org"`. `rest` is the part of
/// the line after the user-agent field. Returns `None` when there is no
/// trailing quoted field or it does not look like a host name (empty, `-`,
/// whitespace inside, longer than 253 bytes).
pub fn trailing_vhost(rest: &str) -> Option<String> {
    let rest = rest.trim_end();
    let body = rest.strip_suffix('"')?;
    let start = body.rfind('"')?;
    let host = &body[start + 1..];
    if host.is_empty()
        || host == "-"
        || host.len() > 253
        || host.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return None;
    }
    Some(host.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_last_quoted_field() {
        assert_eq!(
            trailing_vhost(r#" "site-a.example.org""#).as_deref(),
            Some("site-a.example.org")
        );
        assert_eq!(
            trailing_vhost(r#" "x" "Shop.Example.ORG"  "#).as_deref(),
            Some("shop.example.org")
        );
        assert_eq!(trailing_vhost(r#" 0.123 "a.b""#).as_deref(), Some("a.b"));
    }

    #[test]
    fn rejects_missing_or_bogus() {
        assert!(trailing_vhost("").is_none());
        assert!(trailing_vhost(" 0.123").is_none());
        assert!(trailing_vhost(r#" "-""#).is_none());
        assert!(trailing_vhost(r#" """#).is_none());
        assert!(trailing_vhost(r#" "a b""#).is_none());
    }
}
