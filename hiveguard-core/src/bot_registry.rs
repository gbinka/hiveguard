use std::collections::HashMap;
use std::time::Instant;

use serde::{Deserialize, Serialize};

/// Policy for a known bot pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BotPolicy {
    /// Allow — exempt from all detection, never ban.
    Allow,
    /// Block — immediately reject (high severity signal).
    Block,
    /// Monitor — track activity but don't exempt from detection.
    Monitor,
}

/// A known bot pattern definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotRule {
    /// Display name (e.g., "Googlebot", "Bingbot").
    pub name: String,
    /// Substring or pattern to match in User-Agent.
    pub ua_contains: String,
    /// Organization / owner description.
    #[serde(default)]
    pub org: String,
    /// Policy: allow, block, or monitor.
    pub policy: BotPolicy,
}

/// Runtime stats for a detected bot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotStats {
    pub name: String,
    pub org: String,
    pub policy: BotPolicy,
    pub request_count: u64,
    pub last_seen_ip: String,
    pub last_seen_ua: String,
    #[serde(skip)]
    pub first_seen: Option<Instant>,
    #[serde(skip)]
    pub last_seen: Option<Instant>,
}

/// Registry for managing known bots and tracking detected bot activity.
pub struct BotRegistry {
    /// Configured bot rules (from config file).
    rules: Vec<BotRule>,
    /// Runtime stats keyed by rule name.
    stats: HashMap<String, BotStats>,
    /// Unknown bots seen: keyed by a normalized UA prefix.
    unknown_bots: HashMap<String, BotStats>,
}

impl BotRegistry {
    pub fn new(rules: Vec<BotRule>) -> Self {
        let mut stats = HashMap::new();
        for rule in &rules {
            stats.insert(
                rule.name.clone(),
                BotStats {
                    name: rule.name.clone(),
                    org: rule.org.clone(),
                    policy: rule.policy,
                    request_count: 0,
                    last_seen_ip: String::new(),
                    last_seen_ua: String::new(),
                    first_seen: None,
                    last_seen: None,
                },
            );
        }
        Self {
            rules,
            stats,
            unknown_bots: HashMap::new(),
        }
    }

    /// Match an event's User-Agent against known bot rules.
    /// Returns the matching rule's policy, or None if no rule matched.
    pub fn classify(&mut self, user_agent: &str, source_ip: &str) -> Option<BotPolicy> {
        let ua_lower = user_agent.to_lowercase();

        for rule in &self.rules {
            if ua_lower.contains(&rule.ua_contains.to_lowercase()) {
                let stat = self.stats.entry(rule.name.clone()).or_insert_with(|| BotStats {
                    name: rule.name.clone(),
                    org: rule.org.clone(),
                    policy: rule.policy,
                    request_count: 0,
                    last_seen_ip: String::new(),
                    last_seen_ua: String::new(),
                    first_seen: None,
                    last_seen: None,
                });
                stat.request_count += 1;
                stat.last_seen_ip = source_ip.to_string();
                stat.last_seen_ua = user_agent.to_string();
                let now = Instant::now();
                if stat.first_seen.is_none() {
                    stat.first_seen = Some(now);
                }
                stat.last_seen = Some(now);
                return Some(rule.policy);
            }
        }

        // Track unknown bot-like User-Agents (contain "bot", "crawler", "spider", etc.)
        if is_bot_like_ua(&ua_lower) {
            let key = extract_bot_key(&ua_lower);
            let stat = self.unknown_bots.entry(key.clone()).or_insert_with(|| BotStats {
                name: key,
                org: "Unknown".to_string(),
                policy: BotPolicy::Monitor,
                request_count: 0,
                last_seen_ip: String::new(),
                last_seen_ua: String::new(),
                first_seen: None,
                last_seen: None,
            });
            stat.request_count += 1;
            stat.last_seen_ip = source_ip.to_string();
            stat.last_seen_ua = user_agent.to_string();
            let now = Instant::now();
            if stat.first_seen.is_none() {
                stat.first_seen = Some(now);
            }
            stat.last_seen = Some(now);
        }

        None
    }

    /// Get all known bot stats (configured rules).
    pub fn known_stats(&self) -> Vec<&BotStats> {
        self.stats.values().collect()
    }

    /// Get all unknown/discovered bot stats.
    pub fn unknown_stats(&self) -> Vec<&BotStats> {
        self.unknown_bots.values().collect()
    }

    /// Get a combined list of all bot stats for the API.
    pub fn all_stats(&self) -> Vec<BotStatsResponse> {
        let mut result: Vec<BotStatsResponse> = Vec::new();

        for stat in self.stats.values() {
            result.push(BotStatsResponse {
                name: stat.name.clone(),
                org: stat.org.clone(),
                policy: stat.policy,
                request_count: stat.request_count,
                last_seen_ip: stat.last_seen_ip.clone(),
                last_seen_ua: stat.last_seen_ua.clone(),
                known: true,
            });
        }

        for stat in self.unknown_bots.values() {
            result.push(BotStatsResponse {
                name: stat.name.clone(),
                org: stat.org.clone(),
                policy: stat.policy,
                request_count: stat.request_count,
                last_seen_ip: stat.last_seen_ip.clone(),
                last_seen_ua: stat.last_seen_ua.clone(),
                known: false,
            });
        }

        result.sort_by(|a, b| b.request_count.cmp(&a.request_count));
        result
    }

    /// Update a bot rule's policy at runtime.
    pub fn set_policy(&mut self, name: &str, policy: BotPolicy) -> bool {
        for rule in &mut self.rules {
            if rule.name == name {
                rule.policy = policy;
                if let Some(stat) = self.stats.get_mut(name) {
                    stat.policy = policy;
                }
                return true;
            }
        }
        // Check unknown bots
        if let Some(stat) = self.unknown_bots.get_mut(name) {
            stat.policy = policy;
            // Promote to known rules
            self.rules.push(BotRule {
                name: name.to_string(),
                ua_contains: name.to_string(),
                org: stat.org.clone(),
                policy,
            });
            return true;
        }
        false
    }

    /// Get the current rules (for config persistence).
    pub fn rules(&self) -> &[BotRule] {
        &self.rules
    }
}

/// API response for bot stats.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotStatsResponse {
    pub name: String,
    pub org: String,
    pub policy: BotPolicy,
    pub request_count: u64,
    pub last_seen_ip: String,
    pub last_seen_ua: String,
    pub known: bool,
}

/// Check if a User-Agent string looks like a bot/crawler.
fn is_bot_like_ua(ua_lower: &str) -> bool {
    const BOT_INDICATORS: &[&str] = &[
        "bot", "crawler", "spider", "scraper", "fetcher",
        "archiver", "monitor", "checker", "slurp", "scan",
        "http://", "https://", "+http", "compatible;",
    ];
    BOT_INDICATORS.iter().any(|ind| ua_lower.contains(ind))
}

/// Extract a short key from a bot-like UA for grouping.
fn extract_bot_key(ua_lower: &str) -> String {
    // Try to find the bot's identifier name
    // e.g., "Mozilla/5.0 (compatible; Googlebot/2.1; ...)" → "googlebot"
    if let Some(start) = ua_lower.find("compatible;") {
        if let Some(rest) = ua_lower.get(start + 12..) {
            let trimmed = rest.trim_start();
            if let Some(end) = trimmed.find(|c: char| c == '/' || c == ';' || c == ')') {
                return trimmed[..end].trim().to_string();
            }
        }
    }
    // Try "Something/1.0" pattern at the start
    if let Some(slash) = ua_lower.find('/') {
        if slash < 30 {
            return ua_lower[..slash].trim().to_string();
        }
    }
    // Fallback: first 30 chars
    ua_lower.chars().take(30).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_known_bot() {
        let rules = vec![
            BotRule {
                name: "Googlebot".into(),
                ua_contains: "googlebot".into(),
                org: "Google LLC".into(),
                policy: BotPolicy::Allow,
            },
        ];
        let mut reg = BotRegistry::new(rules);
        let policy = reg.classify(
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "66.249.65.1",
        );
        assert_eq!(policy, Some(BotPolicy::Allow));
        assert_eq!(reg.stats["Googlebot"].request_count, 1);
    }

    #[test]
    fn test_classify_unknown_bot() {
        let mut reg = BotRegistry::new(vec![]);
        let policy = reg.classify("SomeNewCrawler/1.0 (http://example.com)", "1.2.3.4");
        assert_eq!(policy, None); // no matching rule
        assert_eq!(reg.unknown_bots.len(), 1); // but tracked as unknown
    }

    #[test]
    fn test_classify_regular_browser() {
        let mut reg = BotRegistry::new(vec![]);
        let policy = reg.classify(
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "1.2.3.4",
        );
        assert_eq!(policy, None);
        assert!(reg.unknown_bots.is_empty()); // not bot-like
    }

    #[test]
    fn test_set_policy() {
        let rules = vec![
            BotRule {
                name: "Bingbot".into(),
                ua_contains: "bingbot".into(),
                org: "Microsoft".into(),
                policy: BotPolicy::Monitor,
            },
        ];
        let mut reg = BotRegistry::new(rules);
        assert!(reg.set_policy("Bingbot", BotPolicy::Allow));
        assert_eq!(reg.rules[0].policy, BotPolicy::Allow);
    }
}
