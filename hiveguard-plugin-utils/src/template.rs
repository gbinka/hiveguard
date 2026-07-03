use std::collections::HashMap;

/// Substitute `{{key}}` placeholders in `template` with values from `ctx`.
///
/// Unknown placeholders are left as-is — this is intentional, so plugin
/// authors can mix HiveGuard variables with provider-specific syntax
/// (e.g. Slack mentions `<@USER>`).
///
/// Whitespace inside braces is tolerated: `{{ ip }}` works the same as
/// `{{ip}}`.
pub fn render(template: &str, ctx: &HashMap<&'static str, String>) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;

    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find("}}") else {
            out.push_str("{{");
            out.push_str(after);
            return out;
        };
        let key = after[..end].trim();
        match ctx.get(key) {
            Some(value) => out.push_str(value),
            None => {
                // Unknown placeholder — preserve literally.
                out.push_str("{{");
                out.push_str(&after[..end]);
                out.push_str("}}");
            }
        }
        rest = &after[end + 2..];
    }

    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx_with(pairs: &[(&'static str, &str)]) -> HashMap<&'static str, String> {
        pairs.iter().map(|(k, v)| (*k, (*v).to_owned())).collect()
    }

    #[test]
    fn substitutes_known_keys() {
        let ctx = ctx_with(&[("ip", "1.2.3.4"), ("reason", "bruteforce")]);
        assert_eq!(
            render("Banned {{ip}} for {{reason}}", &ctx),
            "Banned 1.2.3.4 for bruteforce"
        );
    }

    #[test]
    fn preserves_unknown_keys() {
        let ctx = ctx_with(&[("ip", "1.2.3.4")]);
        assert_eq!(
            render("ip={{ip}} foo={{foo}}", &ctx),
            "ip=1.2.3.4 foo={{foo}}"
        );
    }

    #[test]
    fn tolerates_whitespace() {
        let ctx = ctx_with(&[("ip", "1.2.3.4")]);
        assert_eq!(render("{{ ip }}", &ctx), "1.2.3.4");
    }

    #[test]
    fn unterminated_brace_kept_literal() {
        let ctx = ctx_with(&[]);
        assert_eq!(render("{{nope", &ctx), "{{nope");
    }

    #[test]
    fn empty_template() {
        assert_eq!(render("", &HashMap::new()), "");
    }
}
