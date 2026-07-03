//! Sigma condition expression parser and evaluator.
//!
//! ## Grammar (simplified)
//!
//! ```text
//! condition   = or_expr
//! or_expr     = and_expr ( OR and_expr )*
//! and_expr    = not_expr ( AND not_expr )*
//! not_expr    = NOT not_expr | primary
//! primary     = '(' condition ')'
//!             | ALL OF selection_pattern
//!             | INTEGER OF selection_pattern
//!             | COUNT '(' [field] ')' [BY field] compare_op INTEGER
//!             | IDENT
//! selection_pattern = THEM | IDENT (may end with '*')
//! compare_op  = '>' | '>=' | '<' | '<=' | '='
//! ```

use std::collections::{HashMap, HashSet};

use crate::error::{Result, SigmaError};
use crate::selection::SigmaSelection;
use crate::fieldmap::FieldMapper;
use hiveguard_core::models::NormalizedEvent;

// ---------------------------------------------------------------------------
// Tokenizer
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Token {
    /// Identifier — selection name or keyword (may include trailing `*`).
    Ident(String),
    And,
    Or,
    Not,
    LParen,
    RParen,
    /// `of` keyword.
    Of,
    /// `them` keyword.
    Them,
    /// `all` keyword.
    All,
    /// `count` keyword.
    Count,
    /// `by` keyword.
    By,
    Integer(u64),
    /// `|` pipe (used in some Sigma conditions for pipes — treated as `AND` here).
    Pipe,
    Gt,
    Gte,
    Lt,
    Lte,
    Eq,
}

fn tokenize(input: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut chars = input.chars().peekable();

    while let Some(&c) = chars.peek() {
        match c {
            ' ' | '\t' | '\n' | '\r' => {
                chars.next();
            }
            '(' => {
                chars.next();
                tokens.push(Token::LParen);
            }
            ')' => {
                chars.next();
                tokens.push(Token::RParen);
            }
            '|' => {
                chars.next();
                tokens.push(Token::Pipe);
            }
            '>' => {
                chars.next();
                if chars.peek() == Some(&'=') {
                    chars.next();
                    tokens.push(Token::Gte);
                } else {
                    tokens.push(Token::Gt);
                }
            }
            '<' => {
                chars.next();
                if chars.peek() == Some(&'=') {
                    chars.next();
                    tokens.push(Token::Lte);
                } else {
                    tokens.push(Token::Lt);
                }
            }
            '=' => {
                chars.next();
                tokens.push(Token::Eq);
            }
            '0'..='9' => {
                let mut num = String::new();
                while chars.peek().map_or(false, |c| c.is_ascii_digit()) {
                    num.push(chars.next().unwrap());
                }
                if let Ok(n) = num.parse::<u64>() {
                    tokens.push(Token::Integer(n));
                }
            }
            c if c.is_alphabetic() || c == '_' => {
                let mut ident = String::new();
                while chars
                    .peek()
                    .map_or(false, |c| c.is_alphanumeric() || *c == '_' || *c == '*' || *c == '.')
                {
                    ident.push(chars.next().unwrap());
                }
                match ident.to_lowercase().as_str() {
                    "and" => tokens.push(Token::And),
                    "or" => tokens.push(Token::Or),
                    "not" => tokens.push(Token::Not),
                    "of" => tokens.push(Token::Of),
                    "them" => tokens.push(Token::Them),
                    "all" => tokens.push(Token::All),
                    "count" => tokens.push(Token::Count),
                    "by" => tokens.push(Token::By),
                    _ => tokens.push(Token::Ident(ident)),
                }
            }
            _ => {
                chars.next(); // skip unknown characters
            }
        }
    }

    tokens
}

// ---------------------------------------------------------------------------
// AST
// ---------------------------------------------------------------------------

/// Comparison operator used in count aggregations.
#[derive(Debug, Clone, PartialEq)]
pub enum CompareOp {
    Gt,
    Gte,
    Lt,
    Lte,
    Eq,
}

/// Quantifier in `N of` / `all of` expressions.
#[derive(Debug, Clone, PartialEq)]
pub enum NOfQuantifier {
    /// At least *N* matching selections.
    N(u64),
    /// All matching selections.
    All,
}

/// Selection reference pattern used in `N of <pattern>` expressions.
#[derive(Debug, Clone, PartialEq)]
pub enum SelectionPattern {
    /// Exactly one named selection.
    Named(String),
    /// All selections whose names start with `prefix` (trailing `*` stripped).
    Wildcard(String),
    /// All selections defined in the detection block.
    Them,
}

/// Condition expression AST node.
#[derive(Debug, Clone)]
pub enum ConditionExpr {
    /// Direct reference to a named selection.
    Selection(String),
    /// Logical NOT.
    Not(Box<ConditionExpr>),
    /// Logical AND (short-circuit).
    And(Box<ConditionExpr>, Box<ConditionExpr>),
    /// Logical OR (short-circuit).
    Or(Box<ConditionExpr>, Box<ConditionExpr>),
    /// `N of <pattern>` or `all of <pattern>`.
    NOf {
        n: NOfQuantifier,
        pattern: SelectionPattern,
    },
    /// Count aggregation (`count() > N`).
    /// For Phase 4.1, always evaluates to `true` (full aggregation is Phase 4.2+).
    CountAgg {
        field: Option<String>,
        group_by: Option<String>,
        op: CompareOp,
        value: u64,
    },
}

// ---------------------------------------------------------------------------
// Recursive-descent parser
// ---------------------------------------------------------------------------

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn new(tokens: Vec<Token>) -> Self {
        Parser { tokens, pos: 0 }
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn next(&mut self) -> Option<Token> {
        let t = self.tokens.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    fn expect(&mut self, expected: &Token) -> Result<()> {
        match self.next() {
            Some(ref t) if t == expected => Ok(()),
            Some(t) => Err(SigmaError::InvalidCondition(format!(
                "expected {expected:?}, got {t:?}"
            ))),
            None => Err(SigmaError::InvalidCondition(format!(
                "expected {expected:?}, got EOF"
            ))),
        }
    }

    fn parse_condition(&mut self) -> Result<ConditionExpr> {
        self.parse_or()
    }

    fn parse_or(&mut self) -> Result<ConditionExpr> {
        let mut left = self.parse_and()?;
        while self.peek() == Some(&Token::Or) {
            self.next();
            let right = self.parse_and()?;
            left = ConditionExpr::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<ConditionExpr> {
        let mut left = self.parse_not()?;
        // AND can be explicit (`and`) or implicit (Sigma pipe `|`).
        while matches!(self.peek(), Some(Token::And) | Some(Token::Pipe)) {
            self.next();
            let right = self.parse_not()?;
            left = ConditionExpr::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_not(&mut self) -> Result<ConditionExpr> {
        if self.peek() == Some(&Token::Not) {
            self.next();
            let inner = self.parse_not()?;
            return Ok(ConditionExpr::Not(Box::new(inner)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<ConditionExpr> {
        match self.peek().cloned() {
            Some(Token::LParen) => {
                self.next();
                let expr = self.parse_condition()?;
                self.expect(&Token::RParen)?;
                Ok(expr)
            }

            Some(Token::Count) => self.parse_count_agg(),

            Some(Token::All) => {
                self.next();
                self.expect(&Token::Of)?;
                let pattern = self.parse_selection_pattern()?;
                Ok(ConditionExpr::NOf {
                    n: NOfQuantifier::All,
                    pattern,
                })
            }

            Some(Token::Integer(n)) => {
                self.next();
                self.expect(&Token::Of)?;
                let pattern = self.parse_selection_pattern()?;
                Ok(ConditionExpr::NOf {
                    n: NOfQuantifier::N(n),
                    pattern,
                })
            }

            Some(Token::Ident(name)) => {
                self.next();
                Ok(ConditionExpr::Selection(name))
            }

            Some(t) => Err(SigmaError::InvalidCondition(format!(
                "unexpected token {t:?} at position {}",
                self.pos
            ))),

            None => Err(SigmaError::InvalidCondition(
                "unexpected end of condition expression".to_string(),
            )),
        }
    }

    fn parse_selection_pattern(&mut self) -> Result<SelectionPattern> {
        match self.peek().cloned() {
            Some(Token::Them) => {
                self.next();
                Ok(SelectionPattern::Them)
            }
            Some(Token::Ident(name)) => {
                self.next();
                if name.ends_with('*') {
                    let prefix = name.trim_end_matches('*').to_string();
                    Ok(SelectionPattern::Wildcard(prefix))
                } else {
                    Ok(SelectionPattern::Named(name))
                }
            }
            Some(t) => Err(SigmaError::InvalidCondition(format!(
                "expected selection pattern (name or 'them'), got {t:?}"
            ))),
            None => Err(SigmaError::InvalidCondition(
                "expected selection pattern, got EOF".to_string(),
            )),
        }
    }

    fn parse_count_agg(&mut self) -> Result<ConditionExpr> {
        self.next(); // consume `count`
        self.expect(&Token::LParen)?;

        let field = match self.peek().cloned() {
            Some(Token::Ident(f)) => {
                self.next();
                Some(f)
            }
            _ => None,
        };

        self.expect(&Token::RParen)?;

        let group_by = if self.peek() == Some(&Token::By) {
            self.next();
            match self.peek().cloned() {
                Some(Token::Ident(f)) => {
                    self.next();
                    Some(f)
                }
                _ => None,
            }
        } else {
            None
        };

        let op = match self.next() {
            Some(Token::Gt) => CompareOp::Gt,
            Some(Token::Gte) => CompareOp::Gte,
            Some(Token::Lt) => CompareOp::Lt,
            Some(Token::Lte) => CompareOp::Lte,
            Some(Token::Eq) => CompareOp::Eq,
            Some(t) => {
                return Err(SigmaError::InvalidCondition(format!(
                    "expected comparison operator, got {t:?}"
                )))
            }
            None => {
                return Err(SigmaError::InvalidCondition(
                    "expected comparison operator, got EOF".to_string(),
                ))
            }
        };

        let value = match self.next() {
            Some(Token::Integer(n)) => n,
            Some(t) => {
                return Err(SigmaError::InvalidCondition(format!(
                    "expected integer after comparison operator, got {t:?}"
                )))
            }
            None => {
                return Err(SigmaError::InvalidCondition(
                    "expected integer after comparison operator, got EOF".to_string(),
                ))
            }
        };

        Ok(ConditionExpr::CountAgg {
            field,
            group_by,
            op,
            value,
        })
    }
}

/// Parse a Sigma condition string into a `ConditionExpr` AST.
pub fn parse_condition(input: &str) -> Result<ConditionExpr> {
    let tokens = tokenize(input);
    let mut parser = Parser::new(tokens);
    let expr = parser.parse_condition()?;
    // Allow trailing tokens (some valid conditions have trailing comments or spaces)
    Ok(expr)
}

// ---------------------------------------------------------------------------
// Evaluator
// ---------------------------------------------------------------------------

/// Evaluate a parsed condition against a set of selection results.
///
/// # Parameters
///
/// - `expr`: the parsed condition AST.
/// - `matched`: set of selection names that matched the current event.
/// - `all_names`: set of **all** selection names defined in the detection block
///   (needed for `N of them` / `all of them` counting).
pub fn evaluate_condition(
    expr: &ConditionExpr,
    matched: &HashSet<String>,
    all_names: &HashSet<String>,
) -> bool {
    match expr {
        ConditionExpr::Selection(name) => matched.contains(name.as_str()),

        ConditionExpr::Not(inner) => !evaluate_condition(inner, matched, all_names),

        ConditionExpr::And(l, r) => {
            evaluate_condition(l, matched, all_names)
                && evaluate_condition(r, matched, all_names)
        }

        ConditionExpr::Or(l, r) => {
            evaluate_condition(l, matched, all_names)
                || evaluate_condition(r, matched, all_names)
        }

        ConditionExpr::NOf { n, pattern } => {
            // Count how many selections matching the pattern also appear in `matched`.
            let candidate_count: usize = all_names
                .iter()
                .filter(|name| selection_pattern_matches(pattern, name))
                .count();

            let matching_count: usize = all_names
                .iter()
                .filter(|name| {
                    selection_pattern_matches(pattern, name) && matched.contains(name.as_str())
                })
                .count();

            match n {
                NOfQuantifier::All => matching_count == candidate_count && candidate_count > 0,
                NOfQuantifier::N(required) => matching_count >= *required as usize,
            }
        }

        ConditionExpr::CountAgg { .. } => {
            // Count aggregations require temporal accumulation of events.
            // Phase 4.1 does not implement aggregation — always true as a safe default.
            true
        }
    }
}

fn selection_pattern_matches(pattern: &SelectionPattern, name: &str) -> bool {
    match pattern {
        SelectionPattern::Named(n) => n == name,
        SelectionPattern::Wildcard(prefix) => name.starts_with(prefix.as_str()),
        SelectionPattern::Them => true,
    }
}

// ---------------------------------------------------------------------------
// High-level helper: evaluate a full detection block against an event
// ---------------------------------------------------------------------------

/// Evaluate a complete detection block (selections map + condition) against an event.
///
/// Returns `true` if the event matches the detection.
pub fn evaluate_detection(
    condition_str: &str,
    selections: &HashMap<String, SigmaSelection>,
    event: &NormalizedEvent,
    mapper: &FieldMapper,
) -> crate::error::Result<bool> {
    let expr = parse_condition(condition_str)?;

    let all_names: HashSet<String> = selections.keys().cloned().collect();

    let matched: HashSet<String> = selections
        .iter()
        .filter(|(_, sel)| sel.matches(event, mapper))
        .map(|(name, _)| name.clone())
        .collect();

    Ok(evaluate_condition(&expr, &matched, &all_names))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn matched(names: &[&str]) -> HashSet<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    fn all(names: &[&str]) -> HashSet<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    // ── parse_condition ───────────────────────────────────────────────────

    #[test]
    fn parse_simple_ident() {
        let expr = parse_condition("selection").unwrap();
        assert!(matches!(expr, ConditionExpr::Selection(ref s) if s == "selection"));
    }

    #[test]
    fn parse_not_ident() {
        let expr = parse_condition("not filter").unwrap();
        assert!(matches!(expr, ConditionExpr::Not(_)));
    }

    #[test]
    fn parse_and_expression() {
        let expr = parse_condition("selection and not filter").unwrap();
        assert!(matches!(expr, ConditionExpr::And(_, _)));
    }

    #[test]
    fn parse_or_expression() {
        let expr = parse_condition("selection1 or selection2").unwrap();
        assert!(matches!(expr, ConditionExpr::Or(_, _)));
    }

    #[test]
    fn parse_parentheses() {
        let expr = parse_condition("(selection1 or selection2) and not filter").unwrap();
        assert!(matches!(expr, ConditionExpr::And(_, _)));
    }

    #[test]
    fn parse_1_of_wildcard() {
        let expr = parse_condition("1 of selection*").unwrap();
        assert!(matches!(
            expr,
            ConditionExpr::NOf {
                n: NOfQuantifier::N(1),
                pattern: SelectionPattern::Wildcard(_)
            }
        ));
    }

    #[test]
    fn parse_all_of_them() {
        let expr = parse_condition("all of them").unwrap();
        assert!(matches!(
            expr,
            ConditionExpr::NOf {
                n: NOfQuantifier::All,
                pattern: SelectionPattern::Them
            }
        ));
    }

    #[test]
    fn parse_count_agg() {
        let expr = parse_condition("count() > 5").unwrap();
        assert!(matches!(
            expr,
            ConditionExpr::CountAgg {
                field: None,
                op: CompareOp::Gt,
                value: 5,
                ..
            }
        ));
    }

    #[test]
    fn parse_count_agg_by_field() {
        let expr = parse_condition("count(src_ip) by dst_port > 10").unwrap();
        assert!(matches!(
            expr,
            ConditionExpr::CountAgg {
                field: Some(_),
                group_by: Some(_),
                op: CompareOp::Gt,
                value: 10,
                ..
            }
        ));
    }

    #[test]
    fn parse_invalid_condition_fails() {
        assert!(parse_condition("(selection").is_err());
    }

    // ── evaluate_condition ────────────────────────────────────────────────

    #[test]
    fn eval_simple_match() {
        let expr = parse_condition("selection").unwrap();
        assert!(evaluate_condition(
            &expr,
            &matched(&["selection"]),
            &all(&["selection"])
        ));
    }

    #[test]
    fn eval_simple_no_match() {
        let expr = parse_condition("selection").unwrap();
        assert!(!evaluate_condition(
            &expr,
            &matched(&[]),
            &all(&["selection"])
        ));
    }

    #[test]
    fn eval_not() {
        let expr = parse_condition("not filter").unwrap();
        // filter not matched → NOT(false) = true
        assert!(evaluate_condition(&expr, &matched(&[]), &all(&["filter"])));
        // filter matched → NOT(true) = false
        assert!(!evaluate_condition(
            &expr,
            &matched(&["filter"]),
            &all(&["filter"])
        ));
    }

    #[test]
    fn eval_and() {
        let expr = parse_condition("selection and not filter").unwrap();
        assert!(evaluate_condition(
            &expr,
            &matched(&["selection"]),
            &all(&["selection", "filter"])
        ));
        assert!(!evaluate_condition(
            &expr,
            &matched(&["selection", "filter"]),
            &all(&["selection", "filter"])
        ));
    }

    #[test]
    fn eval_or() {
        let expr = parse_condition("sel1 or sel2").unwrap();
        assert!(evaluate_condition(
            &expr,
            &matched(&["sel1"]),
            &all(&["sel1", "sel2"])
        ));
        assert!(evaluate_condition(
            &expr,
            &matched(&["sel2"]),
            &all(&["sel1", "sel2"])
        ));
        assert!(!evaluate_condition(
            &expr,
            &matched(&[]),
            &all(&["sel1", "sel2"])
        ));
    }

    #[test]
    fn eval_1_of_wildcard() {
        let expr = parse_condition("1 of sel*").unwrap();
        let names = all(&["sel_a", "sel_b", "filter"]);
        // One matching wildcard selection → should pass.
        assert!(evaluate_condition(&expr, &matched(&["sel_a"]), &names));
        // None matched → fail.
        assert!(!evaluate_condition(&expr, &matched(&[]), &names));
    }

    #[test]
    fn eval_all_of_them() {
        let expr = parse_condition("all of them").unwrap();
        let names = all(&["s1", "s2", "s3"]);
        assert!(evaluate_condition(
            &expr,
            &matched(&["s1", "s2", "s3"]),
            &names
        ));
        assert!(!evaluate_condition(&expr, &matched(&["s1", "s2"]), &names));
    }

    #[test]
    fn eval_2_of_wildcard() {
        let expr = parse_condition("2 of sel*").unwrap();
        let names = all(&["sel_a", "sel_b", "sel_c"]);
        assert!(!evaluate_condition(&expr, &matched(&["sel_a"]), &names));
        assert!(evaluate_condition(
            &expr,
            &matched(&["sel_a", "sel_b"]),
            &names
        ));
    }

    #[test]
    fn eval_count_agg_always_true() {
        let expr = parse_condition("count() > 100").unwrap();
        // Phase 4.1: count aggregations always return true.
        assert!(evaluate_condition(&expr, &matched(&[]), &all(&[])));
    }

    #[test]
    fn eval_complex_expression() {
        // (sel1 or sel2) and not filter
        let expr = parse_condition("(sel1 or sel2) and not filter").unwrap();
        let names = all(&["sel1", "sel2", "filter"]);
        assert!(evaluate_condition(&expr, &matched(&["sel1"]), &names));
        assert!(evaluate_condition(&expr, &matched(&["sel2"]), &names));
        assert!(!evaluate_condition(
            &expr,
            &matched(&["sel1", "filter"]),
            &names
        ));
    }

    #[test]
    fn tokenizer_handles_special_chars() {
        // Make sure the tokenizer doesn't panic on edge input.
        let _ = tokenize("!@#$%^&");
        let _ = tokenize("selection\t\nand\nfilter");
    }
}
