use crate::{
    MetadataAccessPlan, MetadataError, ResolvedMetadataProjection, resolve_skb_metadata,
    resolve_xdp_metadata,
};
use skbx_contract::MetadataEncoding;
use std::path::Path;
use thiserror::Error;

pub const MAX_SKB_FILTER_CONDITIONS: usize = 4;
const MAX_SKB_FILTER_EXPRESSION_BYTES: usize = 4096;
const MAX_SKB_FILTER_NESTING: usize = 16;
type MetadataResolver =
    fn(&[String], Option<&Path>) -> Result<Vec<ResolvedMetadataProjection>, MetadataError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScalarComparison {
    Equal,
    NotEqual,
    Less,
    LessOrEqual,
    Greater,
    GreaterOrEqual,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedSkbFilterCondition {
    pub access: MetadataAccessPlan,
    pub comparison: ScalarComparison,
    pub value: u64,
    pub signed: bool,
    pub group: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedSkbFilter {
    pub source: String,
    pub conditions: Vec<ResolvedSkbFilterCondition>,
}

#[derive(Debug, Error)]
pub enum SkbFilterError {
    #[error(
        "scalar filter supports at most {MAX_SKB_FILTER_CONDITIONS} comparisons after bounded boolean expansion"
    )]
    TooMany,
    #[error("invalid scalar filter expression {expression:?}: {reason}")]
    Invalid { expression: String, reason: String },
    #[error(transparent)]
    Metadata(#[from] MetadataError),
}

pub fn resolve_skb_filter(
    expression: Option<&str>,
    btf_path: Option<&Path>,
) -> Result<Option<ResolvedSkbFilter>, SkbFilterError> {
    resolve_scalar_filter(expression, btf_path, resolve_skb_metadata)
}

pub fn resolve_xdp_filter(
    expression: Option<&str>,
    btf_path: Option<&Path>,
) -> Result<Option<ResolvedSkbFilter>, SkbFilterError> {
    resolve_scalar_filter(expression, btf_path, resolve_xdp_metadata)
}

fn resolve_scalar_filter(
    expression: Option<&str>,
    btf_path: Option<&Path>,
    resolve_metadata: MetadataResolver,
) -> Result<Option<ResolvedSkbFilter>, SkbFilterError> {
    let Some(source) = expression.filter(|value| !value.trim().is_empty()) else {
        return Ok(None);
    };
    if source.len() > MAX_SKB_FILTER_EXPRESSION_BYTES {
        return Err(invalid(
            source,
            format!("expression exceeds the {MAX_SKB_FILTER_EXPRESSION_BYTES}-byte parser bound"),
        ));
    }
    let expression = BooleanParser::new(source).parse()?;
    let groups = bounded_dnf(expression)?;
    if groups.iter().map(Vec::len).sum::<usize>() > MAX_SKB_FILTER_CONDITIONS {
        return Err(SkbFilterError::TooMany);
    }

    let parsed = groups
        .iter()
        .enumerate()
        .flat_map(|(group, clauses)| {
            clauses
                .iter()
                .map(move |clause| (group as u8, parse_clause(source, clause)))
        })
        .map(|(group, parsed)| parsed.map(|parsed| (group, parsed)))
        .collect::<Result<Vec<_>, _>>()?;
    let paths: Vec<String> = parsed
        .iter()
        .map(|(_, (path, _, _))| path.clone())
        .collect();
    let projections = resolve_metadata(&paths, btf_path)?;
    let mut conditions = Vec::with_capacity(parsed.len());
    for ((group, (_, comparison, literal)), projection) in parsed.into_iter().zip(projections) {
        let (value, signed) = parse_literal(
            source,
            &literal,
            projection.descriptor.encoding,
            projection.descriptor.size,
        )?;
        conditions.push(ResolvedSkbFilterCondition {
            access: projection.access,
            comparison,
            value,
            signed,
            group,
        });
    }
    Ok(Some(ResolvedSkbFilter {
        source: source.into(),
        conditions,
    }))
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum BooleanExpression {
    Clause(String),
    And(Box<Self>, Box<Self>),
    Or(Box<Self>, Box<Self>),
}

struct BooleanParser<'a> {
    source: &'a str,
    cursor: usize,
    clauses: usize,
    nesting: usize,
}

impl<'a> BooleanParser<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            source,
            cursor: 0,
            clauses: 0,
            nesting: 0,
        }
    }

    fn parse(mut self) -> Result<BooleanExpression, SkbFilterError> {
        let expression = self.parse_or()?;
        self.skip_whitespace();
        if self.cursor != self.source.len() {
            return Err(invalid(
                self.source,
                format!("unexpected syntax at {:?}", &self.source[self.cursor..]),
            ));
        }
        Ok(expression)
    }

    fn parse_or(&mut self) -> Result<BooleanExpression, SkbFilterError> {
        let mut expression = self.parse_and()?;
        while self.consume("||") {
            expression = BooleanExpression::Or(Box::new(expression), Box::new(self.parse_and()?));
        }
        Ok(expression)
    }

    fn parse_and(&mut self) -> Result<BooleanExpression, SkbFilterError> {
        let mut expression = self.parse_primary()?;
        while self.consume("&&") {
            expression =
                BooleanExpression::And(Box::new(expression), Box::new(self.parse_primary()?));
        }
        Ok(expression)
    }

    fn parse_primary(&mut self) -> Result<BooleanExpression, SkbFilterError> {
        self.skip_whitespace();
        if self.consume("(") {
            if self.nesting >= MAX_SKB_FILTER_NESTING {
                return Err(invalid(
                    self.source,
                    format!("parentheses exceed the {MAX_SKB_FILTER_NESTING}-level nesting bound"),
                ));
            }
            self.nesting += 1;
            let expression = self.parse_or()?;
            self.nesting -= 1;
            if !self.consume(")") {
                return Err(invalid(self.source, "missing closing parenthesis"));
            }
            return Ok(expression);
        }

        let start = self.cursor;
        while self.cursor < self.source.len() {
            let remainder = &self.source[self.cursor..];
            if remainder.starts_with("&&")
                || remainder.starts_with("||")
                || remainder.starts_with(')')
            {
                break;
            }
            let character = remainder
                .chars()
                .next()
                .expect("cursor is inside source bounds");
            self.cursor += character.len_utf8();
        }
        let clause = self.source[start..self.cursor].trim();
        if clause.is_empty() {
            return Err(invalid(
                self.source,
                "every boolean operand must be a comparison",
            ));
        }
        self.clauses += 1;
        if self.clauses > MAX_SKB_FILTER_CONDITIONS {
            return Err(SkbFilterError::TooMany);
        }
        Ok(BooleanExpression::Clause(clause.into()))
    }

    fn consume(&mut self, token: &str) -> bool {
        self.skip_whitespace();
        if self.source[self.cursor..].starts_with(token) {
            self.cursor += token.len();
            true
        } else {
            false
        }
    }

    fn skip_whitespace(&mut self) {
        while let Some(character) = self.source[self.cursor..].chars().next() {
            if !character.is_whitespace() {
                break;
            }
            self.cursor += character.len_utf8();
        }
    }
}

fn bounded_dnf(expression: BooleanExpression) -> Result<Vec<Vec<String>>, SkbFilterError> {
    let groups = match expression {
        BooleanExpression::Clause(clause) => vec![vec![clause]],
        BooleanExpression::Or(left, right) => {
            let mut groups = bounded_dnf(*left)?;
            groups.extend(bounded_dnf(*right)?);
            groups
        }
        BooleanExpression::And(left, right) => {
            let left = bounded_dnf(*left)?;
            let right = bounded_dnf(*right)?;
            let mut groups = Vec::new();
            for left_group in left {
                for right_group in &right {
                    let mut group = left_group.clone();
                    group.extend(right_group.iter().cloned());
                    groups.push(group);
                }
            }
            groups
        }
    };
    if groups.iter().map(Vec::len).sum::<usize>() > MAX_SKB_FILTER_CONDITIONS {
        return Err(SkbFilterError::TooMany);
    }
    Ok(groups)
}

fn parse_clause(
    expression: &str,
    clause: &str,
) -> Result<(String, ScalarComparison, String), SkbFilterError> {
    let operators = [
        ("==", ScalarComparison::Equal),
        ("!=", ScalarComparison::NotEqual),
        ("<=", ScalarComparison::LessOrEqual),
        (">=", ScalarComparison::GreaterOrEqual),
        ("<", ScalarComparison::Less),
        (">", ScalarComparison::Greater),
    ];
    let Some((operator, comparison, position)) =
        clause.char_indices().find_map(|(position, character)| {
            let remainder = &clause[position..];
            operators.iter().find_map(|(token, comparison)| {
                if !remainder.starts_with(token) {
                    return None;
                }
                // `>` is part of every `skb->field` path, not a comparison.
                if *token == ">" && character == '>' && clause[..position].ends_with('-') {
                    return None;
                }
                Some((*token, *comparison, position))
            })
        })
    else {
        return Err(invalid(
            expression,
            format!("condition {clause:?} has no supported comparison operator"),
        ));
    };
    let path = clause[..position].trim();
    let literal = clause[position + operator.len()..].trim();
    if path.is_empty() || literal.is_empty() {
        return Err(invalid(
            expression,
            format!("condition {clause:?} requires a field and literal"),
        ));
    }
    if literal.chars().any(char::is_whitespace)
        || operators.iter().any(|(token, _)| literal.contains(token))
    {
        return Err(invalid(
            expression,
            format!("literal {literal:?} contains unsupported syntax"),
        ));
    }
    Ok((path.into(), comparison, literal.into()))
}

fn parse_literal(
    expression: &str,
    literal: &str,
    encoding: MetadataEncoding,
    size: u8,
) -> Result<(u64, bool), SkbFilterError> {
    let bits = u32::from(size) * 8;
    match encoding {
        MetadataEncoding::Boolean => {
            let value = match literal {
                "true" | "1" => 1,
                "false" | "0" => 0,
                _ => {
                    return Err(invalid(
                        expression,
                        "boolean literals are true, false, 0 or 1",
                    ));
                }
            };
            Ok((value, false))
        }
        MetadataEncoding::Signed => {
            let value = parse_i64(literal).ok_or_else(|| {
                invalid(expression, format!("invalid signed literal {literal:?}"))
            })?;
            let (minimum, maximum) = if bits == 64 {
                (i64::MIN, i64::MAX)
            } else {
                (-(1_i64 << (bits - 1)), (1_i64 << (bits - 1)) - 1)
            };
            if !(minimum..=maximum).contains(&value) {
                return Err(invalid(
                    expression,
                    format!("{literal:?} does not fit a signed {bits}-bit field"),
                ));
            }
            Ok((value as u64, true))
        }
        MetadataEncoding::Unsigned | MetadataEncoding::Pointer => {
            let value = parse_u64(literal).ok_or_else(|| {
                invalid(expression, format!("invalid unsigned literal {literal:?}"))
            })?;
            if bits < 64 && value >= 1_u64 << bits {
                return Err(invalid(
                    expression,
                    format!("{literal:?} does not fit an unsigned {bits}-bit field"),
                ));
            }
            Ok((value, false))
        }
    }
}

fn parse_i64(literal: &str) -> Option<i64> {
    if let Some(value) = literal.strip_prefix("-0x") {
        i64::from_str_radix(value, 16).ok()?.checked_neg()
    } else if let Some(value) = literal
        .strip_prefix("0x")
        .or_else(|| literal.strip_prefix("0X"))
    {
        i64::from_str_radix(value, 16).ok()
    } else {
        literal.parse().ok()
    }
}

fn parse_u64(literal: &str) -> Option<u64> {
    if let Some(value) = literal
        .strip_prefix("0x")
        .or_else(|| literal.strip_prefix("0X"))
    {
        u64::from_str_radix(value, 16).ok()
    } else {
        literal.parse().ok()
    }
}

fn invalid(expression: &str, reason: impl Into<String>) -> SkbFilterError {
    SkbFilterError::Invalid {
        expression: expression.into(),
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_bounded_typed_host_predicates() {
        let filter = resolve_skb_filter(Some("skb->mark == 0x2a && skb->dev->ifindex > 0"), None)
            .unwrap()
            .unwrap();
        assert_eq!(filter.conditions.len(), 2);
        assert_eq!(filter.conditions[0].value, 42);
        assert!(!filter.conditions[0].signed);
        assert_eq!(filter.conditions[1].comparison, ScalarComparison::Greater);
        assert!(filter.conditions[1].signed);
    }

    #[test]
    fn rejects_unbounded_or_ambiguous_syntax() {
        assert!(resolve_skb_filter(Some("skb->mark = 1"), None).is_err());
        assert!(resolve_skb_filter(Some("skb->mark == -1"), None).is_err());
        assert!(resolve_skb_filter(Some("skb->mark == 0x100000000"), None).is_err());
        assert!(resolve_skb_filter(Some("skb->mark == 1 &&"), None).is_err());
        assert!(resolve_skb_filter(
            Some(
                "skb->mark == 1 && skb->hash == 2 && skb->len > 0 && skb->skb_iif > 0 && skb->priority == 0"
            ),
            None
        )
        .is_err());
    }

    #[test]
    fn resolves_bounded_boolean_groups_with_parentheses() {
        let filter = resolve_skb_filter(
            Some("(skb->mark == 1 || skb->mark == 2) && skb->dev->ifindex > 0"),
            None,
        )
        .unwrap()
        .unwrap();
        assert_eq!(filter.conditions.len(), 4);
        assert_eq!(
            filter
                .conditions
                .iter()
                .map(|condition| condition.group)
                .collect::<Vec<_>>(),
            [0, 0, 1, 1]
        );
        assert_eq!(filter.conditions[0].value, 1);
        assert_eq!(filter.conditions[2].value, 2);
        assert!(
            resolve_skb_filter(
                Some("(skb->mark == 1 || skb->mark == 2) && (skb->len > 0 || skb->hash != 0)"),
                None
            )
            .is_err()
        );
        assert!(resolve_skb_filter(Some("(skb->mark == 1"), None).is_err());
        assert!(resolve_skb_filter(Some("skb->mark == 1 ||"), None).is_err());
        let deeply_nested = format!(
            "{}skb->mark == 1{}",
            "(".repeat(MAX_SKB_FILTER_NESTING + 1),
            ")".repeat(MAX_SKB_FILTER_NESTING + 1)
        );
        assert!(resolve_skb_filter(Some(&deeply_nested), None).is_err());
    }

    #[test]
    fn resolves_bounded_typed_xdp_predicates() {
        let filter = resolve_xdp_filter(
            Some("xdp->frame_sz >= 256 && xdp->rxq->dev->ifindex > 0"),
            None,
        )
        .unwrap()
        .unwrap();
        assert_eq!(filter.conditions.len(), 2);
        assert_eq!(
            filter.conditions[0].comparison,
            ScalarComparison::GreaterOrEqual
        );
        assert_eq!(filter.conditions[0].value, 256);
        assert!(filter.conditions[1].signed);
    }
}
