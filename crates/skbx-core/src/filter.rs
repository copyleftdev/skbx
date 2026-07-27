use crate::{MetadataAccessPlan, MetadataError, resolve_skb_metadata};
use skbx_contract::MetadataEncoding;
use std::path::Path;
use thiserror::Error;

pub const MAX_SKB_FILTER_CONDITIONS: usize = 4;

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
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedSkbFilter {
    pub source: String,
    pub conditions: Vec<ResolvedSkbFilterCondition>,
}

#[derive(Debug, Error)]
pub enum SkbFilterError {
    #[error("SKB filter supports at most {MAX_SKB_FILTER_CONDITIONS} &&-joined conditions")]
    TooMany,
    #[error("invalid SKB filter expression {expression:?}: {reason}")]
    Invalid { expression: String, reason: String },
    #[error(transparent)]
    Metadata(#[from] MetadataError),
}

pub fn resolve_skb_filter(
    expression: Option<&str>,
    btf_path: Option<&Path>,
) -> Result<Option<ResolvedSkbFilter>, SkbFilterError> {
    let Some(source) = expression.filter(|value| !value.trim().is_empty()) else {
        return Ok(None);
    };
    if source.contains("||") {
        return Err(invalid(
            source,
            "|| is not supported; use bounded && predicates",
        ));
    }
    let clauses: Vec<&str> = source.split("&&").map(str::trim).collect();
    if clauses.is_empty() || clauses.iter().any(|clause| clause.is_empty()) {
        return Err(invalid(source, "every && operand must be a comparison"));
    }
    if clauses.len() > MAX_SKB_FILTER_CONDITIONS {
        return Err(SkbFilterError::TooMany);
    }

    let parsed: Vec<_> = clauses
        .iter()
        .map(|clause| parse_clause(source, clause))
        .collect::<Result<_, _>>()?;
    let paths: Vec<String> = parsed.iter().map(|(path, _, _)| path.clone()).collect();
    let projections = resolve_skb_metadata(&paths, btf_path)?;
    let mut conditions = Vec::with_capacity(parsed.len());
    for ((_, comparison, literal), projection) in parsed.into_iter().zip(projections) {
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
        });
    }
    Ok(Some(ResolvedSkbFilter {
        source: source.into(),
        conditions,
    }))
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
        assert!(resolve_skb_filter(Some("skb->mark == 1 || skb->mark == 2"), None).is_err());
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
}
