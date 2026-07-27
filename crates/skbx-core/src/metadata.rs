use btf_rs::{Btf, Type};
use skbx_contract::{MetadataEncoding, MetadataProjection};
use std::path::{Path, PathBuf};
use thiserror::Error;

pub const MAX_METADATA_PROJECTIONS: usize = 4;
pub const MAX_METADATA_ACCESS_STEPS: usize = 4;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MetadataAccessPlan {
    pub offsets: [u32; MAX_METADATA_ACCESS_STEPS],
    pub dereference_mask: u8,
    pub steps: u8,
    pub size: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedMetadataProjection {
    pub descriptor: MetadataProjection,
    pub access: MetadataAccessPlan,
}

#[derive(Debug, Error)]
pub enum MetadataError {
    #[error("at most {MAX_METADATA_PROJECTIONS} SKB metadata projections are supported")]
    TooMany,
    #[error("load kernel BTF {path}: {error}")]
    LoadBtf { path: PathBuf, error: String },
    #[error("kernel BTF has no struct sk_buff definition")]
    MissingSkb,
    #[error("invalid metadata expression {expression:?}: {reason}")]
    InvalidExpression { expression: String, reason: String },
    #[error("resolve metadata expression {expression:?}: {reason}")]
    Resolve { expression: String, reason: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Connector {
    Arrow,
    Dot,
}

pub fn resolve_skb_metadata(
    expressions: &[String],
    btf_path: Option<&Path>,
) -> Result<Vec<ResolvedMetadataProjection>, MetadataError> {
    if expressions.len() > MAX_METADATA_PROJECTIONS {
        return Err(MetadataError::TooMany);
    }
    let path = btf_path.unwrap_or_else(|| Path::new(crate::DEFAULT_BTF_PATH));
    let btf = Btf::from_file(path).map_err(|error| MetadataError::LoadBtf {
        path: path.to_owned(),
        error: error.to_string(),
    })?;
    let root = btf
        .resolve_types_by_name("sk_buff")
        .map_err(|error| MetadataError::Resolve {
            expression: "skb".into(),
            reason: error.to_string(),
        })?
        .into_iter()
        .find_map(|candidate| match strip_modifiers(&btf, candidate) {
            Ok(Type::Struct(root)) => Some(root),
            _ => None,
        })
        .ok_or(MetadataError::MissingSkb)?;

    expressions
        .iter()
        .map(|expression| resolve_one(&btf, &root, expression))
        .collect()
}

fn resolve_one(
    btf: &Btf,
    root: &btf_rs::Struct,
    expression: &str,
) -> Result<ResolvedMetadataProjection, MetadataError> {
    let components = parse_expression(expression)?;
    if components.len() > MAX_METADATA_ACCESS_STEPS {
        return Err(resolve_error(
            expression,
            format!(
                "access has {} steps; maximum is {MAX_METADATA_ACCESS_STEPS}",
                components.len()
            ),
        ));
    }
    let mut container = Type::Struct(root.clone());
    let mut access = MetadataAccessPlan {
        steps: components.len() as u8,
        ..MetadataAccessPlan::default()
    };

    for (index, (_, field)) in components.iter().enumerate() {
        let aggregate = match &container {
            Type::Struct(value) | Type::Union(value) => value,
            _ => {
                return Err(resolve_error(
                    expression,
                    format!("{field:?} is accessed through a non-aggregate type"),
                ));
            }
        };
        let member = find_member(btf, aggregate, field, 0, 0).ok_or_else(|| {
            resolve_error(
                expression,
                format!("field {field:?} is absent from target kernel BTF"),
            )
        })?;
        if member.bit_offset % 8 != 0 || member.bitfield_size.is_some_and(|size| size != 0) {
            return Err(resolve_error(
                expression,
                format!("bitfield {field:?} is not a byte-addressable scalar"),
            ));
        }
        access.offsets[index] = member.bit_offset / 8;
        let selected = member.selected;

        if let Some((next_connector, _)) = components.get(index + 1) {
            container = match next_connector {
                Connector::Arrow => {
                    let pointer = match selected {
                        Type::Ptr(pointer) => pointer,
                        _ => {
                            return Err(resolve_error(
                                expression,
                                format!("{field:?} is not a pointer but is followed by ->"),
                            ));
                        }
                    };
                    access.dereference_mask |= 1 << index;
                    let target = btf
                        .resolve_chained_type(&pointer)
                        .map_err(|error| resolve_error(expression, error.to_string()))?;
                    strip_modifiers(btf, target)
                        .map_err(|error| resolve_error(expression, error.to_string()))?
                }
                Connector::Dot => match selected {
                    Type::Struct(_) | Type::Union(_) => selected,
                    _ => {
                        return Err(resolve_error(
                            expression,
                            format!(
                                "{field:?} is not an inline struct or union but is followed by ."
                            ),
                        ));
                    }
                },
            };
            continue;
        }

        let (encoding, size, fallback_name) = scalar_shape(&selected).ok_or_else(|| {
            resolve_error(
                expression,
                format!("{field:?} is not a supported integer, enum, boolean or pointer scalar"),
            )
        })?;
        if !(1..=8).contains(&size) {
            return Err(resolve_error(
                expression,
                format!("field {field:?} is {size} bytes; supported scalar size is 1..=8"),
            ));
        }
        access.size = size as u8;
        let type_name = selected
            .as_btf_type()
            .and_then(|value| btf.resolve_name(value).ok())
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| fallback_name.into());
        return Ok(ResolvedMetadataProjection {
            descriptor: MetadataProjection {
                expression: expression.into(),
                type_name,
                encoding,
                size: size as u8,
            },
            access,
        });
    }

    unreachable!("the parser rejects empty metadata paths")
}

struct FoundMember {
    bit_offset: u32,
    bitfield_size: Option<u32>,
    selected: Type,
}

fn find_member(
    btf: &Btf,
    aggregate: &btf_rs::Struct,
    field: &str,
    base_bit_offset: u32,
    depth: usize,
) -> Option<FoundMember> {
    if depth > 8 {
        return None;
    }
    for member in &aggregate.members {
        let Ok(name) = btf.resolve_name(member) else {
            continue;
        };
        let Some(selected) = btf
            .resolve_chained_type(member)
            .ok()
            .and_then(|value| strip_modifiers(btf, value).ok())
        else {
            continue;
        };
        if name == field {
            return Some(FoundMember {
                bit_offset: base_bit_offset + member.bit_offset(),
                bitfield_size: member.bitfield_size(),
                selected,
            });
        }
        if !name.is_empty() {
            continue;
        }
        let nested = match &selected {
            Type::Struct(value) | Type::Union(value) => value,
            _ => continue,
        };
        if let Some(found) = find_member(
            btf,
            nested,
            field,
            base_bit_offset + member.bit_offset(),
            depth + 1,
        ) {
            return Some(found);
        }
    }
    None
}

fn scalar_shape(value: &Type) -> Option<(MetadataEncoding, usize, &'static str)> {
    match value {
        Type::Int(value) if value.is_bool() => {
            Some((MetadataEncoding::Boolean, value.size(), "bool"))
        }
        Type::Int(value) if value.is_signed() => {
            Some((MetadataEncoding::Signed, value.size(), "signed_integer"))
        }
        Type::Int(value) => Some((MetadataEncoding::Unsigned, value.size(), "unsigned_integer")),
        Type::Enum(value) => Some((
            if value.is_signed() {
                MetadataEncoding::Signed
            } else {
                MetadataEncoding::Unsigned
            },
            value.size(),
            "enum",
        )),
        Type::Enum64(value) => Some((
            if value.is_signed() {
                MetadataEncoding::Signed
            } else {
                MetadataEncoding::Unsigned
            },
            value.size(),
            "enum64",
        )),
        Type::Ptr(_) => Some((MetadataEncoding::Pointer, 8, "pointer")),
        _ => None,
    }
}

fn strip_modifiers(btf: &Btf, mut value: Type) -> Result<Type, btf_rs::Error> {
    loop {
        value = match &value {
            Type::Typedef(inner) => btf.resolve_chained_type(inner)?,
            Type::Volatile(inner) => btf.resolve_chained_type(inner)?,
            Type::Const(inner) => btf.resolve_chained_type(inner)?,
            Type::Restrict(inner) => btf.resolve_chained_type(inner)?,
            Type::DeclTag(inner) => btf.resolve_chained_type(inner)?,
            Type::TypeTag(inner) => btf.resolve_chained_type(inner)?,
            _ => return Ok(value),
        };
    }
}

fn parse_expression(expression: &str) -> Result<Vec<(Connector, String)>, MetadataError> {
    let mut remaining = expression
        .strip_prefix("skb")
        .ok_or_else(|| invalid_error(expression, "expression must begin with skb"))?;
    let mut components = Vec::new();
    while !remaining.is_empty() {
        let (connector, rest) = if let Some(rest) = remaining.strip_prefix("->") {
            (Connector::Arrow, rest)
        } else if let Some(rest) = remaining.strip_prefix('.') {
            (Connector::Dot, rest)
        } else {
            return Err(invalid_error(
                expression,
                "fields must be joined with -> or .",
            ));
        };
        if components.is_empty() && connector != Connector::Arrow {
            return Err(invalid_error(
                expression,
                "the first sk_buff field must be accessed with ->",
            ));
        }
        let end = rest
            .find(|character: char| !character.is_ascii_alphanumeric() && character != '_')
            .unwrap_or(rest.len());
        let field = &rest[..end];
        if field.is_empty()
            || !field
                .as_bytes()
                .first()
                .is_some_and(|character| character.is_ascii_alphabetic() || *character == b'_')
        {
            return Err(invalid_error(
                expression,
                "field names must be C identifiers",
            ));
        }
        components.push((connector, field.into()));
        remaining = &rest[end..];
    }
    if components.is_empty() {
        return Err(invalid_error(expression, "at least one field is required"));
    }
    Ok(components)
}

fn invalid_error(expression: &str, reason: impl Into<String>) -> MetadataError {
    MetadataError::InvalidExpression {
        expression: expression.into(),
        reason: reason.into(),
    }
}

fn resolve_error(expression: &str, reason: impl Into<String>) -> MetadataError {
    MetadataError::Resolve {
        expression: expression.into(),
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_only_bounded_c_style_field_paths() {
        assert_eq!(
            parse_expression("skb->dev->ifindex").unwrap(),
            [
                (Connector::Arrow, "dev".into()),
                (Connector::Arrow, "ifindex".into())
            ]
        );
        assert!(parse_expression("skb.mark").is_err());
        assert!(parse_expression("skb->mark == 1").is_err());
        assert!(parse_expression("other->mark").is_err());
        assert!(parse_expression("skb->").is_err());
    }

    #[test]
    fn resolves_host_skb_scalars_and_pointer_chains() {
        let projections = resolve_skb_metadata(
            &[
                "skb->mark".into(),
                "skb->hash".into(),
                "skb->dev->ifindex".into(),
            ],
            None,
        )
        .unwrap();
        assert_eq!(projections.len(), 3);
        assert_eq!(
            projections[0].descriptor.encoding,
            MetadataEncoding::Unsigned
        );
        assert_eq!(projections[0].descriptor.size, 4);
        assert_eq!(projections[2].access.steps, 2);
        assert_eq!(projections[2].access.dereference_mask, 1);
    }

    #[test]
    fn rejects_unknown_or_non_scalar_fields() {
        assert!(resolve_skb_metadata(&["skb->definitely_absent".into()], None).is_err());
        assert!(resolve_skb_metadata(&["skb->cb".into()], None).is_err());
        assert!(resolve_skb_metadata(&vec!["skb->mark".into(); 5], None).is_err());
    }
}
