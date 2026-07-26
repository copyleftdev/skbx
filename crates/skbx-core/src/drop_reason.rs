use btf_rs::{Btf, Type};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Clone, Debug, Default)]
pub struct DropReasonTable {
    reasons: BTreeMap<u64, String>,
}

impl DropReasonTable {
    pub fn from_btf(path: &Path) -> Self {
        let Ok(btf) = Btf::from_file(path) else {
            return Self::default();
        };
        let Ok(types) = btf.resolve_types_by_name("skb_drop_reason") else {
            return Self::default();
        };

        let mut reasons = BTreeMap::new();
        for r#type in types {
            match r#type {
                Type::Enum(enumeration) => {
                    for member in enumeration.members {
                        if let Ok(name) = btf.resolve_name(&member) {
                            reasons.insert(member.val() as u64, name);
                        }
                    }
                }
                Type::Enum64(enumeration) => {
                    for member in enumeration.members {
                        if let Ok(name) = btf.resolve_name(&member) {
                            reasons.insert(member.val(), name);
                        }
                    }
                }
                _ => {}
            }
        }
        Self { reasons }
    }

    pub fn resolve(&self, value: u64) -> Option<&str> {
        self.reasons.get(&value).map(String::as_str)
    }

    pub fn len(&self) -> usize {
        self.reasons.len()
    }

    pub fn is_empty(&self) -> bool {
        self.reasons.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_drop_reasons_from_host_btf() {
        let table = DropReasonTable::from_btf(Path::new("/sys/kernel/btf/vmlinux"));
        assert!(!table.is_empty());
        assert!(table.resolve(0).is_some());
    }
}
