use btf_rs::{Btf, Type};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BtfDumpSupportError {
    #[error("load kernel BTF {path}: {error}")]
    Load { path: PathBuf, error: String },
    #[error("kernel BTF does not advertise BPF_FUNC_snprintf_btf")]
    MissingHelper,
    #[error("kernel BTF has no struct {0} definition")]
    MissingType(&'static str),
}

pub fn ensure_btf_dump_support(path: &Path) -> Result<(), BtfDumpSupportError> {
    let btf = Btf::from_file(path).map_err(|error| BtfDumpSupportError::Load {
        path: path.to_owned(),
        error: error.to_string(),
    })?;
    for name in ["sk_buff", "skb_shared_info"] {
        let present = btf
            .resolve_types_by_name(name)
            .map_err(|error| BtfDumpSupportError::Load {
                path: path.to_owned(),
                error: error.to_string(),
            })?
            .into_iter()
            .any(|candidate| matches!(candidate, Type::Struct(_)));
        if !present {
            return Err(BtfDumpSupportError::MissingType(name));
        }
    }

    let helper_present = btf
        .resolve_types_by_name("bpf_func_id")
        .map_err(|error| BtfDumpSupportError::Load {
            path: path.to_owned(),
            error: error.to_string(),
        })?
        .into_iter()
        .filter_map(|candidate| match candidate {
            Type::Enum(enumeration) => Some(enumeration),
            _ => None,
        })
        .flat_map(|enumeration| enumeration.members)
        .any(|member| {
            btf.resolve_name(&member)
                .is_ok_and(|name| name == "BPF_FUNC_snprintf_btf")
        });
    if !helper_present {
        return Err(BtfDumpSupportError::MissingHelper);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_btf_supports_bounded_structure_dumps() {
        ensure_btf_dump_support(Path::new(crate::DEFAULT_BTF_PATH)).unwrap();
    }
}
