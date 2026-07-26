use crate::doctor::kernel_release;
use btf_rs::{Btf, BtfType, Type};
use fallible_iterator::FallibleIterator;
use regex::Regex;
use skbx_contract::{CONTRACT_VERSION, ProbePlan, ProbeSource, ProbeSpec};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

pub const DEFAULT_BTF_PATH: &str = "/sys/kernel/btf/vmlinux";
const MAX_KPROBE_ARGUMENT: usize = 5;

#[derive(Debug, Error)]
pub enum PlanError {
    #[error("exact probes and --filter-func cannot be used together")]
    ConflictingSelectors,
    #[error("--kmods and --all-kmods cannot be used together")]
    ConflictingModuleSelectors,
    #[error("invalid function regular expression: {0}")]
    InvalidPattern(#[from] regex::Error),
    #[error("load kernel BTF {path}: {error}")]
    LoadBtf { path: PathBuf, error: String },
    #[error("load split BTF module {module} from {path}: {error}")]
    LoadModuleBtf {
        module: String,
        path: PathBuf,
        error: String,
    },
    #[error("list split BTF directory {path}: {error}")]
    ListModuleBtf { path: PathBuf, error: String },
    #[error("invalid kernel module name {0:?}")]
    InvalidModuleName(String),
    #[error("iterate kernel BTF: {0}")]
    IterateBtf(String),
}

/// Discover every attachable kernel function with a `struct sk_buff *`
/// parameter in the first five ABI argument positions.
///
/// Exact names preserve the original `--probe` interface. `filter_pattern`
/// follows pwru semantics and must match the entire function name.
pub fn build_probe_plan(
    exact_names: &[String],
    filter_pattern: Option<&str>,
    btf_path: Option<&Path>,
    modules: &[String],
    all_modules: bool,
) -> Result<ProbePlan, PlanError> {
    build_probe_plan_with_non_skb(
        exact_names,
        filter_pattern,
        &[],
        btf_path,
        modules,
        all_modules,
    )
}

pub fn build_probe_plan_with_non_skb(
    exact_names: &[String],
    filter_pattern: Option<&str>,
    non_skb_names: &[String],
    btf_path: Option<&Path>,
    modules: &[String],
    all_modules: bool,
) -> Result<ProbePlan, PlanError> {
    if !exact_names.is_empty() && filter_pattern.is_some() {
        return Err(PlanError::ConflictingSelectors);
    }
    if !modules.is_empty() && all_modules {
        return Err(PlanError::ConflictingModuleSelectors);
    }

    let anchored_pattern = filter_pattern
        .filter(|pattern| !pattern.is_empty())
        .map(|pattern| Regex::new(&format!("^(?:{pattern})$")))
        .transpose()?;
    let exact: BTreeSet<&str> = exact_names.iter().map(String::as_str).collect();
    let non_skb: BTreeSet<&str> = non_skb_names.iter().map(String::as_str).collect();
    let selected = |name: &str| {
        if !exact.is_empty() {
            exact.contains(name)
        } else {
            anchored_pattern
                .as_ref()
                .is_none_or(|pattern| pattern.is_match(name))
        }
    };

    let path = btf_path.unwrap_or_else(|| Path::new(DEFAULT_BTF_PATH));
    let btf = Btf::from_file(path).map_err(|error| PlanError::LoadBtf {
        path: path.to_owned(),
        error: error.to_string(),
    })?;

    let mut inspection_failures = 0_u64;
    let mut discovered = Vec::<(String, Option<String>, u8)>::new();
    let mut discovered_non_skb = Vec::<(String, Option<String>)>::new();
    discover_btf(
        &btf,
        None,
        &selected,
        &non_skb,
        &mut discovered,
        &mut discovered_non_skb,
        &mut inspection_failures,
    )?;

    let module_dir = path
        .parent()
        .unwrap_or_else(|| Path::new("/sys/kernel/btf"));
    let module_names = resolve_module_names(module_dir, path, modules, all_modules)?;
    for module in module_names {
        let module_path = module_dir.join(&module);
        let split =
            Btf::from_split_file(&module_path, &btf).map_err(|error| PlanError::LoadModuleBtf {
                module: module.clone(),
                path: module_path,
                error: error.to_string(),
            })?;
        discover_btf(
            &split,
            Some(&module),
            &selected,
            &non_skb,
            &mut discovered,
            &mut discovered_non_skb,
            &mut inspection_failures,
        )?;
    }

    let (available, availability_source) = available_functions();
    let mut probes: Vec<ProbeSpec> = discovered
        .into_iter()
        .map(|(function, module, skb_argument)| ProbeSpec {
            available: available.contains(&function),
            function,
            source: if module.is_some() {
                ProbeSource::KernelModuleBtf
            } else {
                ProbeSource::KernelBtf
            },
            module: module.clone(),
            skb_argument: Some(skb_argument),
            assumption: match module {
                Some(module) => format!(
                    "split BTF module {module} validates struct sk_buff * at argument {skb_argument}"
                ),
                None => {
                    format!("kernel BTF validates struct sk_buff * at argument {skb_argument}")
                }
            },
        })
        .collect();

    probes.extend(
        discovered_non_skb
            .into_iter()
            .map(|(function, module)| ProbeSpec {
                available: available.contains(&function),
                function,
                source: if module.is_some() {
                    ProbeSource::KernelModuleBtf
                } else {
                    ProbeSource::KernelBtf
                },
                module: module.clone(),
                skb_argument: None,
                assumption: match module {
                    Some(module) => format!(
                        "split BTF module {module} validates function existence; SKB association uses a bounded stack anchor"
                    ),
                    None => "kernel BTF validates function existence; SKB association uses a bounded stack anchor".into(),
                },
            }),
    );

    // Exact requests that are missing or do not accept an SKB remain visible
    // in the plan instead of disappearing as an ambiguous empty result.
    for name in exact_names {
        if !probes
            .iter()
            .any(|probe| probe.function == *name && probe.skb_argument.is_some())
        {
            probes.push(ProbeSpec {
                function: name.clone(),
                module: None,
                source: ProbeSource::CallerAsserted,
                available: false,
                skb_argument: None,
                assumption: "not present in kernel BTF with an SKB argument in positions 1-5"
                    .into(),
            });
        }
    }
    for name in non_skb_names {
        if !probes
            .iter()
            .any(|probe| probe.function == *name && probe.skb_argument.is_none())
        {
            probes.push(ProbeSpec {
                function: name.clone(),
                module: None,
                source: ProbeSource::CallerAsserted,
                available: false,
                skb_argument: None,
                assumption: "not present as a function in selected kernel/module BTF".into(),
            });
        }
    }
    probes.sort_by(|a, b| {
        a.function
            .cmp(&b.function)
            .then_with(|| a.module.cmp(&b.module))
    });
    probes.dedup_by(|a, b| {
        a.function == b.function && a.module == b.module && a.skb_argument == b.skb_argument
    });

    let attachable = probes.iter().filter(|probe| probe.available).count();
    let unavailable = probes.len() - attachable;
    let mut warnings = vec![format!(
        "attachability checked against {availability_source}"
    )];
    if inspection_failures > 0 {
        warnings.push(format!(
            "{inspection_failures} selected BTF definitions could not be fully inspected"
        ));
    }
    if unavailable > 0 {
        warnings.push(format!(
            "{unavailable} BTF-matched probes are not exposed as attachable kernel symbols"
        ));
    }

    Ok(ProbePlan {
        schema: format!("{CONTRACT_VERSION}/probe-plan"),
        kernel_release: kernel_release(),
        probes,
        attachable,
        unavailable,
        warnings,
    })
}

fn discover_btf(
    btf: &Btf,
    module: Option<&str>,
    selected: &impl Fn(&str) -> bool,
    non_skb: &BTreeSet<&str>,
    discovered: &mut Vec<(String, Option<String>, u8)>,
    discovered_non_skb: &mut Vec<(String, Option<String>)>,
    inspection_failures: &mut u64,
) -> Result<(), PlanError> {
    let types = if module.is_some() {
        let split = btf
            .split()
            .ok_or_else(|| PlanError::IterateBtf("module BTF has no split section".into()))?;
        let all_names = Regex::new(".*").expect("the all-names BTF regular expression is valid");
        split
            .resolve_ids_by_regex(&all_names)
            .map_err(|error| PlanError::IterateBtf(error.to_string()))?
            .into_iter()
            .filter_map(|id| match btf.resolve_type_by_id(id) {
                Ok(r#type) => Some(r#type),
                Err(_) => {
                    *inspection_failures += 1;
                    None
                }
            })
            .collect::<Vec<_>>()
    } else {
        let mut result = Vec::new();
        let mut types = btf.type_iter();
        while let Some(r#type) = types
            .next()
            .map_err(|error| PlanError::IterateBtf(error.to_string()))?
        {
            result.push(r#type);
        }
        result
    };

    for r#type in types {
        let Type::Func(function) = r#type else {
            continue;
        };
        let Ok(name) = btf.resolve_name(&function) else {
            *inspection_failures += 1;
            continue;
        };
        let selected_skb = selected(&name);
        let selected_non_skb = non_skb.contains(name.as_str());
        if !selected_skb && !selected_non_skb {
            continue;
        }
        let Ok(Type::FuncProto(prototype)) = btf.resolve_chained_type(&function) else {
            *inspection_failures += 1;
            continue;
        };
        let mut skb_argument = None;
        for (index, parameter) in prototype
            .parameters
            .iter()
            .take(MAX_KPROBE_ARGUMENT)
            .enumerate()
        {
            match is_skb_pointer(btf, parameter) {
                Ok(true) => {
                    skb_argument = Some((index + 1) as u8);
                    break;
                }
                Ok(false) => {}
                Err(()) => *inspection_failures += 1,
            }
        }
        if selected_skb {
            if let Some(argument) = skb_argument {
                discovered.push((name.clone(), module.map(str::to_owned), argument));
            }
        }
        if selected_non_skb && skb_argument.is_none() {
            discovered_non_skb.push((name, module.map(str::to_owned)));
        }
    }
    Ok(())
}

fn resolve_module_names(
    module_dir: &Path,
    base_path: &Path,
    requested: &[String],
    all_modules: bool,
) -> Result<Vec<String>, PlanError> {
    let base_name = base_path.file_name().and_then(|name| name.to_str());
    let mut names = if all_modules {
        fs::read_dir(module_dir)
            .map_err(|error| PlanError::ListModuleBtf {
                path: module_dir.to_owned(),
                error: error.to_string(),
            })?
            .filter_map(Result::ok)
            .filter_map(|entry| {
                entry
                    .file_type()
                    .ok()
                    .filter(|kind| kind.is_file())
                    .and_then(|_| entry.file_name().into_string().ok())
            })
            .filter(|name| Some(name.as_str()) != base_name)
            .collect()
    } else {
        requested.to_vec()
    };
    for name in &names {
        let path = Path::new(name);
        if path.file_name().and_then(|value| value.to_str()) != Some(name.as_str())
            || name == "."
            || name == ".."
        {
            return Err(PlanError::InvalidModuleName(name.clone()));
        }
    }
    names.sort();
    names.dedup();
    Ok(names)
}

fn is_skb_pointer(btf: &Btf, parameter: &dyn BtfType) -> Result<bool, ()> {
    let mut current = btf.resolve_chained_type(parameter).map_err(|_| ())?;
    let mut saw_pointer = false;

    loop {
        match &current {
            Type::Ptr(_) if !saw_pointer => saw_pointer = true,
            Type::Ptr(_) => return Ok(false),
            Type::Struct(r#struct) => {
                return btf
                    .resolve_name(r#struct)
                    .map(|name| saw_pointer && name == "sk_buff")
                    .map_err(|_| ());
            }
            Type::Typedef(_)
            | Type::Volatile(_)
            | Type::Const(_)
            | Type::Restrict(_)
            | Type::TypeTag(_) => {}
            _ => return Ok(false),
        }

        let Some(reference) = current.as_btf_type() else {
            return Ok(false);
        };
        current = btf.resolve_chained_type(reference).map_err(|_| ())?;
    }
}

fn available_functions() -> (BTreeSet<String>, &'static str) {
    for path in [
        "/sys/kernel/tracing/available_filter_functions",
        "/sys/kernel/debug/tracing/available_filter_functions",
    ] {
        if let Ok(text) = fs::read_to_string(path) {
            let functions = text
                .lines()
                .filter_map(|line| line.split_whitespace().next())
                .map(str::to_owned)
                .collect();
            return (functions, "tracefs available_filter_functions");
        }
    }

    let functions = fs::read_to_string("/proc/kallsyms")
        .map(|text| {
            text.lines()
                .filter_map(|line| line.split_whitespace().nth(2))
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    (functions, "/proc/kallsyms fallback")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovers_non_first_skb_arguments_from_host_btf() {
        let plan = build_probe_plan(&["tcp_v4_do_rcv".into()], None, None, &[], false).unwrap();
        let probe = &plan.probes[0];
        assert_eq!(probe.function, "tcp_v4_do_rcv");
        assert_eq!(probe.skb_argument, Some(2));
        assert_eq!(probe.source, ProbeSource::KernelBtf);
    }

    #[test]
    fn exact_missing_probe_remains_explicit() {
        let plan = build_probe_plan(
            &["skbx_function_that_cannot_exist".into()],
            None,
            None,
            &[],
            false,
        )
        .unwrap();
        assert_eq!(plan.probes.len(), 1);
        assert!(!plan.probes[0].available);
        assert_eq!(plan.probes[0].skb_argument, None);
    }

    #[test]
    fn validates_non_skb_functions_without_inventing_an_argument() {
        let plan = build_probe_plan_with_non_skb(
            &["ip_rcv".into()],
            None,
            &["fib_table_lookup".into()],
            None,
            &[],
            false,
        )
        .unwrap();
        let probe = plan
            .probes
            .iter()
            .find(|probe| probe.function == "fib_table_lookup")
            .unwrap();
        assert!(probe.available);
        assert_eq!(probe.skb_argument, None);
        assert_eq!(probe.source, ProbeSource::KernelBtf);
    }

    #[test]
    fn pattern_is_a_whole_name_match() {
        let plan = build_probe_plan(&[], Some("kfree_skb.*"), None, &[], false).unwrap();
        assert!(
            plan.probes
                .iter()
                .all(|probe| probe.function.starts_with("kfree_skb"))
        );
    }

    #[test]
    fn selectors_are_mutually_exclusive() {
        assert!(matches!(
            build_probe_plan(&["ip_rcv".into()], Some(".*"), None, &[], false),
            Err(PlanError::ConflictingSelectors)
        ));
    }

    #[test]
    fn module_selectors_are_bounded_and_validated() {
        assert!(matches!(
            build_probe_plan(&[], None, None, &["bridge".into()], true),
            Err(PlanError::ConflictingModuleSelectors)
        ));
        assert!(matches!(
            build_probe_plan(&[], None, None, &["../bridge".into()], false),
            Err(PlanError::InvalidModuleName(_))
        ));
    }

    #[test]
    fn discovers_split_btf_when_bridge_module_is_present() {
        if !Path::new("/sys/kernel/btf/bridge").exists() {
            return;
        }
        let plan = build_probe_plan(
            &["br_dev_xmit".into()],
            None,
            None,
            &["bridge".into()],
            false,
        )
        .unwrap();
        let probe = plan
            .probes
            .iter()
            .find(|probe| probe.module.as_deref() == Some("bridge"))
            .unwrap();
        assert_eq!(probe.source, ProbeSource::KernelModuleBtf);
        assert_eq!(probe.skb_argument, Some(1));
    }
}
