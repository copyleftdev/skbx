use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Pass,
    Warn,
    Fail,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorCheck {
    pub name: String,
    pub status: CheckStatus,
    pub evidence: String,
    pub remediation: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorReport {
    pub schema: String,
    pub kernel_release: String,
    pub ready: bool,
    pub checks: Vec<DoctorCheck>,
}

pub fn doctor() -> DoctorReport {
    let kernel_release = kernel_release();
    let mut checks = Vec::new();

    checks.push(path_check(
        "kernel_btf",
        "/sys/kernel/btf/vmlinux",
        true,
        "Enable CONFIG_DEBUG_INFO_BTF or use a kernel that exposes vmlinux BTF.",
    ));
    checks.push(any_path_check(
        "tracefs",
        &["/sys/kernel/tracing", "/sys/kernel/debug/tracing"],
        true,
        "Mount tracefs and grant the capture process access.",
    ));
    checks.push(path_check(
        "kallsyms",
        "/proc/kallsyms",
        true,
        "Grant read access to /proc/kallsyms for symbol enrichment.",
    ));
    let kernel_config_path = format!("/boot/config-{kernel_release}");
    let frame_pointers = fs::read_to_string(&kernel_config_path).ok().map(|config| {
        config.lines().any(|line| {
            matches!(
                line,
                "CONFIG_FRAME_POINTER=y" | "CONFIG_UNWINDER_FRAME_POINTER=y"
            )
        })
    });
    checks.push(DoctorCheck {
        name: "frame_pointers".into(),
        status: match frame_pointers {
            Some(true) => CheckStatus::Pass,
            Some(false) | None => CheckStatus::Warn,
        },
        evidence: match frame_pointers {
            Some(true) => format!("{kernel_config_path}: enabled"),
            Some(false) => format!("{kernel_config_path}: not enabled"),
            None => format!("{kernel_config_path}: unavailable"),
        },
        remediation: (frame_pointers != Some(true)).then(|| {
            "Stack-associated non-SKB tracing requires kernel frame pointers; direct SKB capture remains available.".into()
        }),
    });

    let effective_uid = unsafe { libc_geteuid() };
    let effective_caps = effective_capabilities();
    const CAP_PERFMON: u32 = 38;
    const CAP_BPF: u32 = 39;
    let has_bpf_caps = effective_caps
        .is_some_and(|caps| caps & (1_u64 << CAP_PERFMON) != 0 && caps & (1_u64 << CAP_BPF) != 0);
    let privileged = effective_uid == 0 || has_bpf_caps;
    checks.push(DoctorCheck {
        name: "privilege".into(),
        status: if privileged {
            CheckStatus::Pass
        } else {
            CheckStatus::Fail
        },
        evidence: format!(
            "effective_uid={effective_uid}, cap_eff={}",
            effective_caps
                .map(|caps| format!("{caps:016x}"))
                .unwrap_or_else(|| "unknown".into())
        ),
        remediation: (!privileged).then(|| {
            "Run capture as root or grant the minimum CAP_BPF/CAP_PERFMON capabilities; replay needs no privilege.".into()
        }),
    });

    let symbol_visibility = fs::read_to_string("/proc/kallsyms")
        .ok()
        .and_then(|text| {
            text.lines()
                .find_map(|line| line.split_whitespace().next())
                .map(|address| address != "0000000000000000")
        })
        .unwrap_or(false);
    checks.push(DoctorCheck {
        name: "symbol_addresses".into(),
        status: if symbol_visibility {
            CheckStatus::Pass
        } else {
            CheckStatus::Warn
        },
        evidence: if symbol_visibility {
            "kernel symbol addresses visible".into()
        } else {
            "kernel symbol addresses are zeroed".into()
        },
        remediation: (!symbol_visibility).then(|| {
            "Capture as a sufficiently privileged user or lower kernel.kptr_restrict if policy allows; raw addresses remain valid evidence.".into()
        }),
    });

    if let Ok(lockdown) = fs::read_to_string("/sys/kernel/security/lockdown") {
        let restricted = lockdown.contains("[integrity]") || lockdown.contains("[confidentiality]");
        checks.push(DoctorCheck {
            name: "kernel_lockdown".into(),
            status: if restricted {
                CheckStatus::Warn
            } else {
                CheckStatus::Pass
            },
            evidence: lockdown.trim().into(),
            remediation: restricted.then(|| {
                "Kernel lockdown may reject kprobes even with capabilities; follow the host security policy.".into()
            }),
        });
    }

    let ready = checks.iter().all(|c| c.status != CheckStatus::Fail);
    DoctorReport {
        schema: "skbx.doctor/0.1.0".into(),
        kernel_release,
        ready,
        checks,
    }
}

fn path_check(name: &str, path: &str, required: bool, remediation: &str) -> DoctorCheck {
    let exists = Path::new(path).exists();
    DoctorCheck {
        name: name.into(),
        status: if exists {
            CheckStatus::Pass
        } else if required {
            CheckStatus::Fail
        } else {
            CheckStatus::Warn
        },
        evidence: format!("{path}: {}", if exists { "present" } else { "missing" }),
        remediation: (!exists).then(|| remediation.into()),
    }
}

fn any_path_check(name: &str, paths: &[&str], required: bool, remediation: &str) -> DoctorCheck {
    if let Some(path) = paths.iter().find(|path| Path::new(path).exists()) {
        path_check(name, path, required, remediation)
    } else {
        DoctorCheck {
            name: name.into(),
            status: if required {
                CheckStatus::Fail
            } else {
                CheckStatus::Warn
            },
            evidence: format!("none present: {}", paths.join(", ")),
            remediation: Some(remediation.into()),
        }
    }
}

pub fn kernel_release() -> String {
    fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_owned())
        .unwrap_or_else(|_| "unknown".into())
}

fn effective_capabilities() -> Option<u64> {
    fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:\t"))
        .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok())
}

unsafe extern "C" {
    #[link_name = "geteuid"]
    fn raw_geteuid() -> u32;
}

unsafe fn libc_geteuid() -> u32 {
    // SAFETY: geteuid has no preconditions and does not dereference pointers.
    unsafe { raw_geteuid() }
}
