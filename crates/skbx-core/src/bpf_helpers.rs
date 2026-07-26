use iced_x86::{Decoder, DecoderOptions, Mnemonic, OpKind};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use thiserror::Error;

const ELF_HEADER_BYTES: usize = 64;
const ELF64_PROGRAM_HEADER_BYTES: usize = 56;
const PT_LOAD: u32 = 1;
const MAX_BPF_PROGRAMS: usize = 65_536;
const MAX_JIT_PROGRAM_BYTES: usize = 1024 * 1024;
const MAX_TOTAL_JIT_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BpfHelperDiscovery {
    pub architecture: &'static str,
    pub programs_seen: usize,
    pub programs_decoded: usize,
    pub program_read_failures: usize,
    pub decoded_bytes: usize,
    pub helpers: Vec<String>,
}

#[derive(Debug, Error)]
pub enum BpfHelperError {
    #[error("BPF helper discovery is only supported on x86_64")]
    UnsupportedArchitecture,
    #[error("read {path}: {error}")]
    Read { path: PathBuf, error: io::Error },
    #[error(
        "/proc/kallsyms exposes no nonzero BPF JIT addresses; run capture with sufficient privilege"
    )]
    SymbolAddressesHidden,
    #[error("invalid /proc/kcore ELF metadata: {0}")]
    InvalidKcore(&'static str),
    #[error("BPF helper discovery exceeded its {0} safety bound")]
    Limit(&'static str),
}

#[derive(Clone, Debug)]
struct KernelSymbol {
    address: u64,
    name: String,
    bpf_program: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LoadSegment {
    offset: u64,
    address: u64,
    size: u64,
}

/// Discover direct kernel callees from every currently JIT-compiled BPF
/// program. Exact callees are resolved back through kallsyms; userspace never
/// guesses helper names from a prefix.
pub fn discover_bpf_helpers() -> Result<BpfHelperDiscovery, BpfHelperError> {
    discover_bpf_helpers_from(Path::new("/proc/kallsyms"), Path::new("/proc/kcore"))
}

fn discover_bpf_helpers_from(
    kallsyms_path: &Path,
    kcore_path: &Path,
) -> Result<BpfHelperDiscovery, BpfHelperError> {
    if !cfg!(target_arch = "x86_64") {
        return Err(BpfHelperError::UnsupportedArchitecture);
    }

    let symbols_text =
        std::fs::read_to_string(kallsyms_path).map_err(|error| BpfHelperError::Read {
            path: kallsyms_path.to_owned(),
            error,
        })?;
    let mut symbols = parse_kallsyms(&symbols_text);
    symbols.sort_by_key(|symbol| symbol.address);
    if !symbols
        .iter()
        .any(|symbol| symbol.bpf_program && symbol.address != 0)
    {
        return Err(BpfHelperError::SymbolAddressesHidden);
    }

    let addresses: BTreeMap<u64, &str> = symbols
        .iter()
        .filter(|symbol| symbol.address != 0)
        .map(|symbol| (symbol.address, symbol.name.as_str()))
        .collect();
    let mut programs: Vec<u64> = symbols
        .iter()
        .filter(|symbol| symbol.bpf_program && symbol.address != 0)
        .map(|symbol| symbol.address)
        .collect();
    programs.sort_unstable();
    programs.dedup();
    if programs.len() > MAX_BPF_PROGRAMS {
        return Err(BpfHelperError::Limit("BPF program count"));
    }

    let kcore = File::open(kcore_path).map_err(|error| BpfHelperError::Read {
        path: kcore_path.to_owned(),
        error,
    })?;
    let segments = read_kcore_segments(&kcore)?;
    let mut helpers = BTreeSet::new();
    let mut programs_decoded = 0;
    let mut program_read_failures = 0;
    let mut decoded_bytes = 0_usize;

    for program_address in &programs {
        let next_index = symbols.partition_point(|symbol| symbol.address <= *program_address);
        let Some(next_address) = symbols.get(next_index).map(|symbol| symbol.address) else {
            program_read_failures += 1;
            continue;
        };
        let Some(length) = next_address
            .checked_sub(*program_address)
            .and_then(|length| usize::try_from(length).ok())
            .filter(|length| *length > 0 && *length <= MAX_JIT_PROGRAM_BYTES)
        else {
            program_read_failures += 1;
            continue;
        };
        if decoded_bytes.saturating_add(length) > MAX_TOTAL_JIT_BYTES {
            return Err(BpfHelperError::Limit("total JIT byte"));
        }
        let Some(segment) = segments.iter().find(|segment| {
            *program_address >= segment.address
                && program_address
                    .checked_add(length as u64)
                    .is_some_and(|end| end <= segment.address.saturating_add(segment.size))
        }) else {
            program_read_failures += 1;
            continue;
        };
        let Some(offset) = segment
            .offset
            .checked_add(*program_address - segment.address)
        else {
            program_read_failures += 1;
            continue;
        };
        let mut bytes = vec![0_u8; length];
        if kcore.read_exact_at(&mut bytes, offset).is_err() {
            program_read_failures += 1;
            continue;
        }

        for target in direct_call_targets(*program_address, &bytes) {
            if let Some(name) = addresses.get(&target) {
                helpers.insert((*name).to_owned());
            }
        }
        programs_decoded += 1;
        decoded_bytes += length;
    }

    Ok(BpfHelperDiscovery {
        architecture: std::env::consts::ARCH,
        programs_seen: programs.len(),
        programs_decoded,
        program_read_failures,
        decoded_bytes,
        helpers: helpers.into_iter().collect(),
    })
}

fn parse_kallsyms(input: &str) -> Vec<KernelSymbol> {
    input
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_ascii_whitespace();
            let address = u64::from_str_radix(fields.next()?, 16).ok()?;
            let _kind = fields.next()?;
            let name = fields.next()?.to_owned();
            let bpf_program = fields.next() == Some("[bpf]");
            Some(KernelSymbol {
                address,
                name,
                bpf_program,
            })
        })
        .collect()
}

fn read_kcore_segments(file: &File) -> Result<Vec<LoadSegment>, BpfHelperError> {
    let mut header = [0_u8; ELF_HEADER_BYTES];
    file.read_exact_at(&mut header, 0)
        .map_err(|_| BpfHelperError::InvalidKcore("cannot read ELF header"))?;
    if &header[0..4] != b"\x7fELF" {
        return Err(BpfHelperError::InvalidKcore("bad ELF magic"));
    }
    if header[4] != 2 || header[5] != 1 {
        return Err(BpfHelperError::InvalidKcore(
            "expected 64-bit little-endian ELF",
        ));
    }
    let program_offset = le_u64(&header, 32)?;
    let entry_size = usize::from(le_u16(&header, 54)?);
    let entry_count = usize::from(le_u16(&header, 56)?);
    if entry_size < ELF64_PROGRAM_HEADER_BYTES || entry_count > 4096 {
        return Err(BpfHelperError::InvalidKcore(
            "invalid program-header dimensions",
        ));
    }

    let mut segments = Vec::new();
    for index in 0..entry_count {
        let offset = program_offset
            .checked_add((index * entry_size) as u64)
            .ok_or(BpfHelperError::InvalidKcore(
                "program-header offset overflow",
            ))?;
        let mut header = vec![0_u8; entry_size];
        file.read_exact_at(&mut header, offset)
            .map_err(|_| BpfHelperError::InvalidKcore("cannot read program header"))?;
        if le_u32(&header, 0)? != PT_LOAD {
            continue;
        }
        segments.push(LoadSegment {
            offset: le_u64(&header, 8)?,
            address: le_u64(&header, 16)?,
            size: le_u64(&header, 32)?,
        });
    }
    if segments.is_empty() {
        return Err(BpfHelperError::InvalidKcore("no loadable segments"));
    }
    Ok(segments)
}

fn direct_call_targets(address: u64, bytes: &[u8]) -> Vec<u64> {
    let mut decoder = Decoder::with_ip(64, bytes, address, DecoderOptions::NONE);
    let mut targets = Vec::new();
    while decoder.can_decode() {
        let instruction = decoder.decode();
        if instruction.mnemonic() == Mnemonic::Call
            && matches!(
                instruction.op0_kind(),
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
            )
        {
            targets.push(instruction.near_branch_target());
        }
    }
    targets
}

fn le_u16(bytes: &[u8], offset: usize) -> Result<u16, BpfHelperError> {
    bytes
        .get(offset..offset + 2)
        .and_then(|value| value.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or(BpfHelperError::InvalidKcore("truncated u16"))
}

fn le_u32(bytes: &[u8], offset: usize) -> Result<u32, BpfHelperError> {
    bytes
        .get(offset..offset + 4)
        .and_then(|value| value.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(BpfHelperError::InvalidKcore("truncated u32"))
}

fn le_u64(bytes: &[u8], offset: usize) -> Result<u64, BpfHelperError> {
    bytes
        .get(offset..offset + 8)
        .and_then(|value| value.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or(BpfHelperError::InvalidKcore("truncated u64"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_only_direct_near_calls() {
        // call +5, nop, indirect call rax
        let bytes = [0xe8, 5, 0, 0, 0, 0x90, 0xff, 0xd0];
        assert_eq!(direct_call_targets(0x1000, &bytes), vec![0x100a]);
    }

    #[test]
    fn identifies_only_kallsyms_bpf_module_markers() {
        let symbols = parse_kallsyms(
            "0000000000001000 t bpf_prog_a [bpf]\n\
             0000000000001010 T helper\n\
             0000000000001020 t bpf_prog_not_jit\n",
        );
        assert_eq!(symbols.len(), 3);
        assert!(symbols[0].bpf_program);
        assert!(!symbols[1].bpf_program);
        assert!(!symbols[2].bpf_program);
    }
}
