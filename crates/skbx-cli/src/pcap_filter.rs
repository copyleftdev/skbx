use anyhow::{Context, Result, bail};
use pcap::{Capture, Linktype};
use skbx_sensor::{CbpfInsn, CbpfProgram, MAX_CBPF_INSNS};

#[repr(C)]
#[derive(Clone, Copy)]
struct NativeInstruction {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

const _: () = {
    assert!(
        std::mem::size_of::<NativeInstruction>() == std::mem::size_of::<pcap::BpfInstruction>()
    );
    assert!(
        std::mem::align_of::<NativeInstruction>() == std::mem::align_of::<pcap::BpfInstruction>()
    );
};

pub fn compile(expression: Option<&str>) -> Result<(CbpfProgram, CbpfProgram)> {
    let Some(expression) = expression.filter(|expression| !expression.is_empty()) else {
        return Ok((CbpfProgram::default(), CbpfProgram::default()));
    };
    Ok((
        compile_for_linktype(expression, Linktype::ETHERNET)
            .context("compile Ethernet pcap filter")?,
        // Linux libpcap uses DLT_RAW=12. Linktype::RAW is the portable
        // savefile LINKTYPE_RAW value (101), which pcap_open_dead rejects on
        // Linux even though the wire format is the same.
        compile_for_linktype(expression, Linktype(12)).context("compile raw-IP pcap filter")?,
    ))
}

pub fn compile_l2(expression: Option<&str>) -> Result<CbpfProgram> {
    compile_optional(expression, Linktype::ETHERNET, "Ethernet")
}

pub fn compile_l3(expression: Option<&str>) -> Result<CbpfProgram> {
    // Linux libpcap uses DLT_RAW=12. Linktype::RAW is the portable savefile
    // LINKTYPE_RAW value (101), which pcap_open_dead rejects on Linux.
    compile_optional(expression, Linktype(12), "raw-IP")
}

fn compile_optional(
    expression: Option<&str>,
    linktype: Linktype,
    label: &str,
) -> Result<CbpfProgram> {
    let Some(expression) = expression.filter(|expression| !expression.is_empty()) else {
        return Ok(CbpfProgram::default());
    };
    compile_for_linktype(expression, linktype)
        .with_context(|| format!("compile {label} pcap filter"))
}

fn compile_for_linktype(expression: &str, linktype: Linktype) -> Result<CbpfProgram> {
    let capture = Capture::dead(linktype).context("create dead libpcap capture")?;
    let native = capture
        .compile(expression, true)
        .with_context(|| format!("libpcap rejected {expression:?}"))?;
    let instructions = native.get_instructions();
    if instructions.is_empty() {
        bail!("libpcap produced an empty filter");
    }
    if instructions.len() > MAX_CBPF_INSNS {
        bail!(
            "pcap filter compiled to {} instructions; maximum is {MAX_CBPF_INSNS}",
            instructions.len()
        );
    }

    let mut output = CbpfProgram {
        len: instructions.len() as u32,
        ..CbpfProgram::default()
    };
    for (index, instruction) in instructions.iter().enumerate() {
        let instruction = copy_instruction(instruction);
        validate_instruction(index, instructions.len(), instruction)?;
        output.instructions[index] = instruction;
    }
    if output.instructions[instructions.len() - 1].code & 0x07 != 0x06 {
        bail!("pcap filter does not terminate with RET");
    }
    Ok(output)
}

fn copy_instruction(instruction: &pcap::BpfInstruction) -> CbpfInsn {
    // SAFETY: rust-pcap declares BpfInstruction repr(transparent) over
    // libpcap's repr(C) bpf_insn. NativeInstruction mirrors that four-field
    // ABI, and the compile-time checks above prove size and alignment.
    let native = unsafe {
        std::ptr::read((instruction as *const pcap::BpfInstruction).cast::<NativeInstruction>())
    };
    CbpfInsn {
        code: native.code,
        jt: native.jt,
        jf: native.jf,
        k: native.k,
    }
}

fn validate_instruction(index: usize, len: usize, instruction: CbpfInsn) -> Result<()> {
    let class = instruction.code & 0x07;
    let mode = instruction.code & 0xe0;
    let size = instruction.code & 0x18;
    let op = instruction.code & 0xf0;

    let supported = match class {
        0x00 => {
            matches!(mode, 0x00 | 0x20 | 0x40 | 0x60 | 0x80)
                && (matches!(mode, 0x00 | 0x60 | 0x80) || matches!(size, 0x00 | 0x08 | 0x10))
        }
        0x01 => {
            matches!(mode, 0x00 | 0x20 | 0x40 | 0x60 | 0x80 | 0xa0)
                && (matches!(mode, 0x00 | 0x60 | 0x80) || matches!(size, 0x00 | 0x08 | 0x10))
        }
        0x02 | 0x03 => true,
        0x04 => matches!(
            op,
            0x00 | 0x10 | 0x20 | 0x30 | 0x40 | 0x50 | 0x60 | 0x70 | 0x80 | 0x90 | 0xa0
        ),
        0x05 => matches!(op, 0x00 | 0x10 | 0x20 | 0x30 | 0x40),
        0x06 => matches!(instruction.code & 0x18, 0x00 | 0x10),
        0x07 => matches!(instruction.code & 0xf8, 0x00 | 0x80),
        _ => false,
    };
    if !supported {
        bail!(
            "libpcap emitted unsupported cBPF opcode {:#06x} at instruction {index}",
            instruction.code
        );
    }

    if class == 0x05 {
        if op == 0 {
            validate_target(index, len, instruction.k as usize)?;
        } else {
            validate_target(index, len, instruction.jt as usize)?;
            validate_target(index, len, instruction.jf as usize)?;
        }
    }
    if ((matches!(class, 0x00 | 0x01) && mode == 0x60) || matches!(class, 0x02 | 0x03))
        && instruction.k >= 16
    {
        bail!("cBPF scratch-memory index exceeds 15 at instruction {index}");
    }
    Ok(())
}

fn validate_target(index: usize, len: usize, relative: usize) -> Result<()> {
    let target = index
        .checked_add(1)
        .and_then(|next| next.checked_add(relative))
        .context("cBPF jump target overflow")?;
    if target >= len {
        bail!("cBPF jump at instruction {index} exits the program");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiles_common_filters_for_l2_and_l3() {
        for expression in [
            "tcp port 443",
            "host 127.0.0.1 and tcp",
            "ip6 or udp portrange 53-5353",
        ] {
            let (l2, l3) = compile(Some(expression)).unwrap();
            assert!(l2.len > 0);
            assert!(l3.len > 0);
            assert!(l2.len as usize <= MAX_CBPF_INSNS);
        }
    }

    #[test]
    fn empty_filter_is_a_zero_cost_program() {
        let (l2, l3) = compile(None).unwrap();
        assert_eq!(l2.len, 0);
        assert_eq!(l3.len, 0);
    }

    #[test]
    fn compiles_independent_tunnel_link_layers() {
        assert!(compile_l2(Some("ether proto 0x0800")).unwrap().len > 0);
        assert!(compile_l3(Some("icmp6 or tcp port 443")).unwrap().len > 0);
        assert_eq!(compile_l2(None).unwrap().len, 0);
        assert_eq!(compile_l3(None).unwrap().len, 0);
    }
}
