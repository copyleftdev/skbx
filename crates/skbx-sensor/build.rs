use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=bpf/skbx.bpf.c");
    println!("cargo:rerun-if-changed=bpf/include");

    if env::var_os("CARGO_FEATURE_EBPF").is_none() {
        return;
    }

    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let bpf = manifest.join("bpf");
    let out = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let vmlinux = out.join("vmlinux.h");
    let object = out.join("skbx.bpf.o");

    let output = Command::new("bpftool")
        .args([
            "btf",
            "dump",
            "file",
            "/sys/kernel/btf/vmlinux",
            "format",
            "c",
        ])
        .output()
        .expect("failed to run bpftool; install bpftool or build without feature ebpf");
    assert!(
        output.status.success(),
        "bpftool could not generate vmlinux.h: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    std::fs::write(&vmlinux, output.stdout).expect("write generated vmlinux.h");

    let arch = match env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("x86_64") => "x86",
        Ok("aarch64") => "arm64",
        Ok(other) => panic!("unsupported eBPF target architecture: {other}"),
        Err(error) => panic!("missing CARGO_CFG_TARGET_ARCH: {error}"),
    };

    let status = Command::new("clang")
        .args([
            "-O2",
            "-g",
            "-Wall",
            "-Werror",
            "-target",
            "bpf",
            &format!("-D__TARGET_ARCH_{arch}"),
            &format!("-I{}", out.display()),
            &format!("-I{}", bpf.join("include").display()),
            "-c",
            &bpf.join("skbx.bpf.c").to_string_lossy(),
            "-o",
            &object.to_string_lossy(),
        ])
        .status()
        .expect("failed to run clang; install clang with the BPF backend");
    assert!(status.success(), "clang failed to compile skbx.bpf.c");

    println!("cargo:rustc-env=SKBX_BPF_OBJ={}", object.display());
}
