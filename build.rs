use std::env;
use std::ffi::OsString;
use std::path::PathBuf;
use libbpf_cargo::SkeletonBuilder;

fn main() {
    let mut out =
        PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"));
    out.push("sensor.skel.rs");
    
    let bpf_source = "src-bpf/sensor.bpf.c";

    SkeletonBuilder::new()
        .source(bpf_source)
        .clang_args([
            OsString::from("-Isrc-bpf"),
            OsString::from("-g"),
            OsString::from("-O2"),
            OsString::from("-target"),
            OsString::from("bpf"),
        ])
        .build_and_generate(&out)
        .expect("Failed to build eBPF skeleton. Check that clang and llvm are installed.");

    println!("cargo:rerun-if-changed={}", bpf_source);
    println!("cargo:rerun-if-changed=src-bpf/common.h");
}
