use std::path::PathBuf;
use std::process::Command;

#[test]
fn replay_matches_mz() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let file = root.join("examples").join("replay").join("mapping_sample.json");
    let rules = root.join("examples").join("rules").join("mz.yar");
    let out = Command::new("cargo")
        .args(["run","--quiet","--bin","yom","--","replay","--file", file.to_str().unwrap(), "--rules", rules.to_str().unwrap()])
        .output()
        .expect("run");
    assert!(out.status.success(), "stdout: {}", String::from_utf8_lossy(&out.stdout));
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("\"rule\":\"mz_header\""));
}
