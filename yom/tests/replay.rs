use std::path::PathBuf;
use std::process::Command;

fn yara_available() -> bool {
    Command::new("yara64.exe")
        .arg("-v")
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

#[test]
fn replay_matches_mz_when_yara_is_available() {
    if !yara_available() {
        eprintln!("skipping replay test: yara64.exe is not available");
        return;
    }

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace parent")
        .to_path_buf();
    let file = root
        .join("examples")
        .join("replay")
        .join("mapping_sample.json");
    let rules = root.join("examples").join("rules").join("mz.yar");
    let exe = env!("CARGO_BIN_EXE_yom");

    let out = Command::new(exe)
        .args([
            "replay",
            "--file",
            file.to_str().expect("replay path"),
            "--rules",
            rules.to_str().expect("rules path"),
        ])
        .output()
        .expect("run yom replay");

    assert!(
        out.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("\"rule\":\"mz_header\""));
}
