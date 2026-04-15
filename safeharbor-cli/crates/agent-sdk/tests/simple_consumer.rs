use std::{
    path::PathBuf,
    process::{Command, Stdio},
};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn simple_consumer_runs_against_sample_manifest() {
    let output = Command::new(env!("CARGO"))
        .current_dir(workspace_root())
        .arg("run")
        .arg("-q")
        .arg("-p")
        .arg("agent-sdk")
        .arg("--example")
        .arg("simple_consumer")
        .arg("--")
        .arg("examples/simple-vault/expected.safeharbor.manifest.json")
        .stderr(Stdio::inherit())
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:#?}");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Protocol: SimpleVault"));
    assert!(stdout.contains("INV-001"));
    assert!(stdout.contains("INV-003"));
    assert!(stdout.contains("selector 0x8456cb59 in scope: true"));
    assert!(stdout.contains("selector-access-breach"));
}
