use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

fn unique_temp_dir() -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    let dir = std::env::temp_dir().join(format!("safeharbor-cli-smoke-test-{unique}"));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn fixture_dir() -> PathBuf {
    workspace_root().join("examples/simple-vault")
}

fn schema_path() -> PathBuf {
    workspace_root().join("schemas/safeharbor.manifest.schema.json")
}

fn copy_file(from: &Path, to: &Path) {
    if let Some(parent) = to.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::copy(from, to).unwrap();
}

fn write_workspace(root: &Path) {
    copy_file(
        &fixture_dir().join("safeharbor.input.json"),
        &root.join("examples/simple-vault/safeharbor.input.json"),
    );
    copy_file(
        &schema_path(),
        &root.join("schemas/safeharbor.manifest.schema.json"),
    );

    fs::write(
        root.join("safeharbor.toml"),
        r#"
[input]
file = "examples/simple-vault/safeharbor.input.json"

[output]
manifest = "examples/simple-vault/out/safeharbor.manifest.json"

[schema]
file = "schemas/safeharbor.manifest.schema.json"
"#,
    )
    .unwrap();
}

#[test]
fn cli_can_emit_and_validate_the_golden_manifest_from_static_input() {
    let root = unique_temp_dir();
    write_workspace(&root);

    let config_path = root.join("safeharbor.toml");
    let manifest_path = root.join("examples/simple-vault/out/safeharbor.manifest.json");
    let expected_path = fixture_dir().join("expected.safeharbor.manifest.json");

    let compile = Command::new(env!("CARGO_BIN_EXE_shcli"))
        .arg("compile")
        .arg("--config")
        .arg(&config_path)
        .output()
        .unwrap();

    assert!(compile.status.success(), "{compile:#?}");
    assert!(String::from_utf8_lossy(&compile.stdout).contains("Emitted manifest successfully"));

    let emitted = fs::read_to_string(&manifest_path).unwrap();
    let expected = fs::read_to_string(&expected_path).unwrap();
    assert_eq!(emitted, expected);

    let validate = Command::new(env!("CARGO_BIN_EXE_shcli"))
        .current_dir(std::env::temp_dir())
        .arg("validate")
        .arg("--manifest")
        .arg(&manifest_path)
        .output()
        .unwrap();

    assert!(validate.status.success(), "{validate:#?}");
    assert!(String::from_utf8_lossy(&validate.stdout).contains("Manifest is valid"));

    fs::remove_dir_all(root).unwrap();
}
