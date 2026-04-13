use serde_json::Value;
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

fn phase_one_fixture_dir() -> PathBuf {
    workspace_root().join("examples/simple-vault")
}

fn foundry_fixture_dir() -> PathBuf {
    workspace_root().join("examples/foundry-simple-vault")
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

fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();

    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let source_path = entry.path();
        let target_path = to.join(entry.file_name());
        let file_type = entry.file_type().unwrap();

        if file_type.is_dir() {
            copy_dir(&source_path, &target_path);
        } else {
            copy_file(&source_path, &target_path);
        }
    }
}

fn write_review_compile_workspace(root: &Path) {
    let mut draft: Value = serde_json::from_str(
        &fs::read_to_string(phase_one_fixture_dir().join("safeharbor.input.json")).unwrap(),
    )
    .unwrap();
    draft["analysis_contract_mappings"] = serde_json::json!([
        {
            "manifest_contract_id": "vault_core",
            "source_analysis_contract_id": "src/SimpleVault.sol:SimpleVault"
        }
    ]);
    fs::create_dir_all(root.join("examples/simple-vault")).unwrap();
    fs::write(
        root.join("examples/simple-vault/safeharbor.input.json"),
        serde_json::to_string_pretty(&draft).unwrap(),
    )
    .unwrap();
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
summary = "examples/simple-vault/out/safeharbor.summary.md"

[schema]
file = "schemas/safeharbor.manifest.schema.json"

[review]
analysis_dir = ".safeharbor/analysis"
state_file = ".safeharbor/review/review-state.json"
reviewed_input = ".safeharbor/review/reviewed-input.json"
low_confidence_threshold = 75

[scan]
repo_root = "."
output_dir = ".safeharbor/analysis"
forge_bin = "forge"
aderyn_bin = "bin/mock-aderyn"
cache = true
"#,
    )
    .unwrap();
}

#[cfg(unix)]
fn chmod_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    let mut perms = fs::metadata(path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms).unwrap();
}

#[cfg(not(unix))]
fn chmod_executable(_: &Path) {}

fn scrub_generated_at(path: &Path) -> Value {
    let mut value: Value = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    value["metadata"]["generated_at"] = Value::String("1970-01-01T00:00:00Z".to_string());
    value
}

#[test]
fn cli_can_review_compile_and_validate_the_foundry_fixture() {
    let root = unique_temp_dir();
    let fixture = foundry_fixture_dir();
    copy_dir(&fixture, &root);
    chmod_executable(&root.join("bin/mock-aderyn"));
    write_review_compile_workspace(&root);

    let config_path = root.join("safeharbor.toml");
    let manifest_path = root.join("examples/simple-vault/out/safeharbor.manifest.json");
    let summary_path = root.join("examples/simple-vault/out/safeharbor.summary.md");

    let scan = Command::new(env!("CARGO_BIN_EXE_shcli"))
        .current_dir(&root)
        .arg("scan")
        .arg("--config")
        .arg(&config_path)
        .output()
        .unwrap();

    assert!(scan.status.success(), "{scan:#?}");

    let review = Command::new(env!("CARGO_BIN_EXE_shcli"))
        .current_dir(&root)
        .arg("review")
        .arg("--config")
        .arg(&config_path)
        .arg("--approve-defaults")
        .output()
        .unwrap();

    assert!(review.status.success(), "{review:#?}");
    assert!(root.join(".safeharbor/review/review-state.json").exists());
    assert!(root.join(".safeharbor/review/reviewed-input.json").exists());

    let compile = Command::new(env!("CARGO_BIN_EXE_shcli"))
        .arg("compile")
        .arg("--config")
        .arg(&config_path)
        .output()
        .unwrap();

    assert!(compile.status.success(), "{compile:#?}");
    assert!(String::from_utf8_lossy(&compile.stdout).contains("Emitted manifest successfully"));
    assert!(manifest_path.exists());
    assert!(summary_path.exists());

    let emitted: Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
    assert_eq!(emitted["scope"]["contracts"][0]["id"], "vault_core");
    assert_eq!(emitted["roles"][0]["id"], "owner");
    assert!(emitted["invariants"].as_array().unwrap().len() >= 4);

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

#[test]
fn cli_can_scan_the_foundry_fixture_and_match_golden_outputs() {
    let root = unique_temp_dir();
    let fixture = foundry_fixture_dir();
    copy_dir(&fixture, &root);
    chmod_executable(&root.join("bin/mock-aderyn"));

    let scan = Command::new(env!("CARGO_BIN_EXE_shcli"))
        .current_dir(&root)
        .arg("scan")
        .arg("--config")
        .arg(root.join("safeharbor.toml"))
        .output()
        .unwrap();

    assert!(scan.status.success(), "{scan:#?}");
    let stdout = String::from_utf8_lossy(&scan.stdout);
    assert!(stdout.contains("Found 1 contracts"));
    assert!(stdout.contains("Found 7 external/public selectors"));
    assert!(stdout.contains("Found 5 privileged selectors"));
    assert!(stdout.contains("Found 2 payable entrypoints"));
    assert!(stdout.contains("Found 1 role candidates"));
    assert!(stdout.contains("Found 1 upgrade surfaces"));
    assert!(stdout.contains("Recognized 3 standards or patterns"));
    assert!(stdout.contains("Suggested 3 semantic templates"));

    let actual_analysis =
        scrub_generated_at(&root.join(".safeharbor/analysis/analysis.graph.json"));
    let actual_candidates =
        scrub_generated_at(&root.join(".safeharbor/analysis/structural-candidates.json"));
    let actual_recognition =
        scrub_generated_at(&root.join(".safeharbor/analysis/standards-recognition.json"));
    let expected_analysis =
        scrub_generated_at(&fixture.join("testdata/expected.analysis.graph.json"));
    let expected_candidates =
        scrub_generated_at(&fixture.join("testdata/expected.structural-candidates.json"));
    let expected_recognition =
        scrub_generated_at(&fixture.join("testdata/expected.standards-recognition.json"));

    assert_eq!(actual_analysis, expected_analysis);
    assert_eq!(actual_candidates, expected_candidates);
    assert_eq!(actual_recognition, expected_recognition);

    fs::remove_dir_all(root).unwrap();
}

#[test]
#[ignore = "runs only when aderyn is installed locally"]
fn cli_scan_can_run_against_live_aderyn() {
    let aderyn_available = Command::new("aderyn").arg("--version").output();
    if aderyn_available.is_err() {
        return;
    }

    let root = unique_temp_dir();
    let fixture = foundry_fixture_dir();
    fs::create_dir_all(root.join("src")).unwrap();
    copy_file(&fixture.join("foundry.toml"), &root.join("foundry.toml"));
    copy_file(
        &fixture.join("src/SimpleVault.sol"),
        &root.join("src/SimpleVault.sol"),
    );

    let scan = Command::new(env!("CARGO_BIN_EXE_shcli"))
        .current_dir(&root)
        .arg("scan")
        .arg("--repo-root")
        .arg(&root)
        .output()
        .unwrap();

    assert!(scan.status.success(), "{scan:#?}");
    assert!(
        root.join(".safeharbor/analysis/analysis.graph.json")
            .exists()
    );
    assert!(
        root.join(".safeharbor/analysis/structural-candidates.json")
            .exists()
    );
    assert!(
        root.join(".safeharbor/analysis/standards-recognition.json")
            .exists()
    );

    fs::remove_dir_all(root).unwrap();
}
