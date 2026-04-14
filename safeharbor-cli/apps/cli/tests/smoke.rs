use serde_json::Value;
use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
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

fn repository_root() -> PathBuf {
    workspace_root()
        .canonicalize()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
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

fn append_registry_publish_config(root: &Path, rpc_url: &str, registry_address: &str) {
    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(root.join("safeharbor.toml"))
        .unwrap();
    writeln!(
        file,
        r#"
[battlechain]
network = "battlechain-testnet"
chain_id = 627
rpc_url = "{rpc_url}"

[registry]
address = "{registry_address}"
"#
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

fn write_compiled_battlechain_workspace(root: &Path, include_adapter: bool, rpc_url: Option<&str>) {
    fs::create_dir_all(root.join("examples/simple-vault/out")).unwrap();
    fs::create_dir_all(root.join(".safeharbor/review")).unwrap();
    fs::create_dir_all(root.join("schemas")).unwrap();

    let mut manifest: Value = serde_json::from_str(
        &fs::read_to_string(phase_one_fixture_dir().join("expected.safeharbor.manifest.json"))
            .unwrap(),
    )
    .unwrap();
    if !include_adapter {
        manifest.as_object_mut().unwrap().remove("adapters");
    }
    fs::write(
        root.join("examples/simple-vault/out/safeharbor.manifest.json"),
        format!("{}\n", serde_json::to_string_pretty(&manifest).unwrap()),
    )
    .unwrap();
    fs::write(
        root.join("examples/simple-vault/out/safeharbor.summary.md"),
        "# Summary\n",
    )
    .unwrap();
    fs::write(
        root.join("examples/simple-vault/safeharbor.input.json"),
        "{}",
    )
    .unwrap();
    fs::write(root.join(".safeharbor/review/reviewed-input.json"), "{}").unwrap();
    copy_file(
        &schema_path(),
        &root.join("schemas/safeharbor.manifest.schema.json"),
    );

    let battlechain_section = match rpc_url {
        Some(rpc_url) => format!(
            r#"
[battlechain]
network = "battlechain-testnet"
chain_id = 627
rpc_url = "{rpc_url}"
"#
        ),
        None => r#"
[battlechain]
network = "battlechain-testnet"
chain_id = 627
"#
        .to_string(),
    };

    fs::write(
        root.join("safeharbor.toml"),
        format!(
            r#"
[input]
file = "examples/simple-vault/safeharbor.input.json"

[output]
manifest = "examples/simple-vault/out/safeharbor.manifest.json"
summary = "examples/simple-vault/out/safeharbor.summary.md"

[schema]
file = "schemas/safeharbor.manifest.schema.json"

[review]
reviewed_input = ".safeharbor/review/reviewed-input.json"
{battlechain_section}
"#
        ),
    )
    .unwrap();
}

fn start_fake_rpc(chain_id_hex: &'static str, code: &'static str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming().take(8) {
            let mut stream = stream.unwrap();
            handle_fake_rpc_connection(&mut stream, chain_id_hex, code);
        }
    });
    format!("http://{addr}")
}

const ANVIL_OWNER: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

struct ChildGuard {
    child: Child,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_anvil() -> (ChildGuard, String) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let child = Command::new("anvil")
        .arg("--host")
        .arg("127.0.0.1")
        .arg("--port")
        .arg(port.to_string())
        .arg("--chain-id")
        .arg("627")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let rpc_url = format!("http://127.0.0.1:{port}");

    for _ in 0..50 {
        let output = Command::new("cast")
            .arg("rpc")
            .arg("--rpc-url")
            .arg(&rpc_url)
            .arg("eth_chainId")
            .output()
            .unwrap();
        if output.status.success() {
            return (ChildGuard { child }, rpc_url);
        }
        thread::sleep(Duration::from_millis(100));
    }

    panic!("anvil did not become ready at {rpc_url}");
}

fn deploy_registry(rpc_url: &str) -> String {
    let contracts_root = repository_root().join("contracts");
    let output = Command::new("forge")
        .current_dir(repository_root())
        .arg("create")
        .arg("--root")
        .arg(&contracts_root)
        .arg("--broadcast")
        .arg("--rpc-url")
        .arg(rpc_url)
        .arg("--unlocked")
        .arg("--from")
        .arg(ANVIL_OWNER)
        .arg("--color")
        .arg("never")
        .arg("src/SafeHarborManifestRegistry.sol:SafeHarborManifestRegistry")
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:#?}");
    let rendered = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    for line in rendered.lines() {
        let line = line.trim();
        if let Some(address) = line.strip_prefix("Deployed to:") {
            return address.trim().to_string();
        }
    }

    panic!("failed to parse registry deployment address from forge output:\n{rendered}");
}

fn extract_calldata(stdout: &[u8]) -> String {
    extract_output_value(stdout, "calldata     : ")
}

fn extract_output_value(stdout: &[u8], prefix: &str) -> String {
    let stdout = String::from_utf8_lossy(stdout);
    stdout
        .lines()
        .find_map(|line| line.trim().strip_prefix(prefix))
        .unwrap_or_else(|| panic!("failed to find '{prefix}' in output:\n{stdout}"))
        .to_string()
}

fn send_raw_calldata(rpc_url: &str, to: &str, calldata: &str) {
    let tx = format!(r#"{{"from":"{ANVIL_OWNER}","to":"{to}","data":"{calldata}"}}"#);
    let output = Command::new("cast")
        .arg("rpc")
        .arg("--rpc-url")
        .arg(rpc_url)
        .arg("eth_sendTransaction")
        .arg(tx)
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:#?}");
}

fn handle_fake_rpc_connection(stream: &mut TcpStream, chain_id_hex: &str, code: &str) {
    let mut buffer = [0u8; 4096];
    let bytes_read = stream.read(&mut buffer).unwrap();
    let request = String::from_utf8_lossy(&buffer[..bytes_read]);
    let result = if request.contains("eth_chainId") {
        chain_id_hex
    } else if request.contains("eth_getCode") {
        code
    } else {
        "0x"
    };
    let body = format!(r#"{{"jsonrpc":"2.0","id":1,"result":"{result}"}}"#);
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(response.as_bytes()).unwrap();
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

    let prepare = Command::new(env!("CARGO_BIN_EXE_shcli"))
        .current_dir(&root)
        .arg("battlechain")
        .arg("prepare")
        .arg("--config")
        .arg(&config_path)
        .output()
        .unwrap();

    assert!(prepare.status.success(), "{prepare:#?}");
    assert!(root.join(".safeharbor/battlechain/prepare.json").exists());
    assert!(String::from_utf8_lossy(&prepare.stdout).contains("BattleChain prepare completed"));

    let status = Command::new(env!("CARGO_BIN_EXE_shcli"))
        .current_dir(&root)
        .arg("status")
        .arg("--config")
        .arg(&config_path)
        .output()
        .unwrap();

    assert!(status.status.success(), "{status:#?}");
    let status_stdout = String::from_utf8_lossy(&status.stdout);
    assert!(status_stdout.contains("BattleChain status"));
    assert!(status_stdout.contains("lifecycle: AGREEMENT_CREATED (local)"));

    let doctor = Command::new(env!("CARGO_BIN_EXE_shcli"))
        .current_dir(&root)
        .arg("doctor")
        .arg("--config")
        .arg(&config_path)
        .output()
        .unwrap();

    assert!(doctor.status.success(), "{doctor:#?}");
    let doctor_stdout = String::from_utf8_lossy(&doctor.stdout);
    assert!(doctor_stdout.contains("[WARN] RPC reachable"));
    assert!(doctor_stdout.contains("summary:"));

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn cli_registry_publish_prepares_and_verifies_local_publication() {
    let root = unique_temp_dir();
    let fixture = foundry_fixture_dir();
    copy_dir(&fixture, &root);
    chmod_executable(&root.join("bin/mock-aderyn"));
    write_review_compile_workspace(&root);

    let (_anvil, rpc_url) = start_anvil();
    let registry_address = deploy_registry(&rpc_url);
    append_registry_publish_config(&root, &rpc_url, &registry_address);

    let config_path = root.join("safeharbor.toml");
    let manifest_uri = "ipfs://bafy-safeharbor-smoke";

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

    let compile = Command::new(env!("CARGO_BIN_EXE_shcli"))
        .current_dir(&root)
        .arg("compile")
        .arg("--config")
        .arg(&config_path)
        .output()
        .unwrap();
    assert!(compile.status.success(), "{compile:#?}");

    let prepare = Command::new(env!("CARGO_BIN_EXE_shcli"))
        .current_dir(&root)
        .arg("battlechain")
        .arg("prepare")
        .arg("--config")
        .arg(&config_path)
        .output()
        .unwrap();
    assert!(prepare.status.success(), "{prepare:#?}");

    let publish = Command::new(env!("CARGO_BIN_EXE_shcli"))
        .current_dir(&root)
        .arg("registry")
        .arg("publish")
        .arg("--config")
        .arg(&config_path)
        .arg("--manifest-uri")
        .arg(manifest_uri)
        .output()
        .unwrap();
    assert!(publish.status.success(), "{publish:#?}");
    let publish_stdout = String::from_utf8_lossy(&publish.stdout);
    assert!(
        publish_stdout.contains("Registry publish prepared"),
        "{publish_stdout}"
    );
    assert!(
        publish_stdout.contains("readback     : no publication"),
        "{publish_stdout}"
    );
    let calldata = extract_calldata(&publish.stdout);
    let manifest_hash = extract_output_value(&publish.stdout, "manifest hash: ");

    send_raw_calldata(&rpc_url, &registry_address, &calldata);

    let verify = Command::new(env!("CARGO_BIN_EXE_shcli"))
        .current_dir(&root)
        .arg("registry")
        .arg("publish")
        .arg("--config")
        .arg(&config_path)
        .arg("--manifest-uri")
        .arg(manifest_uri)
        .output()
        .unwrap();
    assert!(verify.status.success(), "{verify:#?}");
    let verify_stdout = String::from_utf8_lossy(&verify.stdout);
    assert!(
        verify_stdout.contains("readback     : match"),
        "{verify_stdout}"
    );
    assert!(
        verify_stdout.contains("manifest URI : ipfs://bafy-safeharbor-smoke"),
        "{verify_stdout}"
    );
    assert!(
        verify_stdout.contains(&format!("manifest hash: {manifest_hash}")),
        "{verify_stdout}"
    );

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn battlechain_status_reports_missing_agreement_address() {
    let root = unique_temp_dir();
    write_compiled_battlechain_workspace(&root, false, None);

    let status = Command::new(env!("CARGO_BIN_EXE_shcli"))
        .current_dir(&root)
        .arg("status")
        .arg("--config")
        .arg(root.join("safeharbor.toml"))
        .output()
        .unwrap();

    assert!(status.status.success(), "{status:#?}");
    let stdout = String::from_utf8_lossy(&status.stdout);
    assert!(stdout.contains("agreement: missing"));
    assert!(stdout.contains("remote chain: unavailable"));

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn battlechain_doctor_fails_on_wrong_remote_chain_id() {
    let root = unique_temp_dir();
    let rpc_url = start_fake_rpc("0x1", "0x6000");
    write_compiled_battlechain_workspace(&root, true, Some(&rpc_url));

    let doctor = Command::new(env!("CARGO_BIN_EXE_shcli"))
        .current_dir(&root)
        .arg("doctor")
        .arg("--config")
        .arg(root.join("safeharbor.toml"))
        .output()
        .unwrap();

    assert!(!doctor.status.success(), "{doctor:#?}");
    let stdout = String::from_utf8_lossy(&doctor.stdout);
    assert!(stdout.contains("[FAIL] correct chain detected"));
    assert!(stdout.contains("remote chain ID 1 does not match resolved chain ID 627"));

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
