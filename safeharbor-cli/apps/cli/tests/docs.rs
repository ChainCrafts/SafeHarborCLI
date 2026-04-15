use std::{fs, path::PathBuf};

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn docs_text() -> String {
    let root = repository_root();
    let mut text = String::new();
    for path in [
        root.join("README.md"),
        root.join("CHANGELOG.md"),
        root.join("docs/artifact-map.md"),
        root.join("docs/quickstart.md"),
        root.join("docs/review-workflow.md"),
        root.join("docs/battlechain-operations.md"),
        root.join("docs/agent-sdk.md"),
        root.join("docs/command-model.md"),
        root.join("docs/battlechain-adapter-requirements.md"),
        root.join("docs/dogfood-template.md"),
        root.join("docs/dogfood/simple-vault-fixture.md"),
        root.join("docs/release-checklist.md"),
    ] {
        text.push_str(
            &fs::read_to_string(&path)
                .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display())),
        );
        text.push('\n');
    }
    text
}

#[test]
fn docs_cover_current_v01_operator_path_and_artifacts() {
    let text = docs_text();

    for required in [
        "shcli scan",
        "shcli review",
        "--approve-defaults",
        "shcli compile",
        "shcli battlechain prepare",
        "shcli status",
        "shcli doctor",
        "shcli registry publish",
        "cargo run -p agent-sdk --example simple_consumer",
        ".safeharbor/analysis/analysis.graph.json",
        ".safeharbor/analysis/structural-candidates.json",
        ".safeharbor/analysis/standards-recognition.json",
        ".safeharbor/review/review-state.json",
        ".safeharbor/review/reviewed-input.json",
        ".safeharbor/battlechain/prepare.json",
        ".safeharbor/registry/publish.json",
        "metadata.generated_at",
        "0.1.0 Release Candidate",
    ] {
        assert!(
            text.contains(required),
            "docs missing required text: {required}"
        );
    }
}

#[test]
fn docs_do_not_advertise_unimplemented_v01_commands() {
    let text = docs_text();

    for banned in [
        "shcli init",
        "create-agreement",
        "request-attack",
        "shcli export",
    ] {
        assert!(
            !text.contains(banned),
            "docs still mention banned text: {banned}"
        );
    }
}
