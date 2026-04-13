use anyhow::{Context, Result};
use manifest::{SafeHarborManifest, validate_manifest_schema, write_manifest};
use review_engine::{
    DraftCompileInput, ReviewedInput, load_draft_compile_input, sha256_file,
    validate_reviewed_input_for_compile,
};
use std::{fs, path::Path};

pub fn compile_static_input(
    input_path: &Path,
    schema_path: &Path,
    output_path: &Path,
) -> Result<SafeHarborManifest> {
    let input = load_static_input(input_path)?;

    validate_manifest_schema(&input.manifest, schema_path).with_context(|| {
        format!(
            "compiled manifest from static input does not satisfy schema: input={}, schema={}",
            input_path.display(),
            schema_path.display()
        )
    })?;

    write_manifest(output_path, &input.manifest)?;

    Ok(input.manifest)
}

pub fn compile_reviewed_input(
    draft_input_path: &Path,
    reviewed_input_path: &Path,
    schema_path: &Path,
    manifest_output_path: &Path,
    summary_output_path: &Path,
) -> Result<SafeHarborManifest> {
    let draft = load_draft_compile_input(draft_input_path)?;
    let reviewed = load_reviewed_input(reviewed_input_path)?;
    let draft_digest = sha256_file(draft_input_path)?;

    validate_reviewed_input_for_compile(&reviewed, &draft, &draft_digest)?;

    let manifest = assemble_manifest_from_reviewed(&draft, &reviewed);
    validate_manifest_schema(&manifest, schema_path).with_context(|| {
        format!(
            "compiled manifest from reviewed input does not satisfy schema: input={}, reviewed={}, schema={}",
            draft_input_path.display(),
            reviewed_input_path.display(),
            schema_path.display()
        )
    })?;

    write_manifest(manifest_output_path, &manifest)?;
    write_summary(summary_output_path, &manifest)?;

    Ok(manifest)
}

fn assemble_manifest_from_reviewed(
    draft: &DraftCompileInput,
    reviewed: &ReviewedInput,
) -> SafeHarborManifest {
    let mut manifest = draft.manifest.clone();
    manifest.scope = reviewed.reviewed_scope.to_manifest_scope();
    manifest.roles = reviewed
        .reviewed_roles
        .iter()
        .map(|role| role.reviewed_role.clone())
        .collect();
    manifest.invariants = reviewed
        .all_invariants()
        .map(|invariant| invariant.to_manifest_invariant())
        .collect();
    manifest.review = reviewed.review.clone();
    manifest
}

fn load_static_input(path: &Path) -> Result<DraftCompileInput> {
    load_draft_compile_input(path)
}

fn load_reviewed_input(path: &Path) -> Result<ReviewedInput> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read reviewed input file: {}", path.display()))?;
    serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse reviewed input JSON: {}", path.display()))
}

fn write_summary(path: &Path, manifest: &SafeHarborManifest) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create summary output directory: {}",
                parent.display()
            )
        })?;
    }

    let in_scope_contracts = manifest
        .scope
        .contracts
        .iter()
        .filter(|contract| contract.in_scope)
        .count();
    let in_scope_selectors = manifest
        .scope
        .contracts
        .iter()
        .flat_map(|contract| contract.selectors.as_deref().unwrap_or(&[]))
        .filter(|selector| selector.in_scope)
        .count();
    let mut summary = String::new();
    summary.push_str("# SafeHarbor Manifest Summary\n\n");
    summary.push_str(&format!("Protocol: {}\n", manifest.protocol.name));
    summary.push_str(&format!("Slug: {}\n", manifest.protocol.slug));
    summary.push_str(&format!("Network: {}\n", manifest.deployment.network));
    summary.push_str(&format!("Contracts in scope: {in_scope_contracts}\n"));
    summary.push_str(&format!("Selectors in scope: {in_scope_selectors}\n"));
    summary.push_str(&format!("Roles: {}\n", manifest.roles.len()));
    summary.push_str(&format!("Invariants: {}\n\n", manifest.invariants.len()));
    summary.push_str("## Invariants\n\n");
    for invariant in &manifest.invariants {
        summary.push_str(&format!(
            "- {} [{}] {}: {}\n",
            invariant.id,
            render_json_string(&invariant.severity),
            render_json_string(&invariant.kind),
            invariant.description
        ));
    }

    fs::write(path, summary)
        .with_context(|| format!("failed to write summary file: {}", path.display()))
}

fn render_json_string<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(ToString::to_string))
        .unwrap_or_else(|| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use manifest::{read_manifest, validate_file};
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_dir() -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        let dir = std::env::temp_dir().join(format!("safeharbor-compiler-test-{unique}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn fixture_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/simple-vault")
    }

    fn schema_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../schemas/safeharbor.manifest.schema.json")
    }

    #[test]
    fn compiles_static_input_into_expected_manifest() {
        let dir = unique_temp_dir();
        let output_path = dir.join("safeharbor.manifest.json");
        let input_path = fixture_dir().join("safeharbor.input.json");
        let expected_path = fixture_dir().join("expected.safeharbor.manifest.json");
        let schema_path = schema_path();

        let compiled = compile_static_input(&input_path, &schema_path, &output_path).unwrap();
        let emitted = read_manifest(&output_path).unwrap();
        let expected = read_manifest(&expected_path).unwrap();
        let emitted_bytes = std::fs::read_to_string(&output_path).unwrap();
        let expected_bytes = std::fs::read_to_string(&expected_path).unwrap();

        assert_eq!(compiled, expected);
        assert_eq!(emitted, expected);
        assert_eq!(emitted_bytes, expected_bytes);
        validate_file(&output_path, &schema_path).unwrap();

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rejects_invalid_compile_input_shape() {
        let dir = unique_temp_dir();
        let input_path = dir.join("safeharbor.input.json");
        let output_path = dir.join("safeharbor.manifest.json");

        std::fs::write(&input_path, r#"{ "note": "not a compile input" }"#).unwrap();

        let err = compile_static_input(&input_path, &schema_path(), &output_path).unwrap_err();
        assert!(err.to_string().contains("failed to parse JSON file"));

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn reviewed_compile_reports_missing_reviewed_input() {
        let dir = unique_temp_dir();
        let manifest_output_path = dir.join("safeharbor.manifest.json");
        let summary_output_path = dir.join("safeharbor.summary.md");
        let reviewed_input_path = dir.join("missing-reviewed-input.json");
        let input_path = fixture_dir().join("safeharbor.input.json");
        let schema_path = schema_path();

        let err = compile_reviewed_input(
            &input_path,
            &reviewed_input_path,
            &schema_path,
            &manifest_output_path,
            &summary_output_path,
        )
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("failed to read reviewed input file")
        );

        std::fs::remove_dir_all(dir).unwrap();
    }
}
