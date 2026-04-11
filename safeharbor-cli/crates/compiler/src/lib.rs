use anyhow::{Context, Result};
use manifest::{SafeHarborManifest, validate_manifest_schema, write_manifest};
use serde::Deserialize;
use std::{fs, path::Path};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticCompileInput {
    pub manifest: SafeHarborManifest,
}

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

fn load_static_input(path: &Path) -> Result<StaticCompileInput> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read compile input file: {}", path.display()))?;

    serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse compile input JSON: {}", path.display()))
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
        assert!(
            err.to_string()
                .contains("failed to parse compile input JSON")
        );

        std::fs::remove_dir_all(dir).unwrap();
    }
}
