use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppConfig {
    pub input: Option<InputConfig>,
    pub output: Option<OutputConfig>,
    pub schema: Option<SchemaConfig>,
    pub scan: Option<ScanConfig>,
    pub review: Option<ReviewConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputConfig {
    pub file: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputConfig {
    pub manifest: PathBuf,
    pub summary: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaConfig {
    pub file: PathBuf,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct ScanConfig {
    pub repo_root: Option<PathBuf>,
    pub output_dir: Option<PathBuf>,
    pub aderyn_bin: Option<String>,
    pub forge_bin: Option<String>,
    pub cache: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct ReviewConfig {
    pub analysis_dir: Option<PathBuf>,
    pub state_file: Option<PathBuf>,
    pub reviewed_input: Option<PathBuf>,
    pub low_confidence_threshold: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompileSettings {
    pub input_file: PathBuf,
    pub reviewed_input_file: PathBuf,
    pub manifest_output: PathBuf,
    pub summary_output: PathBuf,
    pub schema_file: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewSettings {
    pub input_file: PathBuf,
    pub analysis_dir: PathBuf,
    pub state_file: PathBuf,
    pub reviewed_input_file: PathBuf,
    pub low_confidence_threshold: u32,
}

#[derive(Debug, Clone)]
pub struct LoadedConfig {
    pub config_path: PathBuf,
    pub workspace_root: PathBuf,
    pub app: AppConfig,
}

impl LoadedConfig {
    pub fn compile_settings(&self) -> Result<CompileSettings> {
        let input = self
            .app
            .input
            .as_ref()
            .context("missing [input] section required for compile")?;
        let output = self
            .app
            .output
            .as_ref()
            .context("missing [output] section required for compile")?;
        let schema = self
            .app
            .schema
            .as_ref()
            .context("missing [schema] section required for compile")?;

        Ok(CompileSettings {
            input_file: self.workspace_root.join(&input.file),
            reviewed_input_file: self.review_settings()?.reviewed_input_file,
            manifest_output: self.workspace_root.join(&output.manifest),
            summary_output: self.workspace_root.join(
                output
                    .summary
                    .clone()
                    .unwrap_or_else(|| default_summary_path(&output.manifest)),
            ),
            schema_file: self.workspace_root.join(&schema.file),
        })
    }

    pub fn review_settings(&self) -> Result<ReviewSettings> {
        let input = self
            .app
            .input
            .as_ref()
            .context("missing [input] section required for review")?;
        let review = self.app.review.clone().unwrap_or_default();

        Ok(ReviewSettings {
            input_file: self.workspace_root.join(&input.file),
            analysis_dir: self
                .workspace_root
                .join(review.analysis_dir.unwrap_or_else(default_analysis_dir)),
            state_file: self
                .workspace_root
                .join(review.state_file.unwrap_or_else(default_review_state_path)),
            reviewed_input_file: self.workspace_root.join(
                review
                    .reviewed_input
                    .unwrap_or_else(default_reviewed_input_path),
            ),
            low_confidence_threshold: review.low_confidence_threshold.unwrap_or(75),
        })
    }

    pub fn schema_file(&self) -> Result<PathBuf> {
        let schema = self
            .app
            .schema
            .as_ref()
            .context("missing [schema] section required for schema resolution")?;
        Ok(self.workspace_root.join(&schema.file))
    }

    pub fn scan_config(&self) -> ScanConfig {
        self.app.scan.clone().unwrap_or_default()
    }
}

pub fn load_config(config_path: &Path) -> Result<LoadedConfig> {
    let raw = fs::read_to_string(config_path)
        .with_context(|| format!("failed to read config file: {}", config_path.display()))?;

    let app: AppConfig = toml::from_str(&raw)
        .with_context(|| format!("failed to parse TOML config: {}", config_path.display()))?;

    let config_path = fs::canonicalize(config_path).with_context(|| {
        format!(
            "failed to canonicalize config path: {}",
            config_path.display()
        )
    })?;

    let workspace_root = config_path
        .parent()
        .context("config file must have a parent directory")?
        .to_path_buf();

    Ok(LoadedConfig {
        config_path,
        workspace_root,
        app,
    })
}

pub fn resolve_relative_to(base: &Path, candidate: &Path) -> PathBuf {
    if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        base.join(candidate)
    }
}

pub fn resolve_optional_command(base: &Path, candidate: Option<&str>, fallback: &str) -> PathBuf {
    let raw = candidate.unwrap_or(fallback);
    let path = Path::new(raw);
    if path.components().count() > 1 || path.is_absolute() {
        resolve_relative_to(base, path)
    } else {
        PathBuf::from(raw)
    }
}

fn default_analysis_dir() -> PathBuf {
    PathBuf::from(".safeharbor/analysis")
}

fn default_review_state_path() -> PathBuf {
    PathBuf::from(".safeharbor/review/review-state.json")
}

fn default_reviewed_input_path() -> PathBuf {
    PathBuf::from(".safeharbor/review/reviewed-input.json")
}

fn default_summary_path(manifest: &Path) -> PathBuf {
    manifest.with_file_name("safeharbor.summary.md")
}

pub fn require_existing_config(path: &Path) -> Result<LoadedConfig> {
    if !path.exists() {
        bail!("config file not found: {}", path.display());
    }
    load_config(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_dir() -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        let temp_root = std::env::temp_dir().join(format!("safeharbor-config-test-{unique}"));
        std::fs::create_dir_all(&temp_root).unwrap();
        temp_root
    }

    #[test]
    fn loads_config_and_resolves_workspace_root() {
        let temp_root = unique_temp_dir();
        let config_path = temp_root.join("safeharbor.toml");

        std::fs::write(
            &config_path,
            r#"
[input]
file = "examples/simple-vault/safeharbor.input.json"

[output]
manifest = "out/safeharbor.manifest.json"

[schema]
file = "schemas/safeharbor.manifest.schema.json"

[scan]
repo_root = "../protocol"
output_dir = ".safeharbor/analysis"
cache = true
"#,
        )
        .unwrap();

        let loaded = load_config(&config_path).unwrap();
        let compile = loaded.compile_settings().unwrap();

        assert_eq!(loaded.workspace_root, temp_root.canonicalize().unwrap());
        assert!(
            compile
                .input_file
                .ends_with("examples/simple-vault/safeharbor.input.json")
        );
        assert!(
            compile
                .manifest_output
                .ends_with("out/safeharbor.manifest.json")
        );
        assert!(
            compile
                .summary_output
                .ends_with("out/safeharbor.summary.md")
        );
        assert!(
            compile
                .reviewed_input_file
                .ends_with(".safeharbor/review/reviewed-input.json")
        );
        assert!(
            compile
                .schema_file
                .ends_with("schemas/safeharbor.manifest.schema.json")
        );
        assert_eq!(
            loaded.scan_config(),
            ScanConfig {
                repo_root: Some(PathBuf::from("../protocol")),
                output_dir: Some(PathBuf::from(".safeharbor/analysis")),
                aderyn_bin: None,
                forge_bin: None,
                cache: Some(true),
            }
        );

        std::fs::remove_dir_all(temp_root).unwrap();
    }

    #[test]
    fn supports_scan_only_configs() {
        let temp_root = unique_temp_dir();
        let config_path = temp_root.join("safeharbor.toml");

        std::fs::write(
            &config_path,
            r#"
[scan]
repo_root = "."
forge_bin = "forge"
aderyn_bin = "bin/mock-aderyn"
"#,
        )
        .unwrap();

        let loaded = load_config(&config_path).unwrap();
        let err = loaded.compile_settings().unwrap_err();

        assert!(err.to_string().contains("missing [input] section"));

        std::fs::remove_dir_all(temp_root).unwrap();
    }

    #[test]
    fn supports_review_and_summary_paths() {
        let temp_root = unique_temp_dir();
        let config_path = temp_root.join("safeharbor.toml");

        std::fs::write(
            &config_path,
            r#"
[input]
file = "examples/simple-vault/safeharbor.input.json"

[output]
manifest = "out/safeharbor.manifest.json"
summary = "out/safeharbor.summary.md"

[schema]
file = "schemas/safeharbor.manifest.schema.json"

[review]
analysis_dir = "analysis"
state_file = "review/state.json"
reviewed_input = "review/reviewed-input.json"
low_confidence_threshold = 70
"#,
        )
        .unwrap();

        let loaded = load_config(&config_path).unwrap();
        let compile = loaded.compile_settings().unwrap();
        let review = loaded.review_settings().unwrap();

        assert!(
            compile
                .summary_output
                .ends_with("out/safeharbor.summary.md")
        );
        assert!(
            compile
                .reviewed_input_file
                .ends_with("review/reviewed-input.json")
        );
        assert!(review.analysis_dir.ends_with("analysis"));
        assert!(review.state_file.ends_with("review/state.json"));
        assert!(
            review
                .reviewed_input_file
                .ends_with("review/reviewed-input.json")
        );
        assert_eq!(review.low_confidence_threshold, 70);

        std::fs::remove_dir_all(temp_root).unwrap();
    }

    #[test]
    fn resolves_optional_commands_relative_to_workspace() {
        let base = PathBuf::from("/workspace");

        assert_eq!(
            resolve_optional_command(&base, Some("bin/mock-aderyn"), "aderyn"),
            PathBuf::from("/workspace/bin/mock-aderyn")
        );
        assert_eq!(
            resolve_optional_command(&base, Some("aderyn"), "aderyn"),
            PathBuf::from("aderyn")
        );
        assert_eq!(
            resolve_optional_command(&base, None, "forge"),
            PathBuf::from("forge")
        );
    }
}
