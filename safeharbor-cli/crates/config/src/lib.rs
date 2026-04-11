use anyhow::{Context, Result};
use serde::Deserialize;
use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppConfig {
    pub input: InputConfig,
    pub output: OutputConfig,
    pub schema: SchemaConfig,
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
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaConfig {
    pub file: PathBuf,
}

#[derive(Debug, Clone)]
pub struct LoadedConfig {
    pub config_path: PathBuf,
    pub workspace_root: PathBuf,
    pub app: AppConfig,
}

impl LoadedConfig {
    pub fn input_file(&self) -> PathBuf {
        self.workspace_root.join(&self.app.input.file)
    }

    pub fn manifest_output(&self) -> PathBuf {
        self.workspace_root.join(&self.app.output.manifest)
    }

    pub fn schema_file(&self) -> PathBuf {
        self.workspace_root.join(&self.app.schema.file)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn loads_config_and_resolves_workspace_root() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        let temp_root = std::env::temp_dir().join(format!("safeharbor-config-test-{unique}"));
        std::fs::create_dir_all(&temp_root).unwrap();

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
"#,
        )
        .unwrap();

        let loaded = load_config(&config_path).unwrap();

        assert_eq!(loaded.workspace_root, temp_root.canonicalize().unwrap());
        assert!(
            loaded
                .input_file()
                .ends_with("examples/simple-vault/safeharbor.input.json")
        );
        assert!(
            loaded
                .manifest_output()
                .ends_with("out/safeharbor.manifest.json")
        );
        assert!(
            loaded
                .schema_file()
                .ends_with("schemas/safeharbor.manifest.schema.json")
        );

        std::fs::remove_dir_all(temp_root).unwrap();
    }

    #[test]
    fn rejects_unknown_config_keys() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        let temp_root = std::env::temp_dir().join(format!("safeharbor-config-test-{unique}"));
        std::fs::create_dir_all(&temp_root).unwrap();

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
"#,
        )
        .unwrap();

        let err = load_config(&config_path).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("unknown field `summary`"));

        std::fs::remove_dir_all(temp_root).unwrap();
    }
}
