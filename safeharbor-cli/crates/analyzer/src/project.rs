use crate::types::ProjectFacts;
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::{
    ffi::OsStr,
    path::{Component, Path, PathBuf},
    process::Command,
};

#[derive(Debug, Clone)]
pub struct FoundryProject {
    pub repo_root: PathBuf,
    pub foundry_config_path: PathBuf,
    pub src_dir: String,
    pub test_dir: String,
    pub script_dir: String,
    pub libs: Vec<String>,
    pub artifact_dir: PathBuf,
    pub artifact_dir_relative: String,
}

#[derive(Debug, Deserialize)]
struct ForgeConfigJson {
    src: String,
    test: String,
    script: String,
    out: String,
    libs: Vec<String>,
}

impl FoundryProject {
    pub fn discover(repo_root: &Path, forge_bin: &Path) -> Result<Self> {
        let repo_root = std::fs::canonicalize(repo_root).with_context(|| {
            format!(
                "failed to canonicalize repo root for scan: {}",
                repo_root.display()
            )
        })?;
        let foundry_config_path = repo_root.join("foundry.toml");
        if !foundry_config_path.is_file() {
            bail!(
                "Phase 2 scan currently supports Foundry repos only: missing foundry.toml at {}",
                foundry_config_path.display()
            );
        }

        let config = forge_config_json(&repo_root, forge_bin)?;
        let artifact_dir_relative = normalize_repo_relative_path(Path::new(&config.out));
        let artifact_dir = repo_root.join(&artifact_dir_relative);

        Ok(Self {
            repo_root,
            foundry_config_path,
            src_dir: normalize_repo_relative_path(Path::new(&config.src)),
            test_dir: normalize_repo_relative_path(Path::new(&config.test)),
            script_dir: normalize_repo_relative_path(Path::new(&config.script)),
            libs: config
                .libs
                .into_iter()
                .map(|lib| normalize_repo_relative_path(Path::new(&lib)))
                .collect(),
            artifact_dir,
            artifact_dir_relative,
        })
    }

    pub fn build(&self, forge_bin: &Path) -> Result<()> {
        let output = Command::new(forge_bin)
            .arg("build")
            .arg("--ast")
            .current_dir(&self.repo_root)
            .output()
            .with_context(|| format!("failed to start forge build via {}", forge_bin.display()))?;

        if !output.status.success() {
            bail!(
                "forge build via {} failed for {}:\nstdout:\n{}\nstderr:\n{}",
                forge_bin.display(),
                self.repo_root.display(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }

        Ok(())
    }

    pub fn to_project_facts(&self) -> ProjectFacts {
        ProjectFacts {
            build_system: "foundry".to_string(),
            foundry_config_path: normalize_repo_relative_path(
                self.foundry_config_path
                    .strip_prefix(&self.repo_root)
                    .unwrap_or(&self.foundry_config_path),
            ),
            src_dir: self.src_dir.clone(),
            test_dir: self.test_dir.clone(),
            script_dir: self.script_dir.clone(),
            libs: self.libs.clone(),
            artifact_dir: self.artifact_dir_relative.clone(),
        }
    }
}

pub fn forge_version(forge_bin: &Path) -> Result<String> {
    read_version_string(forge_bin, "--version")
}

pub fn read_version_string(command: &Path, arg: &str) -> Result<String> {
    let output = Command::new(command)
        .arg(arg)
        .output()
        .with_context(|| format!("failed to start {}", command.display()))?;

    if !output.status.success() {
        bail!(
            "{} {} failed:\nstdout:\n{}\nstderr:\n{}",
            command.display(),
            arg,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn forge_config_json(repo_root: &Path, forge_bin: &Path) -> Result<ForgeConfigJson> {
    let output = Command::new(forge_bin)
        .arg("config")
        .arg("--json")
        .current_dir(repo_root)
        .output()
        .with_context(|| {
            format!(
                "failed to start forge config --json via {}",
                forge_bin.display()
            )
        })?;

    if !output.status.success() {
        bail!(
            "forge config --json failed for {}:\nstdout:\n{}\nstderr:\n{}",
            repo_root.display(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    serde_json::from_slice(&output.stdout).with_context(|| {
        format!(
            "failed to parse forge config JSON for {}",
            repo_root.display()
        )
    })
}

pub fn normalize_repo_relative_path(path: &Path) -> String {
    let mut parts = Vec::new();

    for component in path.components() {
        match component {
            Component::Prefix(prefix) => {
                parts.push(prefix.as_os_str().to_string_lossy().to_string())
            }
            Component::RootDir => {}
            Component::CurDir => {}
            Component::ParentDir => {
                if !parts.is_empty() {
                    parts.pop();
                }
            }
            Component::Normal(part) => parts.push(os_str_to_string(part)),
        }
    }

    if parts.is_empty() {
        ".".to_string()
    } else {
        parts.join("/")
    }
}

fn os_str_to_string(value: &OsStr) -> String {
    value.to_string_lossy().to_string()
}

pub fn make_repo_relative(repo_root: &Path, path: &Path) -> String {
    let relative = path.strip_prefix(repo_root).unwrap_or(path);
    normalize_repo_relative_path(relative)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    fn unique_temp_dir() -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("safeharbor-analyzer-project-{unique}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[cfg(unix)]
    fn write_executable(path: &Path, contents: &str) {
        use std::os::unix::fs::PermissionsExt;

        fs::write(path, contents).unwrap();
        let mut perms = fs::metadata(path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms).unwrap();
    }

    #[cfg(not(unix))]
    fn write_executable(path: &Path, contents: &str) {
        fs::write(path, contents).unwrap();
    }

    fn temp_project(root: &Path) -> FoundryProject {
        FoundryProject {
            repo_root: root.to_path_buf(),
            foundry_config_path: root.join("foundry.toml"),
            src_dir: "src".to_string(),
            test_dir: "test".to_string(),
            script_dir: "script".to_string(),
            libs: vec!["lib".to_string()],
            artifact_dir: root.join("out"),
            artifact_dir_relative: "out".to_string(),
        }
    }

    #[test]
    fn normalizes_repo_relative_paths_without_lowercasing() {
        assert_eq!(
            normalize_repo_relative_path(Path::new("./src/../src/Admin/Proxy.sol")),
            "src/Admin/Proxy.sol"
        );
        assert_eq!(normalize_repo_relative_path(Path::new(".")), ".");
        assert_eq!(
            normalize_repo_relative_path(Path::new("lib/openzeppelin")),
            "lib/openzeppelin"
        );
    }

    #[test]
    fn missing_forge_reports_the_attempted_binary() {
        let root = unique_temp_dir();
        fs::write(root.join("foundry.toml"), "").unwrap();
        let missing = PathBuf::from("__safeharbor_missing_forge__");

        let err = FoundryProject::discover(&root, &missing).unwrap_err();
        let msg = format!("{err:#}");

        assert!(msg.contains("failed to start forge config --json via"));
        assert!(msg.contains("__safeharbor_missing_forge__"));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn failing_forge_build_reports_the_attempted_binary() {
        let root = unique_temp_dir();
        let forge_bin = root.join("fake-forge");
        write_executable(
            &forge_bin,
            "#!/usr/bin/env sh\necho build stdout\necho build stderr >&2\nexit 19\n",
        );

        let err = temp_project(&root).build(&forge_bin).unwrap_err();
        let msg = format!("{err:#}");

        assert!(msg.contains("forge build via"));
        assert!(msg.contains(&forge_bin.display().to_string()));
        assert!(msg.contains("build stdout"));
        assert!(msg.contains("build stderr"));

        fs::remove_dir_all(root).unwrap();
    }
}
