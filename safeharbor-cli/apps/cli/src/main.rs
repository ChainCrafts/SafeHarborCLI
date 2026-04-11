use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use compiler::compile_static_input;
use manifest::validate_file;
use std::{
    env,
    path::{Path, PathBuf},
};

#[derive(Parser, Debug)]
#[command(
    name = "shcli",
    version,
    about = "Phase 1 CLI for emitting and validating Safe Harbor manifests from static input"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Emit a Safe Harbor manifest from static input
    Compile(CompileArgs),

    /// Validate a manifest against the schema
    Validate(ValidateArgs),
}

#[derive(Args, Debug)]
struct CompileArgs {
    /// Path to Safe Harbor config file for static input emission
    #[arg(long, default_value = "safeharbor.toml")]
    config: PathBuf,
}

#[derive(Args, Debug)]
struct ValidateArgs {
    /// Path to manifest JSON
    #[arg(long)]
    manifest: PathBuf,

    /// Path to schema JSON. When omitted, the schema from the nearest
    /// safeharbor.toml above the manifest path is used.
    #[arg(long)]
    schema: Option<PathBuf>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Compile(args) => {
            let cfg = config::load_config(&args.config)?;
            let manifest = compile_static_input(
                &cfg.input_file(),
                &cfg.schema_file(),
                &cfg.manifest_output(),
            )?;

            println!("Emitted manifest successfully");
            println!("  config      : {}", cfg.config_path.display());
            println!("  input       : {}", cfg.input_file().display());
            println!("  schema      : {}", cfg.schema_file().display());
            println!("  manifest out: {}", cfg.manifest_output().display());
            println!("  protocol    : {}", manifest.protocol.slug);
        }
        Commands::Validate(args) => {
            let (manifest_path, schema_path) = resolve_validate_paths(&args)?;
            validate_file(&manifest_path, &schema_path)?;
            println!("Manifest is valid");
            println!("  manifest: {}", manifest_path.display());
            println!("  schema  : {}", schema_path.display());
        }
    }

    Ok(())
}

fn resolve_validate_paths(args: &ValidateArgs) -> Result<(PathBuf, PathBuf)> {
    if let Some(schema_path) = &args.schema {
        return Ok((args.manifest.clone(), schema_path.clone()));
    }

    let manifest_search_path = absolute_path(&args.manifest)?;
    let Some(config_path) = find_workspace_config(&manifest_search_path) else {
        bail!(
            "failed to resolve schema for manifest {}: no safeharbor.toml found in its parent directories; pass --schema explicitly",
            args.manifest.display()
        );
    };

    let cfg = config::load_config(&config_path).with_context(|| {
        format!(
            "failed to load workspace config while resolving schema: {}",
            config_path.display()
        )
    })?;

    Ok((args.manifest.clone(), cfg.schema_file()))
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(env::current_dir()
            .context("failed to read current working directory")?
            .join(path))
    }
}

fn find_workspace_config(path: &Path) -> Option<PathBuf> {
    let start = if path.is_dir() { path } else { path.parent()? };

    for candidate_dir in start.ancestors() {
        let config_path = candidate_dir.join("safeharbor.toml");
        if config_path.is_file() {
            return Some(config_path);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn unique_temp_dir() -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        let dir = env::temp_dir().join(format!("safeharbor-cli-test-{unique}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_workspace(root: &Path) {
        fs::create_dir_all(root.join("schemas")).unwrap();
        fs::create_dir_all(root.join("examples/simple-vault/out")).unwrap();

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

        fs::write(root.join("schemas/safeharbor.manifest.schema.json"), "{}").unwrap();
        fs::write(
            root.join("examples/simple-vault/out/safeharbor.manifest.json"),
            "{}",
        )
        .unwrap();
    }

    #[test]
    fn resolves_default_schema_from_manifest_workspace() {
        let root = unique_temp_dir();
        write_workspace(&root);

        let args = ValidateArgs {
            manifest: root.join("examples/simple-vault/out/safeharbor.manifest.json"),
            schema: None,
        };

        let (manifest_path, schema_path) = resolve_validate_paths(&args).unwrap();

        assert_eq!(manifest_path, args.manifest);
        assert_eq!(
            schema_path,
            root.join("schemas/safeharbor.manifest.schema.json")
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn preserves_explicit_schema_override() {
        let args = ValidateArgs {
            manifest: PathBuf::from("manifest.json"),
            schema: Some(PathBuf::from("custom-schema.json")),
        };

        let (manifest_path, schema_path) = resolve_validate_paths(&args).unwrap();

        assert_eq!(manifest_path, PathBuf::from("manifest.json"));
        assert_eq!(schema_path, PathBuf::from("custom-schema.json"));
    }
}
