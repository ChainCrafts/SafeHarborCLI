use analyzer::{
    ScanRequest, cleanup_temporary_outputs, persisted_analysis_graph, run_scan,
    write_analysis_graph, write_json_pretty,
};
use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use compiler::compile_static_input;
use manifest::validate_file;
use std::{
    env,
    path::{Path, PathBuf},
};
use structural_extractor::{PersistedStructuralCandidates, extract_candidates, summarize};

#[derive(Parser, Debug)]
#[command(
    name = "shcli",
    version,
    about = "SafeHarbor CLI for structural scan, manifest emission, and validation"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Scan a Foundry repo and emit structural analysis candidates
    Scan(ScanArgs),

    /// Emit a Safe Harbor manifest from static input
    Compile(CompileArgs),

    /// Validate a manifest against the schema
    Validate(ValidateArgs),
}

#[derive(Args, Debug)]
struct ScanArgs {
    /// Foundry repo root to scan. Defaults to the current directory unless [scan].repo_root is set.
    #[arg(long)]
    repo_root: Option<PathBuf>,

    /// Optional SafeHarbor config path. When omitted, shcli will use defaults or auto-discover safeharbor.toml.
    #[arg(long)]
    config: Option<PathBuf>,

    /// Override the scan output directory. Relative paths are resolved from the repo root.
    #[arg(long)]
    out_dir: Option<PathBuf>,
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

#[derive(Debug)]
struct ResolvedScanArgs {
    request: ScanRequest,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan(args) => scan_command(args),
        Commands::Compile(args) => {
            let cfg = config::require_existing_config(&args.config)?;
            let settings = cfg.compile_settings()?;
            let manifest = compile_static_input(
                &settings.input_file,
                &settings.schema_file,
                &settings.manifest_output,
            )?;

            println!("Emitted manifest successfully");
            println!("  config      : {}", cfg.config_path.display());
            println!("  input       : {}", settings.input_file.display());
            println!("  schema      : {}", settings.schema_file.display());
            println!("  manifest out: {}", settings.manifest_output.display());
            println!("  protocol    : {}", manifest.protocol.slug);
            Ok(())
        }
        Commands::Validate(args) => {
            let (manifest_path, schema_path) = resolve_validate_paths(&args)?;
            validate_file(&manifest_path, &schema_path)?;
            println!("Manifest is valid");
            println!("  manifest: {}", manifest_path.display());
            println!("  schema  : {}", schema_path.display());
            Ok(())
        }
    }
}

fn scan_command(args: ScanArgs) -> Result<()> {
    let resolved = resolve_scan_args(&args)?;
    let analysis = run_scan(&resolved.request)?;
    let analysis_metadata = analysis
        .metadata_base
        .with_schema_version("analysis_graph/v1");
    let persisted_graph = persisted_analysis_graph(&analysis.graph, analysis_metadata);
    write_analysis_graph(&analysis.paths.analysis_graph_path, &persisted_graph)?;

    let extracted = extract_candidates(&analysis.graph);
    let summary = summarize(&analysis.graph, &extracted);
    let structural_metadata = analysis
        .metadata_base
        .with_schema_version("structural_candidates/v1");
    let persisted_candidates = PersistedStructuralCandidates {
        metadata: structural_metadata,
        extracted_candidates: extracted,
        summary: summary.clone(),
    };
    write_json_pretty(
        &analysis.paths.structural_candidates_path,
        &persisted_candidates,
    )?;
    cleanup_temporary_outputs(&analysis.paths, resolved.request.cache)?;

    println!("Structural scan completed");
    println!(
        "  analysis graph        : {}",
        analysis.paths.analysis_graph_path.display()
    );
    println!(
        "  structural candidates : {}",
        analysis.paths.structural_candidates_path.display()
    );
    println!("Found {} contracts", summary.contract_count);
    println!(
        "Found {} external/public selectors",
        summary.external_public_selector_count
    );
    println!(
        "Found {} privileged selectors",
        summary.privileged_selector_count
    );
    println!(
        "Found {} payable entrypoints",
        summary.payable_entrypoint_count
    );
    println!("Found {} role candidates", summary.role_candidate_count);
    println!("Found {} upgrade surfaces", summary.upgrade_surface_count);

    Ok(())
}

fn resolve_scan_args(args: &ScanArgs) -> Result<ResolvedScanArgs> {
    let cwd = env::current_dir().context("failed to read current working directory")?;
    let explicit_repo_root = args
        .repo_root
        .as_ref()
        .map(|path| absolutize_from(&cwd, path))
        .transpose()?;

    let config = match &args.config {
        Some(path) => Some(config::require_existing_config(path)?),
        None => {
            let search_root = explicit_repo_root.as_ref().unwrap_or(&cwd);
            find_workspace_config(search_root)
                .map(|path| config::load_config(&path))
                .transpose()?
        }
    };

    let scan_config = config
        .as_ref()
        .map(config::LoadedConfig::scan_config)
        .unwrap_or_default();
    let repo_root = match explicit_repo_root {
        Some(repo_root) => repo_root,
        None => match scan_config.repo_root.as_ref() {
            Some(repo_root) => {
                let base = config
                    .as_ref()
                    .map(|cfg| cfg.workspace_root.as_path())
                    .unwrap_or(cwd.as_path());
                config::resolve_relative_to(base, repo_root)
            }
            None => cwd.clone(),
        },
    };
    let repo_root = std::fs::canonicalize(&repo_root).with_context(|| {
        format!(
            "failed to canonicalize repo root for scan: {}",
            repo_root.display()
        )
    })?;

    let output_dir = match &args.out_dir {
        Some(out_dir) => config::resolve_relative_to(&repo_root, out_dir),
        None => scan_config
            .output_dir
            .as_ref()
            .map(|out_dir| config::resolve_relative_to(&repo_root, out_dir))
            .unwrap_or_else(|| repo_root.join(".safeharbor/analysis")),
    };

    let command_base = config
        .as_ref()
        .map(|cfg| cfg.workspace_root.as_path())
        .unwrap_or(cwd.as_path());
    let forge_bin =
        config::resolve_optional_command(command_base, scan_config.forge_bin.as_deref(), "forge");
    let aderyn_bin =
        config::resolve_optional_command(command_base, scan_config.aderyn_bin.as_deref(), "aderyn");

    Ok(ResolvedScanArgs {
        request: ScanRequest {
            repo_root,
            output_dir,
            forge_bin,
            aderyn_bin,
            cache: scan_config.cache.unwrap_or(true),
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
        },
    })
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

    Ok((args.manifest.clone(), cfg.schema_file()?))
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    absolutize_from(
        &env::current_dir().context("failed to read current working directory")?,
        path,
    )
}

fn absolutize_from(base: &Path, path: &Path) -> Result<PathBuf> {
    Ok(if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    })
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

    fn write_compile_workspace(root: &Path) {
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
        write_compile_workspace(&root);

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

    #[test]
    fn scan_defaults_without_config() {
        let root = unique_temp_dir();
        fs::write(root.join("foundry.toml"), "[profile.default]\n").unwrap();

        let args = ScanArgs {
            repo_root: Some(root.clone()),
            config: None,
            out_dir: None,
        };
        let resolved = resolve_scan_args(&args).unwrap();

        assert_eq!(resolved.request.repo_root, root.canonicalize().unwrap());
        assert_eq!(
            resolved.request.output_dir,
            root.canonicalize().unwrap().join(".safeharbor/analysis")
        );
        assert_eq!(resolved.request.forge_bin, PathBuf::from("forge"));
        assert_eq!(resolved.request.aderyn_bin, PathBuf::from("aderyn"));
        assert!(resolved.request.cache);

        fs::remove_dir_all(root).unwrap();
    }
}
