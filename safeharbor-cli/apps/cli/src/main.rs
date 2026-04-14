use analyzer::{
    ScanRequest, cleanup_temporary_outputs, persisted_analysis_graph, run_scan,
    write_analysis_graph, write_json_pretty,
};
use anyhow::{Context, Result, bail};
use battlechain_adapter::{
    BattlechainOverrides, HttpBattlechainClient, WorkspaceArtifacts, prepare_battlechain,
    run_doctor, run_status,
};
use clap::{Args, Parser, Subcommand};
use compiler::compile_reviewed_input;
use manifest::validate_file;
use registry::{
    HttpRegistryRpcClient, ReadbackStatus, RegistryOverrides, prepare_registry_publish,
};
use review_engine::{ApproveDefaultsPrompter, ReviewRequest, TerminalReviewPrompter, run_review};
use standards_recognizer::{persisted_standards_recognition, recognize_standards};
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

    /// Prepare or inspect BattleChain adapter metadata
    Battlechain {
        #[command(subcommand)]
        command: BattlechainCommands,
    },

    /// Prepare and verify optional manifest registry publication calldata
    Registry {
        #[command(subcommand)]
        command: RegistryCommands,
    },

    /// Emit a Safe Harbor manifest from static input
    Compile(CompileArgs),

    /// Review scan candidates and emit reviewed compiler input
    Review(ReviewArgs),

    /// Validate a manifest against the schema
    Validate(ValidateArgs),

    /// Show local and remote BattleChain lifecycle status
    Status(StatusArgs),

    /// Diagnose local and remote BattleChain readiness
    Doctor(DoctorArgs),
}

#[derive(Subcommand, Debug)]
enum BattlechainCommands {
    /// Prepare BattleChain adapter metadata from compiled manifest output
    Prepare(BattlechainPrepareArgs),
}

#[derive(Subcommand, Debug)]
enum RegistryCommands {
    /// Prepare calldata to associate an agreement with a compiled manifest URI
    Publish(RegistryPublishArgs),
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
    /// Path to Safe Harbor config file for reviewed input emission
    #[arg(long, default_value = "safeharbor.toml")]
    config: PathBuf,
}

#[derive(Args, Debug, Clone)]
struct BattlechainCommonArgs {
    /// Optional SafeHarbor config path.
    #[arg(long, default_value = "safeharbor.toml")]
    config: PathBuf,

    /// Override BattleChain network name.
    #[arg(long)]
    network: Option<String>,

    /// Override BattleChain RPC URL.
    #[arg(long)]
    rpc_url: Option<String>,

    /// Override BattleChain chain ID.
    #[arg(long)]
    chain_id: Option<u64>,

    /// Override BattleChain agreement address.
    #[arg(long)]
    agreement_address: Option<String>,
}

#[derive(Args, Debug)]
struct BattlechainPrepareArgs {
    #[command(flatten)]
    common: BattlechainCommonArgs,

    /// Override BattleChain explorer base URL.
    #[arg(long)]
    explorer_base_url: Option<String>,

    /// Seed local BattleChain recovery address metadata.
    #[arg(long)]
    recovery_address: Option<String>,

    /// Seed local BattleChain bounty percentage metadata.
    #[arg(long)]
    bounty_pct: Option<f64>,

    /// Seed local BattleChain commitment window metadata.
    #[arg(long)]
    commitment_window_days: Option<u32>,

    /// Seed local unverified lifecycle state metadata.
    #[arg(long)]
    lifecycle_state: Option<String>,
}

#[derive(Args, Debug)]
struct StatusArgs {
    #[command(flatten)]
    common: BattlechainCommonArgs,
}

#[derive(Args, Debug)]
struct DoctorArgs {
    #[command(flatten)]
    common: BattlechainCommonArgs,
}

#[derive(Args, Debug)]
struct RegistryPublishArgs {
    /// Optional SafeHarbor config path.
    #[arg(long, default_value = "safeharbor.toml")]
    config: PathBuf,

    /// Manifest URI to associate with the compiled manifest hash.
    #[arg(long)]
    manifest_uri: String,

    /// Override BattleChain network name.
    #[arg(long)]
    network: Option<String>,

    /// Override BattleChain RPC URL for chain checks and readback verification.
    #[arg(long)]
    rpc_url: Option<String>,

    /// Override BattleChain chain ID.
    #[arg(long)]
    chain_id: Option<u64>,

    /// Agreement address override. Only used when the compiled manifest has no BattleChain adapter agreement.
    #[arg(long)]
    agreement_address: Option<String>,

    /// Registry contract address override.
    #[arg(long)]
    registry_address: Option<String>,
}

#[derive(Args, Debug)]
struct ReviewArgs {
    /// Optional SafeHarbor config path.
    #[arg(long, default_value = "safeharbor.toml")]
    config: PathBuf,

    /// Override analysis artifact directory. Relative paths are resolved from the config workspace root.
    #[arg(long)]
    analysis_dir: Option<PathBuf>,

    /// Override review state path. Relative paths are resolved from the config workspace root.
    #[arg(long)]
    state_file: Option<PathBuf>,

    /// Override reviewed input output path. Relative paths are resolved from the config workspace root.
    #[arg(long)]
    reviewed_input: Option<PathBuf>,

    /// Approve all default review decisions without interactive prompts.
    #[arg(long)]
    approve_defaults: bool,

    /// When used with --approve-defaults, reject semantic templates below the configured threshold.
    #[arg(long)]
    reject_low_confidence_semantic_templates: bool,
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
        Commands::Battlechain { command } => match command {
            BattlechainCommands::Prepare(args) => battlechain_prepare_command(args),
        },
        Commands::Registry { command } => match command {
            RegistryCommands::Publish(args) => registry_publish_command(args),
        },
        Commands::Compile(args) => {
            let cfg = config::require_existing_config(&args.config)?;
            let settings = cfg.compile_settings()?;
            let manifest = compile_reviewed_input(
                &settings.input_file,
                &settings.reviewed_input_file,
                &settings.schema_file,
                &settings.manifest_output,
                &settings.summary_output,
            )?;

            println!("Emitted manifest successfully");
            println!("  config      : {}", cfg.config_path.display());
            println!("  draft input : {}", settings.input_file.display());
            println!("  reviewed    : {}", settings.reviewed_input_file.display());
            println!("  schema      : {}", settings.schema_file.display());
            println!("  manifest out: {}", settings.manifest_output.display());
            println!("  summary out : {}", settings.summary_output.display());
            println!("  protocol    : {}", manifest.protocol.slug);
            Ok(())
        }
        Commands::Review(args) => review_command(args),
        Commands::Validate(args) => {
            let (manifest_path, schema_path) = resolve_validate_paths(&args)?;
            validate_file(&manifest_path, &schema_path)?;
            println!("Manifest is valid");
            println!("  manifest: {}", manifest_path.display());
            println!("  schema  : {}", schema_path.display());
            Ok(())
        }
        Commands::Status(args) => status_command(args),
        Commands::Doctor(args) => doctor_command(args),
    }
}

fn registry_publish_command(args: RegistryPublishArgs) -> Result<()> {
    let cfg = config::require_existing_config(&args.config)?;
    let client = HttpRegistryRpcClient::new()?;
    let prepared = prepare_registry_publish(
        &cfg,
        &args.manifest_uri,
        &RegistryOverrides {
            network: args.network,
            rpc_url: args.rpc_url,
            chain_id: args.chain_id,
            agreement_address: args.agreement_address,
            registry_address: args.registry_address,
        },
        &client,
    )?;

    println!("Registry publish prepared");
    println!("  config       : {}", cfg.config_path.display());
    println!("  manifest     : {}", prepared.manifest_display_path);
    println!("  agreement    : {}", prepared.agreement_address);
    println!("  registry     : {}", prepared.registry_address);
    println!("  manifest hash: {}", prepared.manifest_digest);
    println!("  manifest URI : {}", prepared.manifest_uri);
    println!(
        "  network      : {} (chain {})",
        prepared.network.network, prepared.network.chain_id
    );
    println!("  calldata     : {}", prepared.calldata);

    match &prepared.readback {
        Some(report) => {
            println!("  readback     : {}", report.status);
            if let Some(current) = &report.current {
                println!("  current hash : sha256:{}", current.manifest_hash_hex);
                println!("  current URI  : {}", current.manifest_uri);
                println!("  publisher    : {}", current.publisher);
                println!("  published at : {}", current.published_at);
            }
            if report.status != ReadbackStatus::Match {
                println!("Next steps:");
                println!(
                    "  - Submit the calldata above to {} from the registry owner.",
                    prepared.registry_address
                );
                println!("  - Re-run this command with the same manifest URI to verify readback.");
            }
        }
        None => {
            println!("  readback     : unavailable (no RPC URL configured)");
            println!("Next steps:");
            println!(
                "  - Submit the calldata above to {} from the registry owner.",
                prepared.registry_address
            );
            println!("  - Configure [battlechain].rpc_url or pass --rpc-url to verify readback.");
        }
    }

    Ok(())
}

fn battlechain_prepare_command(args: BattlechainPrepareArgs) -> Result<()> {
    let cfg = config::require_existing_config(&args.common.config)?;
    let artifacts = WorkspaceArtifacts::from_loaded_config(&cfg);
    let overrides = prepare_overrides(args);
    let artifact = prepare_battlechain(&cfg, &overrides)?;

    let readiness = if artifact.has_failures() {
        "not ready"
    } else if artifact.has_warnings() {
        "ready with warnings"
    } else {
        "ready"
    };

    println!("BattleChain prepare completed");
    println!("  artifact : {}", artifacts.prepare_path.display());
    println!("  readiness: {readiness}");
    println!(
        "  network  : {} (chain {})",
        artifact.resolved_network.network, artifact.resolved_network.chain_id
    );
    match &artifact.agreement_binding {
        Some(binding) => println!("  agreement: {}", binding.agreement_address),
        None => println!("  agreement: missing"),
    }
    println!("Next steps:");
    for step in &artifact.next_steps {
        println!("  - {step}");
    }

    Ok(())
}

fn status_command(args: StatusArgs) -> Result<()> {
    let cfg = config::require_existing_config(&args.common.config)?;
    let overrides = common_overrides(args.common);
    let client = HttpBattlechainClient::new()?;
    let report = run_status(&cfg, &overrides, &client)?;

    print!("{}", report.render_text());
    Ok(())
}

fn doctor_command(args: DoctorArgs) -> Result<()> {
    let cfg = config::require_existing_config(&args.common.config)?;
    let overrides = common_overrides(args.common);
    let client = HttpBattlechainClient::new()?;
    let report = run_doctor(&cfg, &overrides, &client)?;

    print!("{}", report.render_text());
    if report.has_failures() {
        bail!("doctor found failing BattleChain checks");
    }

    Ok(())
}

fn prepare_overrides(args: BattlechainPrepareArgs) -> BattlechainOverrides {
    let mut overrides = common_overrides(args.common);
    overrides.explorer_base_url = args.explorer_base_url;
    overrides.recovery_address = args.recovery_address;
    overrides.bounty_pct = args.bounty_pct;
    overrides.commitment_window_days = args.commitment_window_days;
    overrides.lifecycle_state = args.lifecycle_state;
    overrides
}

fn common_overrides(args: BattlechainCommonArgs) -> BattlechainOverrides {
    BattlechainOverrides {
        network: args.network,
        rpc_url: args.rpc_url,
        chain_id: args.chain_id,
        agreement_address: args.agreement_address,
        ..BattlechainOverrides::default()
    }
}

fn review_command(args: ReviewArgs) -> Result<()> {
    let cfg = config::require_existing_config(&args.config)?;
    let mut settings = cfg.review_settings()?;

    if let Some(analysis_dir) = args.analysis_dir {
        settings.analysis_dir = config::resolve_relative_to(&cfg.workspace_root, &analysis_dir);
    }
    if let Some(state_file) = args.state_file {
        settings.state_file = config::resolve_relative_to(&cfg.workspace_root, &state_file);
    }
    if let Some(reviewed_input) = args.reviewed_input {
        settings.reviewed_input_file =
            config::resolve_relative_to(&cfg.workspace_root, &reviewed_input);
    }

    let request = ReviewRequest {
        analysis_graph_path: settings.analysis_dir.join("analysis.graph.json"),
        structural_candidates_path: settings.analysis_dir.join("structural-candidates.json"),
        standards_recognition_path: settings.analysis_dir.join("standards-recognition.json"),
        draft_input_path: settings.input_file.clone(),
        state_path: settings.state_file.clone(),
        reviewed_input_path: settings.reviewed_input_file.clone(),
        low_confidence_threshold: settings.low_confidence_threshold,
    };

    let reviewed = if args.approve_defaults {
        let mut prompter = if args.reject_low_confidence_semantic_templates {
            ApproveDefaultsPrompter::new()
                .reject_low_confidence_semantic_templates(settings.low_confidence_threshold)
        } else {
            ApproveDefaultsPrompter::new()
        };
        run_review(request, &mut prompter)?
    } else {
        let mut prompter = TerminalReviewPrompter::new();
        run_review(request, &mut prompter)?
    };

    println!("Review completed");
    println!("  config       : {}", cfg.config_path.display());
    println!("  state        : {}", settings.state_file.display());
    println!(
        "  reviewed input: {}",
        settings.reviewed_input_file.display()
    );
    println!(
        "  contracts    : {}",
        reviewed.reviewed_scope.contracts.len()
    );
    println!("  roles        : {}", reviewed.reviewed_roles.len());
    println!("  invariants   : {}", reviewed.all_invariants().count());
    Ok(())
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

    let recognition = recognize_standards(&analysis.graph);
    let recognition_summary = recognition.recognition_summary.clone();
    let recognition_metadata = analysis
        .metadata_base
        .with_schema_version("standards_recognition/v1");
    let persisted_recognition = persisted_standards_recognition(recognition, recognition_metadata);
    write_json_pretty(
        &analysis.paths.standards_recognition_path,
        &persisted_recognition,
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
    println!(
        "  standards recognition : {}",
        analysis.paths.standards_recognition_path.display()
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
    println!(
        "Recognized {} standards or patterns",
        recognition_summary.recognized_standard_count
    );
    println!(
        "Suggested {} semantic templates",
        recognition_summary.semantic_template_suggestion_count
    );

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
