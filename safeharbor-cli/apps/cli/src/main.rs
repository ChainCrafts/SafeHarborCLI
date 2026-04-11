use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "shcli",
    version,
    about = "Protocol-aware Safe Harbor spec compiler for BattleChain"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Compile a Safe Harbor manifest from static input
    Compile(CompileArgs),

    /// Validate a manifest or input file
    Validate(ValidateArgs),

    /// Phase 1 shell only
    Init,

    /// Phase 2
    Scan,

    /// Phase 4
    Review,

    /// Future status command
    Status,
}

#[derive(Args, Debug)]
struct CompileArgs {
    /// Path to shcli config file
    #[arg(long, default_value = "shcli.toml")]
    config: PathBuf,
}

#[derive(Args, Debug)]
struct ValidateArgs {
    /// Path to manifest JSON
    #[arg(long)]
    manifest: PathBuf,

    /// Path to schema JSON
    #[arg(long, default_value = "schemas/safeharbor.manifest.schema.json")]
    schema: PathBuf,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Compile(args) => {
            let cfg = config::load_config(&args.config)?;

            println!("Loaded config successfully");
            println!("  config      : {}", cfg.config_path.display());
            println!("  workspace   : {}", cfg.workspace_root.display());
            println!("  input       : {}", cfg.input_file().display());
            println!("  schema      : {}", cfg.schema_file().display());
            println!("  manifest out: {}", cfg.manifest_output().display());
            println!("  summary out : {}", cfg.summary_output().display());
        }
        Commands::Validate(args) => {
            println!(
                "validate not wired yet: manifest={:?}, schema={:?}",
                args.manifest, args.schema
            );
        }
        Commands::Init => {
            println!("init is a shell stub in Phase 1");
        }
        Commands::Scan => {
            println!("scan is Phase 2 work, not implemented in Phase 1");
        }
        Commands::Review => {
            println!("review is Phase 4 work, not implemented in Phase 1");
        }
        Commands::Status => {
            println!("status is future work");
        }
    }

    Ok(())
}