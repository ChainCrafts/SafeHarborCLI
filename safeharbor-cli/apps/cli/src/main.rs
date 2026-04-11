use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use compiler::compile_static_input;
use manifest::validate_file;
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

    /// Validate a manifest against the schema
    Validate(ValidateArgs),
}

#[derive(Args, Debug)]
struct CompileArgs {
    /// Path to Safe Harbor config file
    #[arg(long, default_value = "safeharbor.toml")]
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
            let manifest = compile_static_input(
                &cfg.input_file(),
                &cfg.schema_file(),
                &cfg.manifest_output(),
            )?;

            println!("Compiled manifest successfully");
            println!("  config      : {}", cfg.config_path.display());
            println!("  input       : {}", cfg.input_file().display());
            println!("  schema      : {}", cfg.schema_file().display());
            println!("  manifest out: {}", cfg.manifest_output().display());
            println!("  protocol    : {}", manifest.protocol.slug);
        }
        Commands::Validate(args) => {
            validate_file(&args.manifest, &args.schema)?;
            println!("Manifest is valid");
            println!("  manifest: {}", args.manifest.display());
            println!("  schema  : {}", args.schema.display());
        }
    }

    Ok(())
}
