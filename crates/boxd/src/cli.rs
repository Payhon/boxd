use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use crate::{composition, config, doctor, init, runtime_image};

pub const EXIT_FAILURE: i32 = 1;
pub const EXIT_WORKER_USAGE: i32 = 64;
pub const EXIT_WORKER_RUNTIME: i32 = 70;

#[derive(Debug)]
pub struct CliFailure {
    pub message: String,
    pub exit_code: i32,
}

impl CliFailure {
    fn general(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exit_code: EXIT_FAILURE,
        }
    }

    fn worker_usage(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exit_code: EXIT_WORKER_USAGE,
        }
    }
}

impl From<String> for CliFailure {
    fn from(message: String) -> Self {
        Self::general(message)
    }
}

const BUILD_VERSION: &str = match option_env!("BOXD_BUILD_VERSION") {
    Some(version) => version,
    None => env!("CARGO_PKG_VERSION"),
};

#[derive(Debug, Parser)]
#[command(name = "boxd", version = BUILD_VERSION, about = "boxd control-plane host")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Serve(ConfigArgs),
    Init(InitArgs),
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    Doctor(DoctorArgs),
    Runtime {
        #[command(subcommand)]
        command: RuntimeCommand,
    },
    #[command(name = "__vmm-worker", hide = true)]
    VmmWorker {
        #[arg(long)]
        spec_fd: i32,
    },
}
#[derive(Debug, Args)]
struct ConfigArgs {
    #[arg(short = 'c', long, default_value = "boxd.toml")]
    config: PathBuf,
    #[command(flatten)]
    overrides: ConfigOverrideArgs,
}
#[derive(Debug, Args)]
struct InitArgs {
    #[arg(long, default_value = "boxd.toml")]
    config: PathBuf,
}
#[derive(Debug, Args)]
struct DoctorArgs {
    #[arg(short = 'c', long, default_value = "boxd.toml")]
    config: PathBuf,
    #[arg(long)]
    json: bool,
    #[command(flatten)]
    overrides: ConfigOverrideArgs,
}
#[derive(Clone, Debug, Default, Args)]
struct ConfigOverrideArgs {
    #[arg(long)]
    listen: Option<String>,
    #[arg(long)]
    public_url: Option<String>,
    #[arg(long)]
    database_url: Option<String>,
    #[arg(long)]
    data_dir: Option<PathBuf>,
}
impl From<ConfigOverrideArgs> for config::CliOverrides {
    fn from(value: ConfigOverrideArgs) -> Self {
        Self {
            listen: value.listen,
            public_url: value.public_url,
            database_url: value.database_url,
            data_dir: value.data_dir,
        }
    }
}
#[derive(Debug, Subcommand)]
enum ConfigCommand {
    Validate(ConfigArgs),
}
#[derive(Debug, Subcommand)]
enum RuntimeCommand {
    Pull {
        name: String,
        #[arg(short = 'c', long, default_value = "boxd.toml")]
        config: PathBuf,
    },
    Import {
        bundle: PathBuf,
        #[arg(short = 'c', long, default_value = "boxd.toml")]
        config: PathBuf,
    },
}

pub async fn run() -> Result<(), CliFailure> {
    let result = match Cli::parse().command {
        Command::Init(args) => init::run(&args.config).await,
        Command::Config {
            command: ConfigCommand::Validate(args),
        } => validate(&args.config, args.overrides.into()),
        Command::Doctor(args) => {
            let config = checked_config(&args.config, args.overrides.into())?;
            doctor::run(&config, args.json)
        }
        Command::Serve(args) => {
            let config = checked_config(&args.config, args.overrides.into())?;
            composition::serve(config).await
        }
        Command::Runtime {
            command: RuntimeCommand::Pull { name, config },
        } => runtime_image::pull(
            &checked_config(&config, config::CliOverrides::default())?,
            &name,
        ),
        Command::Runtime {
            command: RuntimeCommand::Import { bundle, config },
        } => runtime_image::import(
            &checked_config(&config, config::CliOverrides::default())?,
            &bundle,
        ),
        Command::VmmWorker { spec_fd } => {
            let _ = spec_fd;
            return Err(CliFailure::worker_usage(
                "__vmm-worker is accepted only as the exact hidden invocation with --spec-fd 0",
            ));
        }
    };
    result.map_err(CliFailure::general)
}

fn validate(path: &std::path::Path, overrides: config::CliOverrides) -> Result<(), String> {
    let warnings = config::validate(&checked_config(path, overrides)?)?;
    println!("configuration is valid");
    for warning in warnings {
        eprintln!("warning: {warning}");
    }
    Ok(())
}
fn checked_config(
    path: &std::path::Path,
    overrides: config::CliOverrides,
) -> Result<config::AppConfig, String> {
    let mut config = config::load(Some(path), &overrides)?;
    config::resolve_storage_paths(path, &mut config)?;
    config::validate(&config)?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    #[test]
    fn parses_documented_commands() {
        assert!(Cli::try_parse_from(["boxd", "serve", "-c", "a.toml"]).is_ok());
        assert!(Cli::try_parse_from(["boxd", "config", "validate", "-c", "a.toml"]).is_ok());
        assert!(Cli::try_parse_from(["boxd", "doctor", "--json"]).is_ok());
        assert!(
            Cli::try_parse_from([
                "boxd",
                "config",
                "validate",
                "--listen",
                "127.0.0.1:7444",
                "--public-url",
                "http://127.0.0.1:7444",
                "--database-url",
                "sqlite://override.sqlite3?mode=rwc",
                "--data-dir",
                "./override-data"
            ])
            .is_ok()
        );
        assert!(Cli::try_parse_from(["boxd", "__vmm-worker", "--spec-fd", "3"]).is_ok());
    }
}
