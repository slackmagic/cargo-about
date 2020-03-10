#![warn(clippy::all)]
#![warn(rust_2018_idioms)]

use anyhow::{anyhow, bail, Context, Error};
use std::path::{Path, PathBuf};
use structopt::StructOpt;
use tracing_subscriber::filter::LevelFilter;

mod generate;
mod init;

#[derive(StructOpt, Debug)]
enum Command {
    /// Outputs a listing of all licenses and the crates that use them
    #[structopt(name = "generate")]
    Generate(generate::Args),
    #[structopt(name = "init")]
    Init(init::Args),
}

fn parse_level(s: &str) -> Result<LevelFilter, Error> {
    s.parse::<LevelFilter>()
        .map_err(|e| anyhow!("failed to parse level '{}': {}", s, e))
}

#[derive(Debug, StructOpt)]
struct Opts {
    /// The log level for messages, only log messages at or above
    /// the level will be emitted.
    #[structopt(
        short = "L",
        long = "log-level",
        default_value = "warn",
        parse(try_from_str = parse_level),
        long_help = "The log level for messages, only log messages at or above the level will be emitted.

Possible values:
* off
* error
* warn
* info
* debug
* trace"
    )]
    log_level: LevelFilter,
    /// Space-separated list of features to activate
    #[structopt(long)]
    features: Vec<String>,
    /// Activate all available features
    #[structopt(long)]
    all_features: bool,
    /// Do not activate the `default` feature
    #[structopt(long)]
    no_default_features: bool,
    /// Output log messages as json
    #[structopt(long)]
    json: bool,
    /// The path of the Cargo.toml for the root crate, defaults to the
    /// current crate or workspace in the current working directory
    #[structopt(short, long = "manifest-path", parse(from_os_str))]
    manifest_path: Option<PathBuf>,
    #[structopt(subcommand)]
    cmd: Command,
}

fn setup_logger(args: &Opts) -> Result<(), Error> {
    let mut env_filter = tracing_subscriber::EnvFilter::from_default_env();

    // If a user specifies a log level, we assume it only pertains to cargo_fetcher,
    // if they want to trace other crates they can use the RUST_LOG env approach
    env_filter = env_filter.add_directive(args.log_level.clone().into());

    let subscriber = tracing_subscriber::FmtSubscriber::builder().with_env_filter(env_filter);

    if args.json {
        tracing::subscriber::set_global_default(subscriber.json().finish())
            .context("failed to set default subscriber")?;
    } else {
        tracing::subscriber::set_global_default(subscriber.finish())
            .context("failed to set default subscriber")?;
    };

    Ok(())
}

fn load_config(manifest_path: &Path) -> Result<cargo_about::licenses::config::Config, Error> {
    let mut parent = manifest_path.parent();

    // Move up directories until we find an about.toml, to handle
    // cases where eg in a workspace there is a top-level about.toml
    // but the user is only getting a listing for a particular crate from it
    while let Some(p) = parent {
        // We _could_ limit ourselves to only directories that also have a Cargo.toml
        // in them, but there could be cases where someone has multiple
        // rust projects in subdirectories with a single top level about.toml that is
        // used across all of them, we could also introduce a metadata entry for the
        // relative path of the about.toml to use for the crate/workspace

        // if !p.join("Cargo.toml").exists() {
        //     parent = p.parent();
        //     continue;
        // }

        let about_toml = p.join("about.toml");

        if about_toml.exists() {
            let contents = std::fs::read_to_string(&about_toml)?;
            let cfg = toml::from_str(&contents)?;

            tracing::info!(path = %about_toml.display(), "loaded config");
            return Ok(cfg);
        }

        parent = p.parent();
    }

    tracing::warn!("no 'about.toml' found, falling back to default configuration");
    Ok(cargo_about::licenses::config::Config::default())
}

fn real_main() -> Result<(), Error> {
    let args = Opts::from_iter({
        std::env::args().enumerate().filter_map(|(i, a)| {
            if i == 1 && a == "about" {
                None
            } else {
                Some(a)
            }
        })
    });

    setup_logger(&args)?;

    let manifest_path = args
        .manifest_path
        .clone()
        .or_else(|| {
            std::env::current_dir()
                .and_then(|cd| Ok(cd.join("Cargo.toml")))
                .ok()
        })
        .context("unable to determine manifest path")?;

    if !manifest_path.exists() {
        bail!(
            "cargo manifest path '{}' does not exist",
            manifest_path.display()
        );
    }

    let cfg = load_config(&manifest_path)?;
    use tracing::info;

    let (all_crates, store) = rayon::join(
        || {
            info!(manifest = %manifest_path.display(), "gathering crates");
            cargo_about::get_all_crates(
                manifest_path,
                args.no_default_features,
                args.all_features,
                args.features.clone(),
                &cfg,
            )
        },
        || {
            info!("loading license store");
            cargo_about::licenses::LicenseStore::from_cache()
        },
    );

    let all_crates = all_crates?;
    let store = store?;

    info!(count = all_crates.len(), "gathered crates");

    match args.cmd {
        Command::Generate(gen) => generate::cmd(gen, cfg, all_crates, store),
        Command::Init(init) => init::cmd(init),
    }
}

fn main() {
    match real_main() {
        Ok(_) => {}
        Err(e) => {
            tracing::error!("{:#}", e);
            std::process::exit(1);
        }
    }
}
