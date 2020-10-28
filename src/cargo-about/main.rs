#![warn(clippy::all)]
#![warn(rust_2018_idioms)]

use anyhow::{anyhow, bail, Context, Error};
use std::path::{Path, PathBuf};
use structopt::StructOpt;

mod generate;
mod init;

#[global_allocator]
static ALLOC: rpmalloc::RpMalloc = rpmalloc::RpMalloc;

#[derive(StructOpt, Debug)]
enum Command {
    /// Outputs a listing of all licenses and the crates that use them
    #[structopt(name = "generate")]
    Generate(generate::Args),
    #[structopt(name = "init")]
    Init(init::Args),
}

fn parse_level(s: &str) -> Result<log::LevelFilter, Error> {
    s.parse::<log::LevelFilter>()
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
    log_level: log::LevelFilter,
    /// Space-separated list of features to activate
    #[structopt(long)]
    features: Vec<String>,
    /// Activate all available features
    #[structopt(long)]
    all_features: bool,
    /// Do not activate the `default` feature
    #[structopt(long)]
    no_default_features: bool,
    /// The path of the Cargo.toml for the root crate, defaults to the
    /// current crate or workspace in the current working directory
    #[structopt(short, long = "manifest-path", parse(from_os_str))]
    manifest_path: Option<PathBuf>,
    #[structopt(subcommand)]
    cmd: Command,
}

fn setup_logger(level: log::LevelFilter) -> Result<(), fern::InitError> {
    use ansi_term::Color::*;
    use log::Level::*;

    fern::Dispatch::new()
        .level(log::LevelFilter::Warn)
        .level_for("cargo_about", level)
        .format(move |out, message, record| {
            out.finish(format_args!(
                "{date} [{level}] {message}\x1B[0m",
                date = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S"),
                level = match record.level() {
                    Error => Red.paint("ERROR"),
                    Warn => Yellow.paint("WARN"),
                    Info => Green.paint("INFO"),
                    Debug => Blue.paint("DEBUG"),
                    Trace => Purple.paint("TRACE"),
                },
                message = message,
            ));
        })
        .chain(std::io::stderr())
        .apply()?;
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

            log::info!("loaded config from {}", about_toml.display());
            return Ok(cfg);
        }

        parent = p.parent();
    }

    log::warn!("no 'about.toml' found, falling back to default configuration");
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

    setup_logger(args.log_level)?;

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

    let (all_crates, store) = rayon::join(
        || {
            log::info!("gathering crates for {}", manifest_path.display());
            cargo_about::get_all_crates(
                manifest_path,
                args.no_default_features,
                args.all_features,
                args.features.clone(),
                &cfg,
            )
        },
        || {
            log::info!("loading license store");
            cargo_about::licenses::LicenseStore::from_cache()
        },
    );

    let all_crates = all_crates?;
    let store = store?;

    log::info!("gathered {} crates", all_crates.len());

    match args.cmd {
        Command::Generate(gen) => generate::cmd(gen, cfg, all_crates, store),
        Command::Init(init) => init::cmd(init),
    }
}

fn main() {
    match real_main() {
        Ok(_) => {}
        Err(e) => {
            log::error!("{:#}", e);
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_cmd::prelude::*;
    use std::boxed::Box;
    use std::env;
    use std::path::Path;
    use std::path::PathBuf;
    use std::process::Command;

    #[test]
    fn end_to_end() -> Result<(), Box<dyn std::error::Error>> {
        std::env::set_current_dir("./test");
        let mut cmd = Command::cargo_bin("cargo-about").unwrap();

        cmd.arg("init").current_dir(&env::current_dir().unwrap());
        cmd.assert().success();

        //TODO Check => https://rust-cli.github.io/book/tutorial/testing.html#generating-test-files
        Ok(())
    }
}
