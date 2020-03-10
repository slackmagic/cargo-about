#![warn(clippy::all)]
#![warn(rust_2018_idioms)]

use anyhow::Error;
use krates::cm;
use std::fmt;

pub mod licenses;
pub mod overlay;

pub struct Krate {
    pub inner: cm::Package,
    pub src: Option<url::Url>,
}

impl krates::KrateDetails for Krate {
    fn name(&self) -> &str {
        &self.inner.name
    }
    fn version(&self) -> &krates::semver::Version {
        &self.inner.version
    }
}

impl From<cm::Package> for Krate {
    fn from(mut pkg: cm::Package) -> Self {
        // Fix the license field as cargo used to allow the
        // invalid / separator
        // if let Some(ref mut lf) = pkg.license {
        //     *lf = lf.replace("/", " OR ");
        // }

        // Rip out the source once as it's a type that is just wrapping a
        // private string making it annoying to use
        let src = pkg
            .source
            .take()
            .and_then(|src| url::Url::parse(&format!("{}", src)).ok());

        Self { inner: pkg, src }
    }
}

impl fmt::Display for Krate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.inner.name, self.inner.version)
    }
}

impl std::ops::Deref for Krate {
    type Target = cm::Package;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

pub type Krates = krates::Krates<Krate>;

pub fn get_all_crates(
    cargo_toml: std::path::PathBuf,
    no_default_features: bool,
    all_features: bool,
    features: Vec<String>,
    cfg: &licenses::config::Config,
) -> Result<Krates, Error> {
    let mut mdc = krates::Cmd::new();
    mdc.manifest_path(cargo_toml);

    // The metadata command builder is weird and only allows you to specify
    // one of these, but really you might need to do multiple of them
    if no_default_features {
        mdc.no_default_features();
    }

    if all_features {
        mdc.all_features();
    }

    mdc.features(features);

    let mut builder = krates::Builder::new();

    if cfg.ignore_build_dependencies {
        builder.ignore_kind(krates::DepKind::Build, krates::Scope::All);
    }

    if cfg.ignore_dev_dependencies {
        builder.ignore_kind(krates::DepKind::Dev, krates::Scope::All);
    }

    builder.include_targets(cfg.targets.iter().map(|triple| (triple.as_str(), vec![])));

    use tracing::debug;

    let graph = builder.build(mdc, |filtered: cm::Package| match filtered.source {
        Some(src) => {
            if src.is_crates_io() {
                debug!(
                    name = %filtered.name,
                    version = %filtered.version,
                    "filtered crate",
                );
            } else {
                debug!(
                    name = %filtered.name,
                    version = %filtered.version,
                    %src,
                    "filtered crate"
                );
            }
        }
        None => debug!(
            name = %filtered.name,
            version = %filtered.version,
            "filtered crate"
        ),
    })?;

    Ok(graph)
}
