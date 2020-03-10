use anyhow::{bail, Error};

pub mod auth;
mod commit;
pub mod config;

//pub mod commit;
//pub mod signature;

pub use self::commit::Commit;

//use self::authentication::with_authentication;
use git2;
use std::{fs, path::PathBuf};

/// Default overlay repository
pub const DEFAULT_URL: &str = "https://github.com/EmbarkStudios/overlay.git";

/// Directory under ~/.cargo where the overlay repo will be kept
pub(crate) const OVERLAY_DIRECTORY: &str = "license-overlay";

/// Ref for master in the local repository
const LOCAL_MASTER_REF: &str = "refs/heads/master";

/// Ref for master in the remote repository
const REMOTE_MASTER_REF: &str = "refs/remotes/origin/master";

/// Git repository for a license overlay
pub struct Repository {
    /// Path to the Git repository
    path: PathBuf,
    /// Repository object
    repo: git2::Repository,
}

impl Repository {
    /// Location of the default `license-overlay` repository
    pub fn default_path() -> PathBuf {
        home::cargo_home()
            .unwrap_or_else(|err| {
                panic!("Error locating Cargo home directory: {}", err);
            })
            .join(OVERLAY_DIRECTORY)
    }

    /// Fetch the default repository
    pub fn fetch_default_repo() -> Result<Self, Error> {
        Self::fetch(DEFAULT_URL, Repository::default_path())
    }

    /// Create a new [`Repository`] with the given URL and path
    pub fn fetch<P: Into<PathBuf>>(url: &str, into_path: P) -> Result<Self, Error> {
        if !url.starts_with("https://") {
            bail!("expected {} to start with https://", url);
        }

        let path = into_path.into();

        if let Some(parent) = path.parent() {
            if !parent.is_dir() {
                fs::create_dir_all(parent)?;
            }
        } else {
            bail!("invalid directory: {}", path.display())
        }

        // Avoid libgit2 errors in the case the directory exists but is
        // otherwise empty.
        //
        // See: https://github.com/RustSec/cargo-audit/issues/32
        if path.is_dir() && fs::read_dir(&path)?.next().is_none() {
            fs::remove_dir(&path)?;
        }

        let git_config = git2::Config::new()?;

        auth::with_authentication(url, &git_config, |f| {
            let mut callbacks = git2::RemoteCallbacks::new();
            callbacks.credentials(f);

            let mut proxy_opts = git2::ProxyOptions::new();
            proxy_opts.auto();

            let mut fetch_opts = git2::FetchOptions::new();
            fetch_opts.remote_callbacks(callbacks);
            fetch_opts.proxy_options(proxy_opts);

            if path.exists() {
                let repo = git2::Repository::open(&path)?;
                let refspec = LOCAL_MASTER_REF.to_owned() + ":" + REMOTE_MASTER_REF;

                // Fetch remote packfiles and update tips
                let mut remote = repo.remote_anonymous(url)?;
                remote.fetch(&[refspec.as_str()], Some(&mut fetch_opts), None)?;

                // Get the current remote tip (as an updated local reference)
                let remote_master_ref = repo.find_reference(REMOTE_MASTER_REF)?;
                let remote_target = remote_master_ref.target().unwrap();

                // Set the local master ref to match the remote
                let mut local_master_ref = repo.find_reference(LOCAL_MASTER_REF)?;
                local_master_ref.set_target(
                    remote_target,
                    &format!(
                        "cargo-about: moving master to {}: {}",
                        REMOTE_MASTER_REF, &remote_target
                    ),
                )?;
            } else {
                git2::build::RepoBuilder::new()
                    .fetch_options(fetch_opts)
                    .clone(url, &path)?;
            }

            Ok(())
        })?;

        let repo = Self::open(path)?;
        let latest_commit = repo.latest_commit()?;
        latest_commit.reset(&repo)?;

        Ok(repo)
    }

    /// Open a repository at the given path
    pub fn open<P: Into<PathBuf>>(into_path: P) -> Result<Self, Error> {
        let path = into_path.into();
        let repo = git2::Repository::open(&path)?;

        if repo.state() == git2::RepositoryState::Clean {
            Ok(Repository { path, repo })
        } else {
            bail!("bad repository state: {:?}", repo.state())
        }
    }

    /// Get information about the latest commit to the repo
    pub fn latest_commit(&self) -> Result<Commit, Error> {
        Commit::from_repo_head(self)
    }

    /// Paths to all advisories located in the database
    pub fn packages(&self) -> Result<Vec<PathBuf>, Error> {
        let types = {
            let mut tb = ignore::types::TypesBuilder::new();
            tb.add_defaults();
            tb.select("toml");
            tb.build()?
        };

        let walker = ignore::WalkBuilder::new(self.path.join("crates"))
            .follow_links(false)
            .types(types)
            .build();

        Ok(walker
            .filter_map(|p| p.ok().map(|de| de.path().to_owned()))
            .collect())
    }
}
