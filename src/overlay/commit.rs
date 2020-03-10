//! Commits to the advisory DB git repository

use super::Repository;
use anyhow::{anyhow, Error};
use chrono::{DateTime, Duration, NaiveDateTime, Utc};
use git2;

/// Information about a commit to the Git repository
#[derive(Debug)]
pub struct Commit {
    /// ID (i.e. SHA-1 hash) of the latest commit
    pub commit_id: String,

    /// Information about the author of a commit
    pub author: String,

    /// Summary message for the commit
    pub summary: String,

    /// Commit time in number of seconds since the UNIX epoch
    pub time: DateTime<Utc>,
}

impl Commit {
    /// Get information about HEAD
    pub(crate) fn from_repo_head(repo: &Repository) -> Result<Self, Error> {
        let head = repo.repo.head()?;

        let oid = head
            .target()
            .ok_or_else(|| anyhow!("no ref target for: {}", repo.path.display()))?;

        let commit_id = oid.to_string();
        let commit_object = repo.repo.find_object(oid, Some(git2::ObjectType::Commit))?;
        let commit = commit_object.as_commit().unwrap();
        let author = commit.author().to_string();

        let summary = commit
            .summary()
            .ok_or_else(|| anyhow!("no commit summary for {}", commit_id))?
            .to_owned();

        let time = DateTime::from_utc(
            NaiveDateTime::from_timestamp(commit.time().seconds(), 0),
            Utc,
        );

        Ok(Commit {
            commit_id,
            author,
            summary,

            time,
        })
    }

    /// Reset the repository's state to match this commit

    pub(crate) fn reset(&self, repo: &Repository) -> Result<(), Error> {
        let commit_object = repo.repo.find_object(
            git2::Oid::from_str(&self.commit_id).unwrap(),
            Some(git2::ObjectType::Commit),
        )?;

        // Reset the state of the repository to the latest commit
        repo.repo
            .reset(&commit_object, git2::ResetType::Hard, None)?;

        Ok(())
    }
}
