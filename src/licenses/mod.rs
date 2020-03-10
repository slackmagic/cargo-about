use crate::{Krate, Krates};
use anyhow::{bail, Context, Error};
use rayon::prelude::*;
use spdx::{LicenseId, LicenseItem, LicenseReq, Licensee};
use std::fmt;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use tracing::{debug, error, info, warn};

pub mod config;

const LICENSE_CACHE: &[u8] = include_bytes!("../../spdx_cache.bin.zstd");

pub struct LicenseStore {
    store: askalono::Store,
}

impl LicenseStore {
    pub fn from_cache() -> Result<Self, Error> {
        let store = askalono::Store::from_cache(LICENSE_CACHE)
            .map_err(|e| anyhow::anyhow!("failed to load license store: {}", e))?;

        Ok(Self { store })
    }
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum LicenseInfo {
    Expr(spdx::Expression),
    Unknown,
}

/// The contents of a file with license info in it
pub enum LicenseFileInfo {
    /// The license file is the canonical text of the license
    Text(String),
    /// The license file is the canonical text, and applies to
    /// a path root
    AddendumText(String, PathBuf),
    /// The file just has a license header, and presumably
    /// also contains other text in it (like, you know, code)
    Header,
}

pub struct LicenseFile {
    /// The SPDX identifier for the license in the file
    pub id: LicenseId,
    /// Full path of the file which had license data in it
    pub path: PathBuf,
    /// The confidence score for the license, the closer to the canonical
    /// license text it is, the closert it approaches 1.0
    pub confidence: f32,
    /// The contents of the file
    pub info: LicenseFileInfo,
}

pub struct KrateLicense<'a> {
    pub krate: &'a Krate,
    pub lic_info: LicenseInfo,
    pub license_files: Vec<LicenseFile>,
}

pub struct Summary<'a> {
    store: Arc<LicenseStore>,
    pub nfos: Vec<KrateLicense<'a>>,
}

impl<'a> Summary<'a> {
    fn new(store: Arc<LicenseStore>) -> Self {
        Self {
            store,
            nfos: Vec::new(),
        }
    }
}

#[derive(Debug)]
struct CDFile {
    path: PathBuf,
    hash: String,
    expr: String,
}

#[derive(Debug)]
struct CDDef<'a> {
    /// The id of the crate for the definition
    id: &'a krates::Kid,
    /// The (usually) SPDX expression that clearly defined thinks the crate uses
    declared: String,
    /// The individual (usually) SPDX license identifiers that were actually discovered
    discovered: Vec<String>,
    license_files: Vec<CDFile>,
}

/// Attempts to retrieve licensing terms for every (remote) crate from
/// clearlydefined.io, returning a sorted (by package id) list of definitions
/// actually found, excluding crates that haven't been harvested
fn get_clearly_defined<'k>(krates: &'k crate::Krates) -> Vec<CDDef<'k>> {
    let mut cded: Vec<CDDef<'_>> = Vec::with_capacity(krates.len());

    {
        let client = cd::client::Client::new();

        for response in cd::definitions::get(krates.krates().filter_map(|k| {
            let k = &k.krate;

            // Ignore crates that have a non-github/crates.io source
            if let Some(src) = &k.src  {
                let (shape, provider, ns) = match src.host() {
                    Some(url::Host::Domain("crates.io")) => {
                        (cd::Shape::Crate, cd::Provider::CratesIo, None)
                    }
                    Some(url::Host::Domain("github.com")) => {
                        // _should_ be `/<org>/<repo>`
                        let path = &src.path()[1..];
                        match path.find('/') {
                            Some(ind) => {
                                (cd::Shape::Git, cd::Provider::Github, Some((&path[..ind]).to_owned()))
                            }
                            None => {
                                warn!(krate = %k, url = %src, "detected malformed github URL");
                                return None;
                            }
                        }
                    }
                    Some(_) => {
                        // TODO: support alternative registries in a possible future
                        // where clearlydefined supports them, but for now just
                        // log that we found it and move on
                        warn!("crate '{}' is sourced from a location incompatible with clearlydefined.io and will be ignored", k.id);
                        return None;
                    }
                    None => return None,
                };

                return Some(cd::Coordinate {
                    shape,
                    provider,
                    namespace: ns,
                    name: k.name.clone(),
                    version: cd::CoordVersion::Semver(k.version.clone()),
                    // TODO: Support curation PRs configured by the user?
                    curation_pr: None,
                });
            }

            None
        })).flat_map(|req| {
            client.execute(req).into_iter().map(|res: cd::definitions::GetResponse| {
                res.definitions.into_iter()
                    .filter_map(|def| {
                        // Map the coordinate of the component back to the krate id
                        krates.krates_by_name(&def.coordinates.name).find(|(_, node)| {
                            let version_match = match &def.coordinates.revision {
                                cd::CoordVersion::Semver(semver) => {
                                    semver == &node.krate.version
                                }
                                // Just in case, but we should never have an invalid semver version
                                cd::CoordVersion::Any(s) => {
                                    s == &format!("{}", node.krate.version)
                                }
                            };

                            match &node.krate.src {
                                Some(src) => {
                                    match src.host() {
                                        Some(url::Host::Domain("crates.io")) => {
                                            version_match && def.coordinates.provider == cd::Provider::CratesIo
                                        }
                                        Some(url::Host::Domain("github.com")) => {
                                            version_match && def.coordinates.provider == cd::Provider::Github
                                        }
                                        _ => false,
                                    }
                                }
                                None => false,
                            }
                        }).and_then(|(_, node)| {
                            let files = def.files;
                            def.licensed.map(|lic| {
                                // Get all of the license files that were discovered by clearlydefined
                                let license_files = files.into_iter().filter_map(|file| {
                                    // clearlydefined tags files with "natures", LICENSE files are tagged with the
                                    // license nature to indicate they are license text and (probably) don't have any
                                    // actual code in them
                                    if !file.natures.iter().any(|s| s == "license") {
                                        return None;
                                    }

                                    match (file.license, file.hashes) {
                                        (Some(lic), Some(hashes)) => {
                                            Some(CDFile {
                                                expr: lic,
                                                hash: match hashes.sha256 {
                                                    Some(h) => h,
                                                    None => hashes.sha1,
                                                },
                                                path: PathBuf::from(file.path),
                                            })
                                        }
                                        _ => None,
                                    }
                                }).collect();

                                CDDef {
                                    id: &node.krate.id,
                                    declared: lic.declared,
                                    discovered: lic.facets.core.discovered.expressions,
                                    license_files,
                                }
                            })
                        })
                    })
            })
        }) {
            cded.extend(response);
        }
    }

    cded.sort_by_key(|cd: &CDDef<'_>| cd.id);
    cded
}

/// Gather only the files that clearlydefined has already identified as license files, if a single
/// error is encountered for any reason we fail the entire set of possibilities
fn gather_clearly_defined(
    root: &Path,
    clearly_defed: &CDDef<'_>,
) -> Result<Vec<LicenseFile>, Error> {
    let map = |f: &CDFile| -> Result<LicenseFile, Error> {
        let full_path = root.join(&f.path);
        let contents = std::fs::read_to_string(&full_path)?;

        use ring::digest;
        // Validate that the hashes match
        let algo = match f.hash.len() {
            // sha1
            40 => &digest::SHA1_FOR_LEGACY_USE_ONLY,
            // sha256
            64 => &digest::SHA256,
            _ => bail!("unknown digest algorithm used by clearlydefined.io"),
        };

        let sha_digest = digest::digest(algo, contents.as_bytes());
        let digest = sha_digest.as_ref();

        for (ind, exp) in f.hash.as_bytes().chunks(2).enumerate() {
            let mut cur = match exp[0] {
                b'A'..=b'F' => exp[0] - b'A' + 10,
                b'a'..=b'f' => exp[0] - b'a' + 10,
                b'0'..=b'9' => exp[0] - b'0',
                c => bail!("invalid byte in expected checksum string {}", c),
            };

            cur <<= 4;

            cur |= match exp[1] {
                b'A'..=b'F' => exp[1] - b'A' + 10,
                b'a'..=b'f' => exp[1] - b'a' + 10,
                b'0'..=b'9' => exp[1] - b'0',
                c => bail!("invalid byte in expected checksum string {}", c),
            };

            if digest[ind] != cur {
                bail!("checksum mismatch, expected {}", f.hash);
            }
        }

        match spdx::Expression::parse_mode(&f.expr, spdx::ParseMode::Lax) {
            Ok(validated) => {
                Ok(LicenseFile {
                    id: validated
                        .requirements()
                        .filter_map(|req| req.req.license.id())
                        .collect(),
                    path: full_path,
                    // clearlydefined only keeps scores on a package level, not an individual
                    // file level, so just make this up
                    confidence: 0.95,
                    info: LicenseFileInfo::Text(contents),
                })
            }
            Err(err) => {
                error!(
                    err = %err.reason,
                    license = %f.expr,
                    "unable to parse license expression",
                );

                // ParseError uses a lifetime...my fault
                bail!("failed to parse expression: {}", err);
            }
        }
    };

    clearly_defed
        .license_files
        .iter()
        .map(|cdf| map(cdf))
        .collect()
}

fn licenses_match(lic_info: &LicenseInfo, clearly_defed: &CDDef<'_>) -> bool {
    // Use relaxed parsing rules for SPDX expressions from clearlydefined, as, for example
    // there "may" be some non-valid license identifiers in the harvested data
    match spdx::Expression::parse_mode(&clearly_defed.declared, spdx::ParseMode::Lax) {
        Ok(expr) => {
            // Only scan files if the crate's declared expression doesn't match the one on clearlydefined.io,
            // as they do more in depth analysis and attribution detection that should be more accurate
            // than what we could gather ourselves
            if let LicenseInfo::Expr(declared) = &lic_info {
                // clearlydefined has a bug where `/` is interpreted as `AND` rather than `OR`
                // so ignore
                let has_slashes = declared.as_ref().contains('/');
                use spdx::expression::{ExprNode, Operator as Op};

                let matches = declared.iter().zip(expr.iter()).all(|(d, e)| match (d, e) {
                    (ExprNode::Req(dl), ExprNode::Req(el)) => {
                        dl.req.license.id() == el.req.license.id()
                    }
                    (ExprNode::Op(dop), ExprNode::Op(eop)) => {
                        dop == eop || (dop == &Op::Or && eop == &Op::And && has_slashes)
                    }
                    _ => false,
                });

                if !matches {
                    error!(
                        "crate '{}' clearlydefined.io {}",
                        declared, clearly_defed.declared,
                    );
                }

                matches
            } else {
                false
            }
        }
        Err(err) => {
            warn!(
                err = %err.reason,
                expr = %clearly_defed.declared,
                "unable to parse declared expression from clearlydefined.io",
            );
            false
        }
    }
}

pub struct Gatherer {
    store: Arc<LicenseStore>,
    threshold: f32,
}

impl Gatherer {
    pub fn with_store(store: Arc<LicenseStore>) -> Self {
        Self {
            store,
            threshold: 0.8,
        }
    }

    pub fn with_confidence_threshold(mut self, threshold: f32) -> Self {
        self.threshold = if threshold > 1.0 {
            1.0
        } else if threshold < 0.0 {
            0.0
        } else {
            threshold
        };
        self
    }

    pub fn gather<'k>(self, krates: &'k Krates, cfg: &config::Config) -> Summary<'k> {
        let mut summary = Summary::new(self.store);

        let threshold = self.threshold;
        let min_threshold = threshold - 0.5;

        let strategy = askalono::ScanStrategy::new(&summary.store.store)
            .mode(askalono::ScanMode::Elimination)
            .confidence_threshold(if min_threshold < 0.1 {
                0.1
            } else {
                min_threshold
            })
            .optimize(false)
            .max_passes(1);

        let cded = get_clearly_defined(krates);

        summary.nfos = krates
            .krates()
            .par_bridge()
            .map(|kn| {
                let krate = &kn.krate;

                let span = tracing::info_span!("gather", krate = %krate);
                let _ = span.enter();

                let info = match krate.license {
                    Some(ref license_field) => {
                        //. Reasons this can fail:
                        // * Empty! The rust crate used to validate this field has a bug
                        // https://github.com/rust-lang-nursery/license-exprs/issues/23
                        // * It also just does basic lexing, so parens, duplicate operators,
                        // unpaired exceptions etc can all fail validation

                        match spdx::Expression::parse_mode(license_field, spdx::ParseMode::Lax) {
                            Ok(validated) => LicenseInfo::Expr(validated),
                            Err(err) => {
                                error!(
                                    krate = %krate,
                                    err = %err.reason,
                                    license = %license_field,
                                    "unable to parse license expression",
                                );
                                LicenseInfo::Unknown
                            }
                        }
                    }
                    None => {
                        debug!(
                            krate = %krate,
                            "crate doesn't have a license field",
                        );
                        LicenseInfo::Unknown
                    }
                };

                let clearly_defed = cded
                    .binary_search_by(|cd: &CDDef<'_>| cd.id.cmp(&krate.id))
                    .map(|ind| &cded[ind])
                    .ok();

                // Check if clearly defined had a definition for the krate in
                // question.
                let use_clearly_defined = if let Some(clearly_defed) = clearly_defed {
                    licenses_match(&info, clearly_defed)
                } else {
                    false
                };

                let root_path = krate.manifest_path.parent().unwrap();
                let krate_cfg = cfg.crates.get(&krate.name);

                let mut license_files = if use_clearly_defined {
                    match gather_clearly_defined(&root_path, clearly_defed.unwrap()) {
                        Ok(cded) => {
                            debug!(
                                krate = %krate,
                                gathered = cded.len(),
                                "gathered license files based on clearlydefined.io definition",
                            );
                            cded
                        }
                        Err(err) => {
                            error!(
                                krate = %krate,
                                %err,
                                "failed to scan license files determined by clearlydefined.io",
                            );

                            match scan_files(
                                &root_path,
                                &strategy,
                                threshold,
                                krate_cfg.map(|kc| (kc, krate.name.as_str())),
                            ) {
                                Ok(files) => files,
                                Err(err) => {
                                    error!(
                                        krate = %krate,
                                        %err,
                                        "unable to scan license files for crate",
                                    );

                                    Vec::new()
                                }
                            }
                        }
                    }
                } else {
                    match scan_files(
                        &root_path,
                        &strategy,
                        threshold,
                        krate_cfg.map(|kc| (kc, krate.name.as_str())),
                    ) {
                        Ok(files) => files,
                        Err(err) => {
                            error!(
                                krate = %krate,
                                %err,
                                "unable to scan license files for crate",
                            );

                            Vec::new()
                        }
                    }
                };

                // Condense each license down to the best candidate if
                // multiple are found
                license_files.sort_by(|a, b| {
                    use std::cmp::Ordering as Ord;
                    match a.id.cmp(&b.id) {
                        Ord::Equal => {
                            // We want the highest confidence on top
                            b.confidence
                                .partial_cmp(&a.confidence)
                                .expect("uhoh looks like we've got a NaN")
                        }
                        o => o,
                    }
                });

                let mut id = None;
                license_files.retain(|lf| match id {
                    Some(cur) => {
                        if cur != lf.id {
                            id = Some(lf.id);
                            true
                        } else {
                            false
                        }
                    }
                    None => {
                        id = Some(lf.id);
                        true
                    }
                });

                KrateLicense {
                    krate,
                    lic_info: info,
                    license_files,
                }
            })
            .collect();

        summary
    }
}

fn scan_files(
    root_dir: &Path,
    strat: &askalono::ScanStrategy<'_>,
    threshold: f32,
    krate_cfg: Option<(&config::KrateConfig, &str)>,
) -> Result<Vec<LicenseFile>, Error> {
    let types = {
        let mut tb = ignore::types::TypesBuilder::new();
        tb.add_defaults();
        tb.select("all");
        tb.build()?
    };

    let walker = ignore::WalkBuilder::new(root_dir)
        .standard_filters(true)
        .follow_links(true)
        .types(types)
        .build();

    let files: Vec<_> = walker.filter_map(|e| e.ok()).collect();

    let license_files: Vec<_> = files
        .into_par_iter()
        .filter_map(|file| {
            tracing::trace!(path = %file.path().display(), "scanning file");

            if let Some(ft) = file.file_type() {
                if ft.is_dir() {
                    return None;
                }
            }

            // Check for pipes on unix just in case
            #[cfg(unix)]
            {
                use std::os::unix::fs::FileTypeExt;

                if let Ok(md) = file.metadata() {
                    if md.file_type().is_fifo() {
                        error!(path = %file.path().display(), "skipping FIFO");
                        return None;
                    }
                }
            }

            let mut contents = match read_file(file.path()) {
                Some(c) => c,
                None => return None,
            };

            let expected = match krate_cfg {
                Some(krate_cfg) => {
                    let relative = match file.path().strip_prefix(root_dir) {
                        Ok(rel) => rel,
                        Err(_) => return None,
                    };

                    match krate_cfg
                        .0
                        .ignore
                        .iter()
                        .find(|i| relative == i.license_file)
                    {
                        Some(ignore) => {
                            contents =
                                snip_contents(contents, ignore.license_start, ignore.license_end);
                            Some((ignore.license, None))
                        }
                        None => {
                            let mut addendum = None;

                            for additional in &krate_cfg.0.additional {
                                if relative == additional.license_file {
                                    addendum = Some(additional);
                                    break;
                                }

                                if relative.starts_with(&additional.root) {
                                    tracing::trace!(
                                        path = %file.path().display(),
                                        root = %additional.root.display(),
                                        "skipping path due to addendum",
                                    );
                                    return None;
                                }
                            }

                            addendum
                                .map(|addendum| (addendum.license, Some(&addendum.license_file)))
                        }
                    }
                }
                None => None,
            };

            check_is_license_file(file.into_path(), contents, strat, threshold, expected)
        })
        .collect();

    Ok(license_files)
}

fn read_file(path: &Path) -> Option<String> {
    match std::fs::read_to_string(path) {
        Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData => {
            // If we fail due to invaliddata, it just means the file in question was
            // probably binary and didn't have valid utf-8 data, so we can ignore it
            debug!(path = %path.display(), "ignoring binary file");
            None
        }
        Err(e) => {
            error!(error = %e, path = %path.display(), "failed to read file");
            None
        }
        Ok(c) => Some(c),
    }
}

fn snip_contents(contents: String, start: Option<usize>, end: Option<usize>) -> String {
    let rng = start.unwrap_or(0)..end.unwrap_or(std::usize::MAX);

    if rng.start == 0 && rng.end == std::usize::MAX {
        contents
    } else {
        let mut snipped_contents = String::with_capacity(contents.len());
        for (i, line) in contents.lines().enumerate() {
            if i >= rng.start && i < rng.end {
                snipped_contents.push_str(line);
                snipped_contents.push('\n');
            }
        }

        snipped_contents
    }
}

fn check_is_license_file(
    path: PathBuf,
    contents: String,
    strat: &askalono::ScanStrategy<'_>,
    threshold: f32,
    expected: Option<(spdx::LicenseId, Option<&PathBuf>)>,
) -> Option<LicenseFile> {
    match scan_text(&contents, strat, threshold) {
        ScanResult::Header(ided) => {
            if let Some((exp_id, addendum)) = expected {
                if exp_id != ided.id {
                    error!(
                        expected = exp_id.name,
                        discovered = ided.id.name,
                        path = %path.display(),
                        "discovered license did not match expected license",
                    );
                } else if addendum.is_none() {
                    debug!(
                        license = ided.id.name,
                        path = %path.display(),
                        "ignoring file, matched expected license",
                    );
                    return None;
                }
            }

            Some(LicenseFile {
                id: vec![ided.id],
                confidence: ided.confidence,
                path,
                info: LicenseFileInfo::Header,
            })
        }
        ScanResult::Text(ided) => {
            let info = if let Some((exp_id, addendum)) = expected {
                if exp_id != ided.id {
                    error!(
                        expected = exp_id.name,
                        discovered = ided.id.name,
                        path = %path.display(),
                        "discovered license did not match expected license",
                    );
                }

                match addendum {
                    Some(path) => LicenseFileInfo::AddendumText(contents, path.clone()),
                    None => {
                        debug!(
                            expected = ided.id.name,
                            path = %path.display(),
                            "ignoring file, matched expected license",
                        );
                        return None;
                    }
                }
            } else {
                LicenseFileInfo::Text(contents)
            };

            Some(LicenseFile {
                id: vec![ided.id],
                confidence: ided.confidence,
                path,
                info,
            })
        }
        ScanResult::UnknownId(id_str) => {
            error!(
                id = %id_str,
                path = %path.display(),
                "found unknown SPDX identifier",
            );
            None
        }
        ScanResult::LowLicenseChance(ided) => {
            debug!(
                license = ided.id.name,
                path = %path.display(),
                score = (ided.confidence * 100.0) as u32,
                "ignoring license file with low confidence",
            );
            None
        }
        ScanResult::NoLicense => None,
    }
}

struct Identified {
    confidence: f32,
    id: spdx::LicenseId,
}

enum ScanResult {
    Header(Identified),
    Text(Identified),
    UnknownId(String),
    LowLicenseChance(Identified),
    NoLicense,
}

fn scan_text(contents: &str, strat: &askalono::ScanStrategy<'_>, threshold: f32) -> ScanResult {
    let text = askalono::TextData::new(&contents);
    match strat.scan(&text) {
        Ok(lic_match) => {
            match lic_match.license {
                Some(identified) => {
                    let lic_id = match spdx::license_id(&identified.name) {
                        Some(id) => Identified {
                            confidence: lic_match.score,
                            id,
                        },
                        None => return ScanResult::UnknownId(identified.name.to_owned()),
                    };

                    // askalano doesn't report any matches below the confidence threshold
                    // but we want to see what it thinks the license is if the confidence
                    // is somewhat ok at least
                    if lic_match.score >= threshold {
                        match identified.kind {
                            askalono::LicenseType::Header => ScanResult::Header(lic_id),
                            askalono::LicenseType::Original => ScanResult::Text(lic_id),
                            askalono::LicenseType::Alternate => {
                                unimplemented!("I guess askalono uses this now")
                            }
                        }
                    } else {
                        ScanResult::LowLicenseChance(lic_id)
                    }
                }
                None => ScanResult::NoLicense,
            }
        }
        Err(e) => {
            // the elimination strategy can't currently fail
            unimplemented!(
                "I guess askalano's elimination strategy can now fail: {}",
                e
            );
        }
    }
}

type KrateId = usize;

pub struct ResolveError<'a> {
    pub krate: &'a Krate,
    pub required: Vec<LicenseReq>,
}

impl fmt::Display for ResolveError<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Krate '{}' requires", self.krate.name)?;
        f.debug_list().entries(self.required.iter()).finish()?;
        writeln!(
            f,
            " , which were not specified as 'accepted' licenses in the 'about.toml' file"
        )
    }
}

/// Simple wrapper to display a slice of licensees
pub struct DisplayList<'a, T>(pub &'a [T]);

impl<T: fmt::Display> fmt::Display for DisplayList<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[")?;
        for (id, val) in self.0.iter().enumerate() {
            write!(f, "{}", val)?;
            if id + 1 < self.0.len() {
                write!(f, ", ")?;
            }
        }
        write!(f, "]")
    }
}

pub struct Resolved(pub Vec<(KrateId, Vec<LicenseReq>)>);

impl Resolved {
    /// Find the minimal required licenses for each crate.
    pub fn resolve<'a>(
        licenses: &'a [KrateLicense<'_>],
        accepted: &'a [Licensee],
    ) -> Result<Resolved, Error> {
        let res: Result<Vec<_>, Error> = licenses
        .par_iter()
        .enumerate()
        .map(move |(id, krate_license)| {
            // Check that the licenses found by scanning the crate contents match what was stated
            // in the license expression
            match krate_license.lic_info {
                LicenseInfo::Expr(ref expr) => {
                    let req = accepted.iter().find_map(|licensee| {
                        expr.requirements().find(|expr| licensee.satisfies(&expr.req))
                    }).map(|expr| expr.req.clone())
                    .context(format!(
                        "Crate '{}': Unable to satisfy [{}], with the following accepted licenses {}", krate_license.krate.name,
                        expr, DisplayList(accepted)
                    ))?;
                    Ok((id, vec![req]))
                }
                // If the license is unknown, we will concatenate all the licenses
                LicenseInfo::Unknown => {
                    let license_reqs: Vec<_> = krate_license
                        .license_files
                        .iter()
                        .flat_map(|file| {
                            file.id.iter().map(|id| {
                                LicenseReq {
                                    license: LicenseItem::SPDX {
                                        id: *id,
                                        or_later: false,
                                    },
                                    exception: None,
                                }
                            })
                        })
                        .collect();

                    let failed_licenses: Vec<_> = license_reqs
                        .iter()
                        .cloned()
                        .filter(|license| !accepted.iter().any(|a| a.satisfies(license)))
                        .collect();

                    if failed_licenses.is_empty() {
                        Ok((id, license_reqs))
                    } else {
                        bail!("Crate '{}': These licenses {}, could not be satisfied with the following accepted licenses {}",
                            krate_license.krate.name,
                            DisplayList(failed_licenses.as_slice()),
                            DisplayList(accepted));
                    }
                }
            }
        })
        .collect();
        Ok(Resolved(res?))
    }
}
