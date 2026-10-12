//! `lockwatch`: command-line front end for lockwatch-core.
//!
//! This file only parses arguments, calls the library and prints results.
//! Exit codes: 0 = nothing at or above `--fail-on`; 1 = findings at or above
//! it; 2 = tool error, or some packages could not be scanned.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use lockwatch_core::registry::DEFAULT_REGISTRY;
use lockwatch_core::report::Report;
use lockwatch_core::rules::{Severity, RULES};
use lockwatch_core::scan::{
    scan_lockfile, scan_package_spec, scan_tarball, LocalTarball, ScanOptions,
    MAX_LOCAL_TARBALL_BYTES,
};
use lockwatch_core::time::parse_rfc3339;

/// `#[derive(Parser)]` makes clap generate the argument parser, `--help`
/// and `--version` from this struct and its doc comments.
#[derive(Parser)]
#[command(name = "lockwatch", version, about = "npm supply-chain risk scanner")]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Print progress logs to stderr (-v info, -vv debug)
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,
}

#[derive(Subcommand)]
enum Command {
    /// Scan every package in a package-lock.json (v2 or v3)
    Scan {
        /// Path to package-lock.json
        lockfile: PathBuf,
        #[command(flatten)]
        opts: ScanArgs,
    },
    /// Scan one published package, for example `left-pad@1.3.0`
    ScanPackage {
        /// <name>@<version>
        spec: String,
        #[command(flatten)]
        opts: ScanArgs,
    },
    /// Scan a package tarball (.tgz) from disk, or from stdin with `-`
    ScanTarball {
        /// Path to the .tgz file, or `-` to read it from stdin
        tarball: PathBuf,
        /// Package name [default: read from the tarball's package.json]
        #[arg(long)]
        name: Option<String>,
        /// Package version [default: read from the tarball's package.json]
        #[arg(long = "package-version")]
        package_version: Option<String>,
        /// Expected integrity (SRI, e.g. sha512-...); a mismatch is LW012
        #[arg(long)]
        integrity: Option<String>,
        /// Fetch registry metadata for LW009/LW010 (off by default)
        #[arg(long, conflicts_with = "packument")]
        metadata: bool,
        /// Use this saved registry metadata JSON for LW009/LW010 instead
        #[arg(long)]
        packument: Option<PathBuf>,
        #[command(flatten)]
        opts: ScanArgs,
    },
    /// List the detection rules
    Rules {
        #[arg(long, value_enum, default_value_t = Format::Table)]
        format: Format,
    },
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Format {
    Json,
    Table,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum FailOn {
    Critical,
    High,
    Medium,
    Low,
    None,
}

/// Options shared by `scan` and `scan-package`. `#[command(flatten)]`
/// above includes these fields in both subcommands.
#[derive(Args)]
struct ScanArgs {
    /// Output format
    #[arg(long, value_enum, default_value_t = Format::Table)]
    format: Format,

    /// Write the report to this file instead of stdout
    #[arg(long)]
    out: Option<PathBuf>,

    /// Maximum parallel downloads
    #[arg(long, default_value_t = 16)]
    concurrency: usize,

    /// Cache directory [default: $LOCKWATCH_CACHE_DIR, else ~/.cache/lockwatch]
    #[arg(long)]
    cache_dir: Option<PathBuf>,

    /// Exit with code 1 if any finding is at or above this severity
    #[arg(long, value_enum, default_value_t = FailOn::High)]
    fail_on: FailOn,

    /// Use the cache only; never access the network
    #[arg(long)]
    offline: bool,

    /// npm registry base URL
    #[arg(long, default_value = DEFAULT_REGISTRY)]
    registry: String,

    /// Timeout for each HTTP request, in seconds
    #[arg(long, default_value_t = 60)]
    timeout: u64,

    /// Evaluate time-based rules as of this RFC 3339 time instead of now
    /// (for reproducible scans and tests)
    #[arg(long)]
    now: Option<String>,
}

fn default_cache_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("LOCKWATCH_CACHE_DIR") {
        return PathBuf::from(dir);
    }
    if let Some(dir) = std::env::var_os("XDG_CACHE_HOME") {
        return PathBuf::from(dir).join("lockwatch");
    }
    match std::env::var_os("HOME") {
        Some(home) => PathBuf::from(home).join(".cache").join("lockwatch"),
        None => PathBuf::from(".lockwatch-cache"),
    }
}

impl ScanArgs {
    fn to_options(&self) -> Result<ScanOptions> {
        let mut opts = ScanOptions::new(self.cache_dir.clone().unwrap_or_else(default_cache_dir));
        opts.concurrency = self.concurrency.max(1);
        opts.registry.offline = self.offline;
        opts.registry.registry = self.registry.clone();
        opts.registry.timeout = Duration::from_secs(self.timeout.max(1));
        if let Some(now) = &self.now {
            let parsed = parse_rfc3339(now)
                .with_context(|| format!("--now {now:?} is not an RFC 3339 timestamp"))?;
            opts.now = Some(parsed);
        }
        Ok(opts)
    }

    fn fail_threshold(&self) -> Option<Severity> {
        match self.fail_on {
            FailOn::Critical => Some(Severity::Critical),
            FailOn::High => Some(Severity::High),
            FailOn::Medium => Some(Severity::Medium),
            FailOn::Low => Some(Severity::Low),
            FailOn::None => None,
        }
    }
}

/// Print or save the report, then decide the exit code.
fn finish(report: &Report, args: &ScanArgs) -> Result<ExitCode> {
    let text = match args.format {
        Format::Json => {
            let mut json = serde_json::to_string_pretty(report)?;
            json.push('\n');
            json
        }
        Format::Table => report.to_table(),
    };
    match &args.out {
        Some(path) => std::fs::write(path, text)
            .with_context(|| format!("cannot write report to {}", path.display()))?,
        None => print!("{text}"),
    }
    let failing = args
        .fail_threshold()
        .is_some_and(|t| report.has_findings_at_or_above(t));
    Ok(if failing {
        ExitCode::from(1)
    } else if report.is_incomplete() {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    })
}

fn print_rules(format: Format) -> Result<()> {
    match format {
        Format::Json => {
            let rules: Vec<serde_json::Value> = RULES
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "id": r.id(),
                        "name": r.name(),
                        "severity": r.severity(),
                        "description": r.description(),
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&rules)?);
        }
        Format::Table => {
            for r in RULES.iter() {
                println!("{}  {:<8}  {}", r.id(), r.severity().as_str(), r.name());
                println!("       {}", r.description());
            }
        }
    }
    Ok(())
}

/// `#[tokio::main]` starts the async runtime and runs `main` on it.
#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    init_logging(cli.verbose);
    match run(cli).await {
        Ok(code) => code,
        Err(err) => {
            // `{:#}` prints the error and its chain of causes on one line.
            eprintln!("lockwatch: error: {err:#}");
            ExitCode::from(2)
        }
    }
}

async fn run(cli: Cli) -> Result<ExitCode> {
    match cli.command {
        Command::Scan { lockfile, opts } => {
            if !lockfile.is_file() {
                bail!("{} is not a file", lockfile.display());
            }
            let report = scan_lockfile(&lockfile, &opts.to_options()?)
                .await
                .with_context(|| format!("scanning {}", lockfile.display()))?;
            finish(&report, &opts)
        }
        Command::ScanPackage { spec, opts } => {
            let report = scan_package_spec(&spec, &opts.to_options()?)
                .await
                .with_context(|| format!("scanning {spec}"))?;
            finish(&report, &opts)
        }
        Command::ScanTarball {
            tarball,
            name,
            package_version,
            integrity,
            metadata,
            packument,
            opts,
        } => {
            let (bytes, label) = read_tarball(&tarball)?;
            let packument_json = match &packument {
                Some(path) => Some(
                    std::fs::read(path)
                        .with_context(|| format!("cannot read {}", path.display()))?,
                ),
                None => None,
            };
            let local = LocalTarball {
                name,
                version: package_version,
                integrity,
                fetch_metadata: metadata,
                packument_json,
                label,
            };
            let report = scan_tarball(bytes, local, &opts.to_options()?)
                .await
                .with_context(|| format!("scanning {}", tarball.display()))?;
            finish(&report, &opts)
        }
        Command::Rules { format } => {
            print_rules(format)?;
            Ok(ExitCode::SUCCESS)
        }
    }
}

/// Read a tarball from a file, or from stdin when the path is `-`, with the
/// same size limit as a registry download. Returns the bytes and a label for
/// the report.
fn read_tarball(path: &std::path::Path) -> Result<(Vec<u8>, String)> {
    use std::io::Read;
    let limit = MAX_LOCAL_TARBALL_BYTES;
    let mut bytes = Vec::new();
    let label = if path.as_os_str() == "-" {
        std::io::stdin()
            .lock()
            .take(limit + 1)
            .read_to_end(&mut bytes)
            .context("reading the tarball from stdin")?;
        "stdin".to_string()
    } else {
        std::fs::File::open(path)
            .with_context(|| format!("cannot open {}", path.display()))?
            .take(limit + 1)
            .read_to_end(&mut bytes)
            .with_context(|| format!("cannot read {}", path.display()))?;
        path.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string())
    };
    if bytes.len() as u64 > limit {
        bail!("tarball is larger than {limit} bytes");
    }
    Ok((bytes, label))
}

fn init_logging(verbose: u8) {
    use tracing_subscriber::EnvFilter;
    let default = match verbose {
        0 => "warn",
        1 => "info",
        _ => "debug",
    };
    // LOCKWATCH_LOG overrides the level, e.g. LOCKWATCH_LOG=lockwatch_core=debug
    let filter =
        EnvFilter::try_from_env("LOCKWATCH_LOG").unwrap_or_else(|_| EnvFilter::new(default));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}
