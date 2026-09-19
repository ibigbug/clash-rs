#![feature(cfg_version)]
#![cfg_attr(not(version("1.88.0")), feature(let_chains))]

#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

use human_panic::{Metadata, setup_panic};
#[cfg(all(feature = "jemallocator", not(feature = "dhat-heap")))]
use tikv_jemallocator::Jemalloc;

#[cfg(all(feature = "jemallocator", not(feature = "dhat-heap")))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

/// Tune jemalloc for low-memory environments (e.g. routers with 128MB RAM).
///
/// **On-demand activation**: only called when the user has opted into memory
/// limiting via `CLASH_RS_MEM_LIMIT_MB`.  Users who don't set the limit keep
/// jemalloc's defaults (10s decay) for maximum throughput.
///
/// Sets short decay times so freed pages are returned to the OS quickly,
/// instead of being cached indefinitely.  This trades a small amount of
/// CPU (more frequent madvise calls) for significantly lower RSS after
/// traffic bursts.
///
/// Override at runtime with `MALLOC_CONF=dirty_decay_ms:5000,...`.
#[cfg(all(feature = "jemallocator", not(feature = "dhat-heap")))]
fn tune_jemalloc() {
    // If MALLOC_CONF is explicitly provided by the user, honor it and avoid
    // overriding.
    if std::env::var("MALLOC_CONF").is_ok() {
        return;
    }

    // Only tune when the user has explicitly enabled memory limiting.
    // Otherwise keep jemalloc defaults (10s decay) for max throughput.
    let enabled = match std::env::var("CLASH_RS_MEM_LIMIT_MB") {
        Ok(val) => {
            let val = val.trim();
            let num_str = if let Some(rest) = val.strip_suffix(":hard") {
                rest
            } else if let Some(rest) = val.strip_suffix(":soft") {
                rest
            } else {
                val
            };
            match num_str.parse::<u64>() {
                Ok(mb) => mb > 0,
                Err(_) => false,
            }
        }
        Err(_) => false,
    };
    if !enabled {
        return;
    }

    // dirty_decay_ms: how long dirty pages are kept before being purged.
    // Shorter = faster RSS reclamation, slightly more CPU.
    //
    // tikv-jemalloc-ctl 0.7's `opt` module doesn't expose dirty_decay_ms /
    // muzzy_decay_ms (they are read-only startup options).  We use the raw
    // mallctl API to set per-arena decay values at runtime.
    //
    // IMPORTANT: raw::write requires null-terminated name strings (validated
    // by `validate_name` which asserts `*name.last() == b'\0'`).  We append
    // `\0` to every key.  The value type must match jemalloc's `ssize_t`:
    // on 64-bit it's i64, on 32-bit (e.g. armv7-musl) it's i32.  Using `isize`
    // matches the platform's native ssize_t size automatically.
    use tikv_jemalloc_ctl::raw;
    let decay_ms: isize = 1000;

    // Update decay for already-existing arenas.
    // (Setting `arenas.dirty_decay_ms` only affects FUTURE arenas created
    // after this call, and is read-only in some jemalloc builds — so we
    // iterate existing arenas directly.  New arenas are rare in a long-running
    // proxy, and they inherit a reasonable default.)
    let narenas = tikv_jemalloc_ctl::arenas::narenas::read().unwrap_or(0);
    for i in 0..narenas {
        // Use CString-style null-terminated bytes; format! + push('\0') avoids
        // allocating a CString and keeps the lifetime local to the call.
        let dirty_key = format!("arena.{}.dirty_decay_ms\0", i);
        let muzzy_key = format!("arena.{}.muzzy_decay_ms\0", i);
        unsafe {
            let _ = raw::write(dirty_key.as_bytes(), decay_ms);
            let _ = raw::write(muzzy_key.as_bytes(), decay_ms);
        }
    }
}

#[cfg(not(all(feature = "jemallocator", not(feature = "dhat-heap"))))]
fn tune_jemalloc() {}

extern crate clash_lib as clash;

use clap::Parser;
use clash::TokioRuntime;
use std::{
    io::Write,
    path::{Path, PathBuf},
    process::exit,
};

#[derive(Parser, Debug)]
#[clap(author, about, long_about = None)]
struct Cli {
    #[clap(short, long, value_parser, value_name = "DIRECTORY")]
    directory: Option<PathBuf>,

    #[clap(
        short,
        long,
        visible_short_aliases = ['f'], // -f is used by clash, it is a compatibility option
        value_parser,
        value_name = "FILE",
        default_value = "config.yaml",
        help = "Specify configuration file"
    )]
    config: PathBuf,
    #[clap(
        short = 't',
        long,
        value_parser,
        default_value = "false",
        help = "Test configuration and exit"
    )]
    test_config: bool,
    #[clap(
        short,
        long,
        visible_short_aliases = ['V'],
        value_parser,
        default_value = "false",
        help = "Print clash-rs version and exit"
    )]
    version: bool,
    #[clap(short, long, help = "Additionally log to file")]
    log_file: Option<String>,

    #[clap(
        long,
        value_parser,
        default_value = "false",
        help = "Enable crash report to help improve clash"
    )]
    help_improve: bool,

    #[clap(
        long,
        visible_aliases = ["ext-ctl-pipe", "ext-ctl-unix"],
        value_parser,
        value_name = "IPC_PATH",
        help = "Specify the IPC path for the controller"
    )]
    controller_ipc: Option<String>,

    #[clap(
        long,
        help = "Enable compatibility mode, which make behaviors more consistent \
                with mihomo but may cause some issues. It is recommended to enable \
                this if you are using clash verge."
    )]
    compatibility: bool,

    #[clap(
        long,
        help = "Reject configuration files that contain unrecognised fields. By \
                default clash-rs silently ignores unknown fields so that profiles \
                shared with other clients (e.g. clash-for-android) load without \
                errors."
    )]
    strict_config: bool,
}

/// Returns `true` if the env var is set to `1` or `true` (case-insensitive).
fn env_truthy(name: &str) -> bool {
    match std::env::var(name) {
        Ok(v) => matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true"),
        Err(_) => false,
    }
}

fn main() -> anyhow::Result<()> {
    #[cfg(feature = "dhat-heap")]
    let _profiler = dhat::Profiler::new_heap();

    // Tune jemalloc early so all subsequent allocations benefit from short
    // decay times (faster RSS reclamation on low-memory devices).
    tune_jemalloc();

    // Those arguments are for compatibility with `mihomo`
    // Technically, I do not think `mihomo` is a modern/standard POSIX Cli
    // program
    let args: Vec<String> = std::env::args()
        .map(|arg| match arg.as_str() {
            "-ext-ctl-unix" => "--ext-ctl-unix".to_string(),
            "-ext-ctl-pipe" => "--ext-ctl-pipe".to_string(),
            _ => arg,
        })
        .collect();
    let mut cli = Cli::parse_from(args);

    // Either `--compatibility` OR `CLASH_RS_COMPATIBILITY_MODE=1|true` enables
    // compatibility mode. The env var is useful when the command line is fixed
    // (containers, init systems, GUI launchers).
    cli.compatibility =
        cli.compatibility || env_truthy("CLASH_RS_COMPATIBILITY_MODE");

    if cli.version {
        println!(
            "{} {}",
            env!("CARGO_PKG_NAME"),
            env!("CLASH_VERSION_OVERRIDE") // Generated by build.rs
        );
        exit(0)
    }

    let file = cli
        .directory
        .as_ref()
        .unwrap_or(&std::env::current_dir().unwrap())
        .join(cli.config)
        .to_string_lossy()
        .to_string();

    if !Path::new(&file).exists() {
        let default_config = "port: 7890";
        let mut config_file = match std::fs::File::create(&file) {
            Ok(config_file) => config_file,
            _ => {
                eprintln!("default profile cannot be created: {file}");
                exit(1);
            }
        };

        if config_file.write_all(default_config.as_bytes()).is_err() {
            eprintln!("default profile cannot be written: {file}");
            exit(1);
        };

        println!(
            "the configuration file cannot be found, the template has been created \
             and used: {file}"
        );
    }

    let parse_config = || {
        let cfg = clash::Config::File(file.clone());
        if cli.strict_config {
            cfg.try_parse_strict()
        } else {
            cfg.try_parse()
        }
    };

    if cli.test_config {
        match parse_config() {
            Ok(_) => {
                println!("configuration file {file} test is successful");
                exit(0);
            }
            Err(e) => {
                eprintln!("configuration file {file} test failed: {e}");
                exit(1);
            }
        }
    }

    // NOTE: set this up before Sentry
    setup_panic!(
        Metadata::new(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))
            .authors(env!("CARGO_PKG_AUTHORS"))
            .homepage(env!("CARGO_PKG_HOMEPAGE"))
            .support(
                "Open an issue on GitHub: https://github.com/Watfaq/clash-rs/issues"
            )
    );

    let mut _guard = None;
    if cli.help_improve {
        _guard = Some(sentry::init((
            env!("SENTRY_DSN"),
            sentry::ClientOptions {
                release: sentry::release_name!(),
                ..Default::default()
            },
        )));
    }

    let mut config = parse_config()?;

    config.general.controller.external_controller_ipc = cli.controller_ipc;
    if cli.compatibility {
        println!(
            "Compatibility mode enabled. This may cause some issues, but it is \
             recommended to enable this if you are using clash verge."
        );
        if let Some(dir) = &cli.directory {
            // Canonicalize to an absolute path before changing the process cwd.
            // If `dir` is relative (e.g. `./clash-bin/tests/data/config`),
            // calling set_current_dir then passing the same relative string as
            // `cwd` to start_scaffold would cause paths like
            // `cwd.join("Country.mmdb")` to be resolved from the *new* process
            // cwd, doubling the directory segments and producing a path that
            // doesn't exist (os error 2).
            let abs = std::fs::canonicalize(dir)?;
            std::env::set_current_dir(&abs)?;
        }
        if config.general.mmdb.is_none() {
            config.general.mmdb = Some("Country.mmdb".to_string());
        }
        if config.general.geosite.is_none() {
            config.general.geosite = Some("geosite.dat".to_string());
        }
    }

    // When compatibility mode called set_current_dir the process cwd is
    // already correct; pass None so start_scaffold uses "." (= the new cwd)
    // rather than the original relative cli.directory which would be resolved
    // from the wrong base.
    let cwd = if cli.compatibility && cli.directory.is_some() {
        None
    } else {
        cli.directory.map(|x| x.to_string_lossy().to_string())
    };

    clash::start_scaffold(clash::Options {
        config: clash::Config::Internal(config),
        cwd,
        rt: Some(TokioRuntime::MultiThread),
        log_file: cli.log_file,
        config_path: Some(file),
    })
    .inspect_err(|err| eprintln!("Failed to start clash: {err}"))?;
    Ok(())
}

#[cfg(test)]
mod env_truthy_tests {
    use super::env_truthy;
    use std::sync::Mutex;

    const KEY: &str = "CLASH_RS_COMPATIBILITY_MODE_TEST";
    // Cargo runs tests in parallel — serialize env-var mutation within this
    // module so the three cases don't observe each other's writes.
    static GUARD: Mutex<()> = Mutex::new(());

    fn with<F: FnOnce()>(value: Option<&str>, f: F) {
        let _g = GUARD.lock().unwrap_or_else(|e| e.into_inner());
        match value {
            Some(v) => unsafe { std::env::set_var(KEY, v) },
            None => unsafe { std::env::remove_var(KEY) },
        }
        f();
        unsafe { std::env::remove_var(KEY) };
    }

    #[test]
    fn unset_is_false() {
        with(None, || assert!(!env_truthy(KEY)));
    }

    #[test]
    fn accepts_one_and_true_case_insensitive() {
        for v in ["1", "true", "TRUE", "True", " true ", "  1 "] {
            with(Some(v), || {
                assert!(env_truthy(KEY), "{v:?} should be truthy")
            });
        }
    }

    #[test]
    fn rejects_other_values() {
        for v in ["0", "false", "yes", "on", "", "2", "truthy"] {
            with(Some(v), || {
                assert!(!env_truthy(KEY), "{v:?} should be falsy")
            });
        }
    }
}
