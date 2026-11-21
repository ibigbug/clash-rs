fn main() -> anyhow::Result<()> {
    println!("cargo::rustc-check-cfg=cfg(docker_test)");
    println!("cargo:rerun-if-env-changed=CLASH_DOCKER_TEST");
    if let Some("1" | "true") = option_env!("CLASH_DOCKER_TEST") {
        println!("cargo::rustc-cfg=docker_test");
    }

    // Emit `--cfg qemu_emulated` for Linux targets that are neither x86_64
    // nor x86 (i686). Every such target in our CI is `cross`-built and runs
    // under qemu-user; QUIC and other timing-sensitive paths flake there.
    // Tests can then write `#[cfg_attr(qemu_emulated, ignore = "…")]`
    // instead of repeating the long target predicate.
    println!("cargo::rustc-check-cfg=cfg(qemu_emulated)");
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    // Android VpnService builds without TPROXY use the system's socket marks.
    // Only the privileged Android backend opts into setting SO_MARK itself.
    println!("cargo::rustc-check-cfg=cfg(socket_mark)");
    if target_os == "linux"
        || (target_os == "android"
            && std::env::var_os("CARGO_FEATURE_TPROXY").is_some())
    {
        println!("cargo::rustc-cfg=socket_mark");
    }
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    if target_os == "linux" && target_arch != "x86_64" && target_arch != "x86" {
        println!("cargo::rustc-cfg=qemu_emulated");
    }

    build_dashboard()?;

    println!("cargo:rerun-if-changed=src/common/geodata/geodata.proto");

    // Use protox (pure Rust) instead of system protobuf-compiler
    let file_descriptors = protox::compile(
        ["src/common/geodata/geodata.proto"],
        ["src/common/geodata"],
    )?;

    prost_build::compile_fds(file_descriptors)?;

    let vars = ["CLASH_GIT_REF", "CLASH_GIT_SHA", "GITHUB_REF", "GITHUB_SHA"];
    for var in vars {
        println!("cargo:rerun-if-env-changed={var}");
    }

    let git_ref = std::env::var_os("CLASH_GIT_REF")
        .or_else(|| std::env::var_os("GITHUB_REF"))
        .and_then(|v| v.into_string().ok());
    let git_sha = std::env::var_os("CLASH_GIT_SHA")
        .or_else(|| std::env::var_os("GITHUB_SHA"))
        .and_then(|v| v.into_string().ok());

    let version = if let Some(ref git_ref_val) = git_ref
        && git_ref_val == "refs/heads/master"
        && let Some(ref sha) = git_sha
    {
        let short_sha = &sha[..7.min(sha.len())];
        // Nightly release below
        format!("{}-alpha+sha.{short_sha}", env!("CARGO_PKG_VERSION"))
    } else {
        env!("CARGO_PKG_VERSION").into()
    };
    println!("cargo:rustc-env=CLASH_VERSION_OVERRIDE={version}");

    Ok(())
}

fn build_dashboard() -> anyhow::Result<()> {
    // Only run when the `dashboard` feature is enabled.
    if std::env::var("CARGO_FEATURE_DASHBOARD").is_err() {
        return Ok(());
    }

    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")?;
    let dashboard_dir =
        std::path::PathBuf::from(&manifest_dir).join("../clash-dashboard");

    let dashboard_dir = dashboard_dir.canonicalize().map_err(|e| {
        anyhow::anyhow!(
            "clash-dashboard directory not found at {}: {e}",
            dashboard_dir.display()
        )
    })?;

    // Watch source files so cargo reruns this script on any frontend change.
    let src_dir = dashboard_dir.join("src");
    emit_rerun_if_changed(&src_dir);
    for file in [
        "index.html",
        "vite.config.ts",
        "package.json",
        "package-lock.json",
        "tsconfig.json",
        "tsconfig.app.json",
    ] {
        println!(
            "cargo:rerun-if-changed={}",
            dashboard_dir.join(file).display()
        );
    }

    // On Windows npm is a .cmd script, not a binary.
    let npm = if cfg!(windows) { "npm.cmd" } else { "npm" };

    // Use /tmp for the npm cache so that non-root users inside cross containers
    // (which run as UID 1001) are not blocked by a root-owned /.npm directory
    // that the nodesource pre-build step may have created.
    let npm_cache = std::env::temp_dir().join("npm-cache");

    // Run `npm ci` to install dependencies (no-op if already up to date).
    let status = match std::process::Command::new(npm)
        .args(["ci", "--prefer-offline", "--cache"])
        .arg(&npm_cache)
        .current_dir(&dashboard_dir)
        .status()
    {
        Ok(s) => s,
        Err(e) => {
            anyhow::bail!("npm not found; is Node.js installed? ({e})");
        }
    };

    anyhow::ensure!(status.success(), "`npm ci` failed with status {status}");

    // Run `npm run build`.
    let status = std::process::Command::new(npm)
        .args(["run", "build"])
        .env("npm_config_cache", &npm_cache)
        .current_dir(&dashboard_dir)
        .status()
        .map_err(|e| {
            anyhow::anyhow!(
                "Failed to run `npm run build` (is Node.js/npm installed?): {e}"
            )
        })?;

    anyhow::ensure!(
        status.success(),
        "`npm run build` exited with status {status}"
    );

    Ok(())
}

/// Recursively emits `cargo:rerun-if-changed` for every file under `dir`.
fn emit_rerun_if_changed(dir: &std::path::Path) {
    if !dir.exists() {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            emit_rerun_if_changed(&path);
        } else {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
}
