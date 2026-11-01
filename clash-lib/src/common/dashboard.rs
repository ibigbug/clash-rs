use std::{
    fs,
    io::Cursor,
    path::{Component, Path, PathBuf},
};

use tracing::{info, warn};

use crate::{
    Error,
    common::{http::HttpClient, utils::download},
};

/// Downloads and extracts a dashboard archive (zip or tgz) to `dir`.
///
/// The download is skipped when `dir` already exists and is non-empty,
/// unless the URL fragment contains the parameter `force=true`
/// (e.g. `https://example.com/dist.tgz#force=true`).
///
/// To route the download through a configured proxy outbound, append
/// `#_clash_outbound=<name>` to the URL.
pub async fn download_dashboard<P: AsRef<Path>>(
    dir: P,
    download_url: &str,
    http_client: &HttpClient,
) -> Result<(), Error> {
    let dir = dir.as_ref();

    // Parse the URL fragment to extract parameters (same convention as
    // `common::utils::download` uses for `_clash_outbound`).
    let fragment = download_url
        .rsplit_once('#')
        .map(|x| x.1)
        .unwrap_or_default();
    let force = fragment.split('&').any(|kv| kv == "force=true");

    let needs_download = force
        || !dir.exists()
        || dir.read_dir().map_or(true, |mut d| d.next().is_none());

    if !needs_download {
        return Ok(());
    }

    info!("downloading dashboard from {}", download_url);

    let rand_part: u64 = rand::random::<u64>();
    let base_dir = dir.parent().unwrap_or(Path::new("."));

    // Ensure the directory that will hold the temp files exists.
    fs::create_dir_all(base_dir)?;

    let tmp_path = base_dir.join(format!("_dashboard_tmp_{rand_part:016x}"));

    // Clean up the temp file on any failure to avoid leaving stale files.
    if let Err(e) = download(download_url, &tmp_path, http_client).await {
        let _ = fs::remove_file(&tmp_path);
        return Err(Error::InvalidConfig(format!(
            "dashboard download failed: {e}"
        )));
    }

    let bytes = match fs::read(&tmp_path) {
        Ok(b) => b,
        Err(e) => {
            let _ = fs::remove_file(&tmp_path);
            return Err(e.into());
        }
    };
    if let Err(e) = fs::remove_file(&tmp_path) {
        warn!(
            "failed to remove dashboard temp file {}: {}",
            tmp_path.display(),
            e
        );
    }

    // Extract into a temporary directory first so the existing working
    // dashboard is not removed until we know extraction succeeded.
    let rand_part2: u64 = rand::random::<u64>();
    let extract_tmp = base_dir.join(format!("_dashboard_extract_{rand_part2:016x}"));
    fs::create_dir_all(&extract_tmp)?;

    // Strip URL fragment before checking the extension (e.g. url#force=true)
    let url_base = download_url.split('#').next().unwrap_or(download_url);
    let extract_result = if url_base.ends_with(".zip") || is_zip(&bytes) {
        extract_zip(&bytes, &extract_tmp)
    } else {
        extract_tgz(&bytes, &extract_tmp)
    };

    if let Err(e) = extract_result {
        let _ = fs::remove_dir_all(&extract_tmp);
        return Err(e);
    }

    // Safely replace the target directory using a backup-and-swap strategy
    // so the existing dashboard is preserved if the rename fails.
    let backup = if dir.exists() {
        let rand_part3: u64 = rand::random::<u64>();
        let backup_dir =
            base_dir.join(format!("_dashboard_backup_{rand_part3:016x}"));
        fs::rename(dir, &backup_dir)?;
        Some(backup_dir)
    } else {
        None
    };

    if let Err(e) = fs::rename(&extract_tmp, dir) {
        // Rollback: restore the previous dashboard from backup.
        if let Some(ref backup_dir) = backup
            && let Err(restore_err) = fs::rename(backup_dir, dir)
        {
            warn!(
                "failed to restore dashboard from backup {}: {}",
                backup_dir.display(),
                restore_err
            );
        }
        let _ = fs::remove_dir_all(&extract_tmp);
        return Err(e.into());
    }

    // New dashboard is in place; remove the backup.
    if let Some(backup_dir) = backup
        && let Err(e) = fs::remove_dir_all(&backup_dir)
    {
        warn!(
            "failed to remove dashboard backup {}: {}",
            backup_dir.display(),
            e
        );
    }

    info!("dashboard extracted to {}", dir.display());
    Ok(())
}

fn is_zip(bytes: &[u8]) -> bool {
    bytes.starts_with(&[0x50, 0x4B, 0x03, 0x04])
}

/// Creates parent directory of `path` if it doesn't already exist.
fn ensure_parent(path: &Path) -> Result<(), Error> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn extract_zip(bytes: &[u8], target_dir: &Path) -> Result<(), Error> {
    let cursor = Cursor::new(bytes);
    let mut archive = zip::ZipArchive::new(cursor)
        .map_err(|e| Error::InvalidConfig(format!("zip open failed: {e}")))?;

    // Detect a common single top-level directory to strip (e.g. "dist/").
    // Use a full path-segment match (require trailing "/") to avoid treating
    // "dist2/..." as sharing the "dist" prefix.
    let strip_prefix: Option<String> = {
        let first = archive.by_index(0).ok().and_then(|f| {
            f.name()
                .ok()
                .map(|n| n.split('/').next().unwrap_or("").to_string())
        });
        match first {
            Some(ref prefix) if !prefix.is_empty() => {
                let candidate = format!("{prefix}/");
                let all_share = (0..archive.len()).all(|i| {
                    archive
                        .by_index(i)
                        .ok()
                        .and_then(|f| {
                            f.name().ok().map(|n| n.starts_with(candidate.as_str()))
                        })
                        .unwrap_or(false)
                });
                if all_share { Some(candidate) } else { None }
            }
            _ => None,
        }
    };

    for i in 0..archive.len() {
        let mut file = archive
            .by_index(i)
            .map_err(|e| Error::InvalidConfig(format!("zip entry failed: {e}")))?;
        let name = file
            .name()
            .map_err(|e| {
                Error::InvalidConfig(format!("zip entry name failed: {e}"))
            })?
            .into_owned();

        // `enclosed_name` returns None for paths with ".." or absolute paths,
        // which is our primary path-traversal guard for zip entries.
        let enclosed = match file.enclosed_name() {
            Some(p) => p,
            None => {
                warn!("skipping potentially dangerous zip entry: {}", name);
                continue;
            }
        };

        // Strip the common prefix if present.
        // Use the raw zip entry name (always '/' separated,
        // platform-independent) rather than the PathBuf representation
        // (which uses OS separators on Windows) so that prefix matching
        // works correctly cross-platform.
        let rel: PathBuf = match strip_prefix {
            Some(ref prefix) => {
                let stripped =
                    name.strip_prefix(prefix.as_str()).unwrap_or(name.as_str());
                // Re-build a PathBuf from the '/' separated components so the
                // result uses native separators on all platforms.
                stripped.split('/').filter(|c| !c.is_empty()).collect()
            }
            None => enclosed.clone(),
        };
        if rel.as_os_str().is_empty() {
            continue;
        }

        let dest = target_dir.join(&rel);
        let is_dir = name.ends_with('/');
        if is_dir {
            fs::create_dir_all(&dest)?;
        } else {
            ensure_parent(&dest)?;
            let mut out = fs::File::create(&dest)?;
            std::io::copy(&mut file, &mut out)?;
        }
    }
    Ok(())
}

fn extract_tgz(bytes: &[u8], target_dir: &Path) -> Result<(), Error> {
    use flate2::read::GzDecoder;
    use tar::Archive;

    // First pass: collect all entry paths to detect a common top-level
    // directory, matching the same logic used in extract_zip.
    let strip_prefix: Option<String> = {
        let gz = GzDecoder::new(Cursor::new(bytes));
        let mut archive = Archive::new(gz);

        let mut first: Option<String> = None;
        let mut all_share = true;

        for entry in archive
            .entries()
            .map_err(|e| Error::InvalidConfig(format!("tgz open failed: {e}")))?
        {
            let entry = entry.map_err(|e| {
                Error::InvalidConfig(format!("tgz entry failed: {e}"))
            })?;
            let path = entry
                .path()
                .map_err(|e| Error::InvalidConfig(format!("tgz entry path: {e}")))?;

            // Skip dangerous entries so they don't influence prefix detection.
            if path.components().any(|c| {
                matches!(
                    c,
                    Component::ParentDir | Component::RootDir | Component::Prefix(_)
                )
            }) {
                continue;
            }

            let mut comps = path.components();
            let top = comps.next();
            // If the entry has only one component (a file directly at archive
            // root with no subdirectory), there is no common top-level
            // directory to strip.
            if comps.next().is_none() {
                all_share = false;
                break;
            }

            let top_str = top.map(|c| c.as_os_str().to_string_lossy().into_owned());

            match (&first, top_str) {
                (None, Some(t)) => first = Some(t),
                (Some(f), Some(t)) if f != &t => {
                    all_share = false;
                    break;
                }
                _ => {}
            }
        }

        if all_share {
            first.map(|p| format!("{p}/"))
        } else {
            None
        }
    };

    // Second pass: extract entries using the detected prefix.
    let gz = GzDecoder::new(Cursor::new(bytes));
    let mut archive = Archive::new(gz);

    for entry in archive
        .entries()
        .map_err(|e| Error::InvalidConfig(format!("tgz open failed: {e}")))?
    {
        let mut entry = entry
            .map_err(|e| Error::InvalidConfig(format!("tgz entry failed: {e}")))?;
        let path = entry
            .path()
            .map_err(|e| Error::InvalidConfig(format!("tgz entry path: {e}")))?
            .to_path_buf();

        // Validate the *original* path before any stripping to prevent
        // traversal attacks (e.g. an archive with `../evil` as first
        // component).
        if path.components().any(|c| {
            matches!(
                c,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        }) {
            warn!(
                "skipping potentially dangerous tgz entry: {}",
                path.display()
            );
            continue;
        }

        let rel: PathBuf = match &strip_prefix {
            Some(prefix) => {
                // Use Path::strip_prefix to remove the common top-level dir by
                // path component (e.g. "dist/index.html" → "index.html")
                // without going through a string
                // representation.
                let prefix_path = Path::new(prefix.trim_end_matches('/'));
                path.strip_prefix(prefix_path)
                    .unwrap_or(&path)
                    .to_path_buf()
            }
            None => path.clone(),
        };

        if rel.as_os_str().is_empty() {
            continue;
        }

        let dest = target_dir.join(&rel);
        if entry.header().entry_type().is_dir() {
            fs::create_dir_all(&dest)?;
        } else {
            ensure_parent(&dest)?;
            let mut out = fs::File::create(&dest)?;
            std::io::copy(&mut entry, &mut out)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    // ── helpers ──────────────────────────────────────────────────────────────

    /// Build an in-memory zip archive from a list of (path, content) pairs.
    fn make_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let buf = Cursor::new(Vec::new());
        let mut w = zip::ZipWriter::new(buf);
        let opts = zip::write::SimpleFileOptions::default();
        for (name, data) in entries {
            w.start_file(*name, opts).unwrap();
            w.write_all(data).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    /// Build an in-memory .tgz archive from a list of (path, content) pairs.
    /// Uses `tar::Builder::append_data` which validates paths — safe for
    /// constructing well-formed test archives.
    fn make_tgz(entries: &[(&str, &[u8])]) -> Vec<u8> {
        use flate2::{Compression, write::GzEncoder};

        let buf = Vec::new();
        let gz = GzEncoder::new(buf, Compression::default());
        let mut ar = tar::Builder::new(gz);
        for (name, data) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            ar.append_data(&mut header, name, *data).unwrap();
        }
        ar.into_inner().unwrap().finish().unwrap()
    }

    /// Build a .tgz archive while bypassing `tar`'s own path validation by
    /// writing raw path bytes directly into the header.  Use this only for
    /// testing that *our* code rejects dangerous entries — the normal builder
    /// would reject such paths itself.
    fn make_tgz_unchecked(entries: &[(&str, &[u8])]) -> Vec<u8> {
        use flate2::{Compression, write::GzEncoder};

        let buf = Vec::new();
        let gz = GzEncoder::new(buf, Compression::default());
        let mut ar = tar::Builder::new(gz);
        for (name, data) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            // Write the raw path bytes into header bytes[0..100], bypassing
            // set_path()'s validation.
            {
                let raw = header.as_mut_bytes();
                let nb = name.as_bytes();
                let copy_len = nb.len().min(99);
                raw[..copy_len].copy_from_slice(&nb[..copy_len]);
                raw[copy_len] = 0; // null-terminate
            }
            header.set_cksum();
            // append() writes the header as-is (no path validation).
            ar.append(&header, *data).unwrap();
        }
        ar.into_inner().unwrap().finish().unwrap()
    }

    // ── zip tests ────────────────────────────────────────────────────────────

    #[test]
    fn zip_strips_common_top_level_dir() {
        let bytes =
            make_zip(&[("dist/index.html", b"hello"), ("dist/app.js", b"js")]);
        let tmp = tempfile::tempdir().unwrap();
        extract_zip(&bytes, tmp.path()).unwrap();
        assert!(tmp.path().join("index.html").exists());
        assert!(tmp.path().join("app.js").exists());
        assert!(!tmp.path().join("dist").exists());
    }

    #[test]
    fn zip_no_common_dir_keeps_paths() {
        let bytes = make_zip(&[("index.html", b"hello"), ("app.js", b"js")]);
        let tmp = tempfile::tempdir().unwrap();
        extract_zip(&bytes, tmp.path()).unwrap();
        assert!(tmp.path().join("index.html").exists());
        assert!(tmp.path().join("app.js").exists());
    }

    #[test]
    fn zip_no_false_prefix_match() {
        // "dist" and "dist2" share a textual prefix but not a path-segment
        // prefix.
        let bytes = make_zip(&[("dist/a.html", b"a"), ("dist2/b.html", b"b")]);
        let tmp = tempfile::tempdir().unwrap();
        extract_zip(&bytes, tmp.path()).unwrap();
        // No stripping should happen; both top-level dirs must be present.
        assert!(tmp.path().join("dist/a.html").exists());
        assert!(tmp.path().join("dist2/b.html").exists());
    }

    #[test]
    fn zip_rejects_traversal_paths() {
        // zip::ZipArchive::enclosed_name() filters these out; verify nothing
        // is written outside target_dir.
        let bytes = make_zip(&[("../evil.txt", b"bad"), ("ok.txt", b"good")]);
        let tmp = tempfile::tempdir().unwrap();
        extract_zip(&bytes, tmp.path()).unwrap();
        assert!(!tmp.path().join("../evil.txt").exists());
        // The harmless file may or may not be extracted depending on the prefix
        // logic, but the traversal entry must never escape the target dir.
        let parent = tmp.path().parent().unwrap();
        assert!(!parent.join("evil.txt").exists());
    }

    // ── tgz tests ────────────────────────────────────────────────────────────

    #[test]
    fn tgz_strips_common_top_level_dir() {
        let bytes =
            make_tgz(&[("dist/index.html", b"hello"), ("dist/app.js", b"js")]);
        let tmp = tempfile::tempdir().unwrap();
        extract_tgz(&bytes, tmp.path()).unwrap();
        assert!(tmp.path().join("index.html").exists());
        assert!(tmp.path().join("app.js").exists());
        assert!(!tmp.path().join("dist").exists());
    }

    #[test]
    fn tgz_no_common_dir_keeps_paths() {
        let bytes = make_tgz(&[("index.html", b"hello"), ("app.js", b"js")]);
        let tmp = tempfile::tempdir().unwrap();
        extract_tgz(&bytes, tmp.path()).unwrap();
        assert!(tmp.path().join("index.html").exists());
        assert!(tmp.path().join("app.js").exists());
    }

    #[test]
    fn tgz_no_false_prefix_match() {
        let bytes = make_tgz(&[("dist/a.html", b"a"), ("dist2/b.html", b"b")]);
        let tmp = tempfile::tempdir().unwrap();
        extract_tgz(&bytes, tmp.path()).unwrap();
        assert!(tmp.path().join("dist/a.html").exists());
        assert!(tmp.path().join("dist2/b.html").exists());
    }

    #[test]
    fn tgz_rejects_traversal_paths() {
        // Build an archive that contains a traversal path using raw header
        // bytes (the safe tar builder would reject this itself).
        let bytes =
            make_tgz_unchecked(&[("../evil.txt", b"bad"), ("ok.txt", b"good")]);
        let tmp = tempfile::tempdir().unwrap();
        extract_tgz(&bytes, tmp.path()).unwrap();
        let parent = tmp.path().parent().unwrap();
        assert!(!parent.join("evil.txt").exists());
        // "ok.txt" is a harmless single-component path; it should be extracted.
        assert!(tmp.path().join("ok.txt").exists());
    }

    #[test]
    fn tgz_rejects_absolute_paths() {
        // Use a distinctive name that is guaranteed not to pre-exist so the
        // assertion is unambiguous and portable (avoids reading /etc/passwd).
        let abs_name = "/clash_rs_must_not_exist_absolute_4d9e2a1b";
        let bytes = make_tgz_unchecked(&[(abs_name, b"bad"), ("ok.txt", b"good")]);
        let tmp = tempfile::tempdir().unwrap();
        extract_tgz(&bytes, tmp.path()).unwrap();
        assert!(!Path::new(abs_name).exists());
        assert!(tmp.path().join("ok.txt").exists());
    }
}
