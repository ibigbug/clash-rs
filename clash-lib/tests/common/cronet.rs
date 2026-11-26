use std::path::Path;

use anyhow::{Result, anyhow, ensure};

pub(crate) fn library_path() -> Result<Option<String>> {
    let Some(path) = std::env::var_os("CLASH_NAIVE_CRONET_LIB") else {
        return Ok(None);
    };
    ensure!(
        Path::new(&path).is_absolute(),
        "CLASH_NAIVE_CRONET_LIB must be an absolute path"
    );
    Ok(Some(path.into_string().map_err(|_| {
        anyhow!("CLASH_NAIVE_CRONET_LIB is not valid UTF-8")
    })?))
}
