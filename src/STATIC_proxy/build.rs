use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=assets/js/src");
    println!("cargo:rerun-if-changed=build/build.js");
    println!("cargo:rerun-if-changed=build/package.json");
    println!("cargo:rerun-if-changed=build/package-lock.json");

    let node_command = resolve_command(&["node", "node.exe"]);
    let npm_command = resolve_command(&["npm", "npm.cmd"]);
    let bundle_path = Path::new("assets/js/dist/runtime.bundle.js");

    let Some(node_command) = node_command else {
        panic!(
            "STATIC JS bundle build requires node to be available; refusing to compile without a freshly generated runtime bundle"
        );
    };

    let Some(npm_command) = npm_command else {
        panic!(
            "STATIC JS bundle build requires npm to be available; refusing to compile without a freshly generated runtime bundle"
        );
    };

    let esbuild_installed = Path::new("build/node_modules/esbuild").exists();
    if !esbuild_installed {
        let status = Command::new(&npm_command)
            .args(["install", "--prefix", "build"])
            .status();

        match status {
            Ok(result) if result.success() => {}
            Ok(result) => {
                panic!(
                    "STATIC JS npm install exited with status {}; refusing to compile with a stale runtime bundle",
                    result
                );
            }
            Err(error) => {
                panic!(
                    "STATIC JS npm install failed: {error}; refusing to compile with a stale runtime bundle"
                );
            }
        }
    }

    let status = Command::new(&node_command)
        .args(["build/build.js"])
        .status();
    match status {
        Ok(result) if result.success() => {
            if !bundle_path.exists() {
                panic!(
                    "STATIC JS bundle build succeeded but {} was not produced",
                    bundle_path.display()
                );
            }
        }
        Ok(result) => {
            panic!(
                "STATIC JS bundle build exited with status {}; refusing to compile with a stale runtime bundle",
                result
            );
        }
        Err(error) => {
            panic!(
                "STATIC JS bundle build failed: {error}; refusing to compile with a stale runtime bundle"
            );
        }
    }
}

fn resolve_command(candidates: &[&str]) -> Option<String> {
    for candidate in candidates {
        if command_works(candidate) {
            return Some((*candidate).to_string());
        }
    }

    #[cfg(windows)]
    {
        for candidate in windows_fallback_candidates(candidates) {
            if command_works(&candidate) {
                return Some(candidate.to_string_lossy().into_owned());
            }
        }
    }

    None
}

fn command_works<S>(command: S) -> bool
where
    S: AsRef<std::ffi::OsStr>,
{
    Command::new(command)
        .arg("--version")
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

#[cfg(windows)]
fn windows_fallback_candidates(candidates: &[&str]) -> Vec<PathBuf> {
    use std::env;

    let mut paths = Vec::new();
    let mut bases = Vec::new();

    if let Some(program_files) = env::var_os("ProgramFiles") {
        bases.push(PathBuf::from(program_files));
    }
    if let Some(program_files_x86) = env::var_os("ProgramFiles(x86)") {
        bases.push(PathBuf::from(program_files_x86));
    }
    if let Some(local_app_data) = env::var_os("LocalAppData") {
        bases.push(PathBuf::from(local_app_data));
    }

    for base in bases {
        for candidate in candidates {
            let file_name = candidate.trim_end_matches(".exe").trim_end_matches(".cmd");
            if file_name == "node" {
                paths.push(base.join("nodejs").join("node.exe"));
            }
            if file_name == "npm" {
                paths.push(base.join("nodejs").join("npm.cmd"));
            }
        }
    }

    paths
}