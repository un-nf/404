use std::env;
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
        println!(
            "cargo:warning=Skipping STATIC JS bundle build because node/npm is unavailable; the last generated runtime bundle will continue to be used."
        );
        if !bundle_path.exists() {
            println!(
                "cargo:warning=No generated runtime bundle exists yet at assets/js/dist/runtime.bundle.js."
            );
        }
        return;
    };

    let Some(npm_command) = npm_command else {
        println!(
            "cargo:warning=Skipping STATIC JS bundle build because node/npm is unavailable; the last generated runtime bundle will continue to be used."
        );
        if !bundle_path.exists() {
            println!(
                "cargo:warning=No generated runtime bundle exists yet at assets/js/dist/runtime.bundle.js."
            );
        }
        return;
    };

    let esbuild_installed = Path::new("build/node_modules/esbuild").exists();
    if !esbuild_installed {
        let status = Command::new(&npm_command)
            .args(["install", "--prefix", "build"])
            .status();

        match status {
            Ok(result) if result.success() => {}
            Ok(result) => {
                println!(
                    "cargo:warning=STATIC JS npm install exited with status {}. The last generated runtime bundle will continue to be used.",
                    result
                );
                return;
            }
            Err(error) => {
                println!(
                    "cargo:warning=STATIC JS npm install failed: {}. The last generated runtime bundle will continue to be used.",
                    error
                );
                return;
            }
        }
    }

    let status = Command::new(&node_command)
        .args(["build/build.js"])
        .status();
    match status {
        Ok(result) if result.success() => {}
        Ok(result) => {
            println!(
                "cargo:warning=STATIC JS bundle build exited with status {}. The last generated runtime bundle will continue to be used.",
                result
            );
        }
        Err(error) => {
            println!(
                "cargo:warning=STATIC JS bundle build failed: {}. The last generated runtime bundle will continue to be used.",
                error
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
            if command_works(candidate.as_os_str()) {
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