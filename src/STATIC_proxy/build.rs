use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=assets/js/src");
    println!("cargo:rerun-if-changed=build/build.js");
    println!("cargo:rerun-if-changed=build/package.json");
    println!("cargo:rerun-if-changed=build/package-lock.json");

    let node_command = resolve_command(&["node", "node.exe"]);
    let npm_command = resolve_command(&["npm", "npm.cmd"]);
    let out_dir = std::env::var("OUT_DIR").expect("cargo must set OUT_DIR for build scripts");
    let bundle_path = PathBuf::from(out_dir).join("runtime.bundle.js");
    let node_modules_path = Path::new("build/node_modules");
    let esbuild_package_path = node_modules_path.join("esbuild");

    ensure_bundle_output_writable(&bundle_path);

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

    let esbuild_installed = esbuild_package_path.exists();
    if !esbuild_installed {
        if node_modules_path.exists() {
            std::fs::remove_dir_all(node_modules_path).unwrap_or_else(|error| {
                panic!(
                    "STATIC JS dependency install found a partial build/node_modules tree but could not remove it: {error}"
                )
            });
        }

        let mut install = Command::new(&npm_command);
        install.args(["ci", "--prefix", "build"]);

        #[cfg(windows)]
        {
            install.arg("--no-bin-links");
            install.env("npm_config_bin_links", "false");
        }

        let status = install.status();

        match status {
            Ok(result) if result.success() => {
                if !esbuild_package_path.exists() {
                    panic!(
                        "STATIC JS npm install succeeded but build/node_modules/esbuild was not produced"
                    );
                }
            }
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
        .env("STATIC_BUNDLE_OUTFILE", &bundle_path)
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

fn ensure_bundle_output_writable(bundle_path: &Path) {
    if let Some(parent) = bundle_path.parent() {
        std::fs::create_dir_all(parent).unwrap_or_else(|error| {
            panic!(
                "STATIC JS bundle build requires a writable output directory at {}: {error}",
                parent.display()
            )
        });
        make_writable(parent);
    }

    if bundle_path.exists() {
        std::fs::remove_file(bundle_path).unwrap_or_else(|error| {
            panic!(
                "failed to remove stale JS bundle {} before rebuild: {error}",
                bundle_path.display()
            )
        });
    }
}

fn make_writable(path: &Path) {
    let metadata = std::fs::metadata(path).unwrap_or_else(|error| {
        panic!("failed to inspect {} before JS bundle build: {error}", path.display())
    });
    let mut permissions = metadata.permissions();

    if permissions.readonly() {
        permissions.set_readonly(false);
        std::fs::set_permissions(path, permissions).unwrap_or_else(|error| {
            panic!(
                "failed to make {} writable before JS bundle build: {error}",
                path.display()
            )
        });
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