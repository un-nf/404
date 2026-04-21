/* STATIC Proxy (AGPL-3.0)

Copyright (C) 2025 - 404 Contributors

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

*/

use std::{env, io::{self, Write}, path::{Path, PathBuf}};

use anyhow::{Context, Result};
use clap::{ArgAction, Parser, ValueEnum};
use static_proxy::{
    app::{RunMode, StaticApp},
    config::StaticConfig,
    proxy::stages::ProfileStore,
    utils::init_tracing,
};

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CliMode {
    Proxy,
    Control,
}

impl From<CliMode> for RunMode {
    fn from(value: CliMode) -> Self {
        match value {
            CliMode::Proxy => RunMode::Proxy,
            CliMode::Control => RunMode::ControlOnly,
        }
    }
}

/// Command-line interface definition using clap's derive API.
#[derive(Debug, Parser)]
#[command(
    name = "static",
    about = "STATIC: Synthetic Traffic and TLS Identity Camouflage"
)]
struct Cli {
    /// Path to the STATIC configuration file (TOML format).
    /// If omitted, STATIC will use config/static.example.toml when present, otherwise built-in defaults.
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Path to the profile directory or single profile JSON.
    /// If omitted and no config file is used, STATIC will look for a profiles directory beside the binary.
    #[arg(long)]
    profiles_path: Option<PathBuf>,

    /// Profile key or display name to run.
    /// Proxy mode refuses to start unless a profile is selected here or in the config file.
    #[arg(long)]
    profile: Option<String>,

    /// Print the discovered profile catalog and exit.
    #[arg(long, action = ArgAction::SetTrue)]
    list_profiles: bool,

    /// Override the listener bind address.
    #[arg(long)]
    bind_address: Option<String>,

    /// Override the listener bind port.
    #[arg(long)]
    bind_port: Option<u16>,

    /// Enable JSON-formatted logs (default: human-readable stdout).
    #[arg(long, default_value_t = false)]
    json_logs: bool,

    /// Runtime mode: full proxy runtime or localhost control-only sidecar.
    #[arg(long, value_enum, default_value_t = CliMode::Proxy)]
    mode: CliMode,
}

/// Application entry point: parse CLI, initialize logging, load config, run server.
///
/// This creates a multi-threaded tokio runtime (default: one thread per CPU core)
/// and runs the async main function on it.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let result = run().await;

    if let Err(error) = &result {
        eprintln!("STATIC failed: {error:#}");
        maybe_pause_before_exit();
    }

    result
}

async fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();

    init_tracing(cli.json_logs);

    let config = load_effective_config(&cli)?;

    if cli.list_profiles {
        let store = ProfileStore::load(
            config.pipeline.profiles_path.clone(),
            config.pipeline.default_profile.clone(),
        )?;
        print_profile_catalog(&store);
        return Ok(());
    }

    let app = StaticApp::new(config, cli.mode.into()).await?;

    app.run().await
}

fn maybe_pause_before_exit() {
    #[cfg(windows)]
    {
        if launched_in_standalone_console() {
            let _ = writeln!(io::stderr(), "\nPress Enter to close this window...");
            let _ = io::stderr().flush();
            let mut line = String::new();
            let _ = io::stdin().read_line(&mut line);
        }
    }
}

#[cfg(windows)]
fn launched_in_standalone_console() -> bool {
    use windows_sys::Win32::System::Console::GetConsoleProcessList;

    let mut processes = [0u32; 8];
    let count = unsafe { GetConsoleProcessList(processes.as_mut_ptr(), processes.len() as u32) };
    count > 0 && count <= 2
}

fn load_effective_config(cli: &Cli) -> Result<StaticConfig> {
    let config_path = resolve_config_path(cli);
    let mut config = if let Some(path) = config_path.as_ref() {
        StaticConfig::load(path)?
    } else {
        StaticConfig::default_for_cli(default_profiles_path()?)
    };

    if let Some(profiles_path) = cli.profiles_path.clone() {
        config.pipeline.profiles_path = absolutize_runtime_path(profiles_path)?;
    }

    if let Some(profile) = cli.profile.as_deref().map(str::trim).filter(|value| !value.is_empty()) {
        config.pipeline.default_profile = Some(profile.to_string());
    }

    if let Some(bind_address) = cli.bind_address.clone() {
        config.listener.bind_address = bind_address;
    }

    if let Some(bind_port) = cli.bind_port {
        config.listener.bind_port = bind_port;
        if !config.http3.enabled {
            config.http3.bind_port = bind_port.saturating_add(1);
        }
    }

    Ok(config)
}

fn resolve_config_path(cli: &Cli) -> Option<PathBuf> {
    cli.config.clone().or_else(|| {
        let default_path = PathBuf::from("config/static.example.toml");
        default_path.exists().then_some(default_path)
    })
}

fn default_profiles_path() -> Result<PathBuf> {
    let exe_path = env::current_exe().context("failed to resolve STATIC executable path")?;
    let exe_dir = exe_path.parent().unwrap_or_else(|| Path::new("."));
    Ok(exe_dir.join("profiles"))
}

fn absolutize_runtime_path(path: PathBuf) -> Result<PathBuf> {
    if path.is_absolute() {
        return Ok(path);
    }

    Ok(env::current_dir()
        .context("failed to resolve current working directory")?
        .join(path))
}

fn print_profile_catalog(store: &ProfileStore) {
    match store.active_profile() {
        Some(active) => println!(
            "Active profile: {} ({}, {}, {})",
            active.key, active.display_name, active.family, active.variant
        ),
        None => println!("Active profile: none"),
    }

    let catalog = store.catalog();
    if catalog.is_empty() {
        println!("No profiles were found in the configured profiles path.");
        return;
    }

    println!("Available profiles:");
    for entry in catalog {
        println!(
            "- {} | {} | family={} | variant={} | platform={}",
            entry.key, entry.display_name, entry.family, entry.variant, entry.platform
        );
    }
}
