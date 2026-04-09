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

use std::path::PathBuf;

use clap::{Parser, ValueEnum};
use static_proxy::{app::{RunMode, StaticApp}, config::StaticConfig, utils::init_tracing};

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
    #[arg(short, long, default_value = "config/static.example.toml")]
    config: PathBuf,

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

    let cli = Cli::parse();

    init_tracing(cli.json_logs);

    let config = StaticConfig::load(&cli.config)?;

    let app = StaticApp::new(config, cli.mode.into()).await?;

    app.run().await
}
