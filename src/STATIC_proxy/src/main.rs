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

use clap::Parser;
use static_proxy::{app::StaticApp, config::StaticConfig, utils::init_tracing};

/// Command-line interface definition using clap's derive API.
///
/// Minimal surface area: only expose configuration file path and logging format.
/// All behavioral config (bind address, TLS settings, stages, profiles) lives in TOML.
#[derive(Debug, Parser)]
#[command(
    name = "static",
    about = "STATIC: Synthetic Traffic and TLS Identity Camouflage"
)]
struct Cli {
    /// Path to the STATIC configuration file (TOML format).
    ///
    /// Default: config/static.example.toml (ships with the repo)
    ///
    /// Usage:
    /// ```sh
    /// # Use default config
    /// ./static_proxy
    ///
    /// # Use custom config
    /// ./static_proxy --config ~/.static_proxy/production.toml
    /// ```
    #[arg(short, long, default_value = "config/static.example.toml")]
    config: PathBuf,

    /// Enable JSON-formatted logs (default: human-readable stdout).
    #[arg(long, default_value_t = false)]
    json_logs: bool,
}

/// Application entry point: parse CLI, initialize logging, load config, run server.
///
/// Startup Sequence:
/// 1. Parse command-line arguments (clap validates types, required fields, etc.)
/// 2. Initialize tracing subscriber (stdout or JSON, based on --json-logs flag)
/// 3. Load TOML configuration file (validates schema, resolves paths)
/// 4. Create StaticApp (initializes TlsProvider, StagePipeline, TelemetrySink)
/// 5. Run the app (binds listener, enters accept loop)
///
/// 
/// Async Runtime:
/// #[tokio::main] macro expands to:
/// ```ignore
/// fn main() -> Result<()> {
///     tokio::runtime::Runtime::new()?.block_on(async_main())
/// }
/// ```
/// This creates a multi-threaded tokio runtime (default: one thread per CPU core)
/// and runs the async main function on it.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Parse CLI arguments (exits with usage message if invalid)
    let cli = Cli::parse();

    // Initialize tracing/logging (must happen before any tracing:: calls)
    init_tracing(cli.json_logs);

    // Load configuration from TOML file (validates schema, resolves paths)
    let config = StaticConfig::load(&cli.config)?;

    // Initialize the application (TLS provider, stages, telemetry)
    let app = StaticApp::new(config).await?;

    // Run the server (binds listener, accepts connections until Ctrl+C)
    app.run().await
}
