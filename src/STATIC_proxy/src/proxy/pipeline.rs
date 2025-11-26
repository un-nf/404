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

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite};

/// Bidirectional copy between client and upstream streams (data plane).
///
/// **Purpose:**
/// After the pipeline completes (request/response headers/body mutations), we forward
/// encrypted bytes between client and upstream without further inspection. This is the
/// "transparent proxy" phase where we're just a dumb pipe.
///
/// **Implementation:**
/// Uses tokio::io::copy_bidirectional to concurrently copy data in both directions:
/// - Client → Upstream: Forward remaining request data (body, pipelined requests)
/// - Upstream → Client: Forward response (headers, body, keep-alive connections)
///
/// **Termination:**
/// Stops when either side closes the connection (EOF) or encounters an error. This is
/// normal for HTTP/1.1 connections where the client closes after receiving the response.
///
/// **Error Handling:**
/// Errors are expected (client disconnects, upstream timeouts, network failures). We log
/// and propagate them to handle_connection, which closes both sides gracefully.
///
/// **Future Enhancements:**
/// - Add instrumentation (bytes transferred, duration, throughput)
/// - Implement backpressure handling for slow readers
/// - Add timeout for idle connections
pub async fn proxy_data<C, U>(client: &mut C, upstream: &mut U) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    // Copy bidirectionally until one side closes or errors
    let (client_to_upstream, upstream_to_client) =
        tokio::io::copy_bidirectional(client, upstream).await?;

    tracing::debug!(
        client_to_upstream,
        upstream_to_client,
        "bidirectional copy completed"
    );

    Ok(())
}
