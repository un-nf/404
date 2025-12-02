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
