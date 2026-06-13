//! Sembazuru worker daemon (M3.1): serves the `Execution` control-plane service
//! on a loopback address. Usage:
//!
//! ```text
//! sembazuru-worker [listen_addr]      # default 127.0.0.1:50061
//! ```

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:50061".to_string());
    let addr: std::net::SocketAddr = addr.parse()?;

    let listener = tokio::net::TcpListener::bind(addr).await?;
    eprintln!(
        "sembazuru-worker: Execution service on {}",
        listener.local_addr()?
    );
    sembazuru_worker::serve_on_listener(listener).await
}
