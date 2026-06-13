//! Sembazuru agent CLI (M3.1): runs one command on a remote worker and exits
//! with the remote process's exit code. Usage:
//!
//! ```text
//! sembazuru-agent <worker_endpoint> -- <argv>...
//! # e.g. sembazuru-agent http://127.0.0.1:50061 -- cmd /c echo hello
//! ```

use sembazuru_proto::v0::Command;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let sep = args.iter().position(|a| a == "--");
    let (endpoint, argv) = match sep {
        Some(i) if i >= 1 && i + 1 < args.len() => (args[0].clone(), args[i + 1..].to_vec()),
        _ => {
            eprintln!("usage: sembazuru-agent <worker_endpoint> -- <argv>...");
            std::process::exit(2);
        }
    };

    let command = Command {
        argv,
        env: Default::default(),
        cwd: std::env::current_dir()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default(),
    };

    let outcome = sembazuru_agent::execute_remote(
        endpoint,
        command,
        "cli-action".to_string(),
        "cli-session".to_string(),
    )
    .await?;

    match outcome.exit_code {
        Some(code) => std::process::exit(code),
        None => {
            eprintln!("sembazuru-agent: action did not complete (no exit status)");
            std::process::exit(1);
        }
    }
}
