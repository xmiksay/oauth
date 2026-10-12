use clap::{Parser, Subcommand};
use oauth_server::{config::Config, serve};

#[derive(Parser)]
#[command(
    name = "oauth",
    version,
    about = "Entra-like multi-tenant OAuth 2.1 / OIDC provider"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the HTTP server (migrates the database on startup).
    Serve,
    /// Create the `system` tenant and its first Global Admin (idempotent).
    Bootstrap {
        /// Email of the first Global Admin of the `system` tenant.
        #[arg(long)]
        admin_email: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Serve => {
            let config = Config::from_env()?;
            serve::init_tracing(config.log_format)?;
            serve::run(config).await
        }
        Command::Bootstrap { admin_email: _ } => anyhow::bail!(
            "`oauth bootstrap` is not implemented yet; it lands in M1a step 2 (feat/m1a-directory)"
        ),
    }
}
