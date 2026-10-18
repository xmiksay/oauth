use clap::{Parser, Subcommand};
use oauth_server::{bootstrap, config::Config, db, serve, telegram};

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
    /// Create the `system` tenant and its first Global Admin (idempotent;
    /// migrates first). Prints a one-time password when the admin is created.
    Bootstrap {
        /// Email of the Global Admin of the `system` tenant.
        #[arg(long)]
        admin_email: String,
        /// Display name for a newly created admin.
        #[arg(long)]
        display_name: Option<String>,
        /// Issue a new one-time password if the admin already exists.
        #[arg(long)]
        reset_password: bool,
    },
    /// Telegram bot administration.
    Telegram {
        #[command(subcommand)]
        command: TelegramCommand,
    },
}

#[derive(Subcommand)]
enum TelegramCommand {
    /// Register `{PUBLIC_URL}/telegram/webhook` (with the webhook secret)
    /// as the bot's webhook.
    SetWebhook,
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
        Command::Bootstrap {
            admin_email,
            display_name,
            reset_password,
        } => {
            let config = Config::from_env()?;
            serve::init_tracing(config.log_format)?;
            let db = db::connect(&config.database_url).await?;
            let opts = bootstrap::Options {
                admin_email,
                display_name,
                reset_password,
            };
            let report = bootstrap::run(&db, &config, &opts).await?;
            println!("{}", report.render());
            Ok(())
        }
        Command::Telegram {
            command: TelegramCommand::SetWebhook,
        } => {
            let config = Config::from_env()?;
            serve::init_tracing(config.log_format)?;
            let url = telegram::set_webhook(&config).await?;
            println!("Telegram webhook registered: {url}");
            Ok(())
        }
    }
}
