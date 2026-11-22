use std::path::PathBuf;

use anyhow::Context;
use clap::{ArgGroup, Parser, Subcommand};
use oauth_server::{
    bootstrap::{self, TenantOptions, provisioning},
    config::Config,
    db, provision, serve, telegram,
};

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
    /// Create a tenant (the system tenant, SYSTEM_TENANT_SLUG, unless
    /// --tenant), its first Global Admin
    /// and / or a provisioning app (idempotent; migrates first). Prints a
    /// one-time password / client secret when one is issued.
    #[command(group(ArgGroup::new("what").required(true).multiple(true)
        .args(["admin_email", "provisioning_app"])))]
    Bootstrap {
        /// Email of a Global Admin of the tenant.
        #[arg(long)]
        admin_email: Option<String>,
        /// Display name for a newly created admin.
        #[arg(long)]
        display_name: Option<String>,
        /// Issue a new one-time password if the admin already exists.
        #[arg(long)]
        reset_password: bool,
        /// Bootstrap this regular tenant (created when missing) instead of
        /// the system tenant.
        #[arg(long)]
        tenant: Option<String>,
        /// Display name of a newly created --tenant (default: its slug).
        #[arg(long, requires = "tenant")]
        tenant_name: Option<String>,
        /// client_id of a confidential app holding a management API role
        /// (client credentials); its secret is printed when it is created.
        #[arg(long)]
        provisioning_app: Option<String>,
        /// The management API role of the provisioning app.
        #[arg(long, value_enum, default_value_t = provisioning::Role::ReadWrite, requires = "provisioning_app")]
        provisioning_role: provisioning::Role,
        /// Issue a new secret for an existing provisioning app.
        #[arg(long, requires = "provisioning_app")]
        rotate_secret: bool,
    },
    /// Apply a declarative tenant file (YAML) in one transaction: create /
    /// update what it declares, delete managed objects it no longer does.
    Apply {
        /// The tenant file.
        #[arg(short = 'f', long = "file")]
        file: PathBuf,
        /// Print the changes without writing anything.
        #[arg(long)]
        dry_run: bool,
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
            tenant,
            tenant_name,
            provisioning_app,
            provisioning_role,
            rotate_secret,
        } => {
            let config = Config::from_env()?;
            serve::init_tracing(config.log_format)?;
            let db = db::connect(&config.database_url).await?;
            let opts = bootstrap::Options {
                admin_email,
                display_name,
                reset_password,
                tenant: tenant.map(|slug| TenantOptions {
                    slug,
                    display_name: tenant_name,
                }),
                provisioning: provisioning_app.map(|client_id| provisioning::Options {
                    client_id,
                    role: provisioning_role,
                    rotate_secret,
                }),
            };
            let report = bootstrap::run(&db, &config, &opts).await?;
            println!("{}", report.render());
            Ok(())
        }
        Command::Apply { file, dry_run } => {
            let config = Config::from_env()?;
            serve::init_tracing(config.log_format)?;
            let text = std::fs::read_to_string(&file)
                .with_context(|| format!("reading {}", file.display()))?;
            let spec = provision::parse(&text)?;
            let db = db::connect(&config.database_url).await?;
            // `Spec::check` already refused other names; this keeps the
            // server's own secrets out of reach should a path skip it.
            let env = |name: &str| {
                name.starts_with(provision::spec::ENV_PREFIX)
                    .then(|| std::env::var(name).ok())
                    .flatten()
            };
            let opts = provision::Options { dry_run };
            let report = provision::run(&db, &config, &spec, &opts, &env).await?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_is_well_formed() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }

    #[test]
    fn bootstrap_needs_an_admin_or_a_provisioning_app() {
        assert!(Cli::try_parse_from(["oauth", "bootstrap"]).is_err());
        assert!(Cli::try_parse_from(["oauth", "bootstrap", "--tenant", "acme"]).is_err());
        assert!(
            Cli::try_parse_from([
                "oauth",
                "bootstrap",
                "--rotate-secret",
                "--admin-email",
                "a@b.c"
            ])
            .is_err()
        );
        let ok = Cli::try_parse_from([
            "oauth",
            "bootstrap",
            "--tenant",
            "acme",
            "--provisioning-app",
            "ci",
            "--provisioning-role",
            "read",
        ]);
        assert!(ok.is_ok());
        assert!(Cli::try_parse_from(["oauth", "apply", "-f", "t.yaml", "--dry-run"]).is_ok());
    }
}
