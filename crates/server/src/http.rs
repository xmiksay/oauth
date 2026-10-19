//! Outbound HTTP: one hardened reqwest client recipe (Telegram Bot API,
//! upstream identity providers) and bounded response reading.

use std::{sync::Arc, time::Duration};

use anyhow::{Context, bail};

/// Timeouts of one client: the whole request, and connecting.
#[derive(Clone, Copy, Debug)]
pub struct Timeouts {
    pub total: Duration,
    pub connect: Duration,
}

/// A client on rustls with the AWS-LC provider and webpki roots that never
/// follows redirects (a redirect could bounce a request carrying a secret
/// elsewhere) and never uses an environment proxy (it would see every URL
/// and body). `https_only = false` is for loopback test servers; callers
/// that allow it check each URL themselves.
pub fn client(
    timeouts: Timeouts,
    https_only: bool,
    resolver: Option<Arc<dyn reqwest::dns::Resolve>>,
) -> anyhow::Result<reqwest::Client> {
    // An explicit AWS-LC provider: rustls is also built with ring (sqlx),
    // so there is no unambiguous process default to fall back on.
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("TLS protocol versions for the HTTP client")?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut builder = reqwest::Client::builder();
    if let Some(resolver) = resolver {
        builder = builder.dns_resolver(resolver);
    }
    builder
        .tls_backend_preconfigured(tls)
        .timeout(timeouts.total)
        .connect_timeout(timeouts.connect)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .https_only(https_only)
        .build()
        .map_err(|e| anyhow::anyhow!("building the HTTP client: {}", e.without_url()))
}

/// Reads at most `max` bytes of the body; a longer one is an error, so a
/// hostile server can't make us buffer without bound.
pub async fn read_capped(mut response: reqwest::Response, max: usize) -> anyhow::Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|len| len > max as u64)
    {
        bail!("response body too large");
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| anyhow::anyhow!("reading response body: {}", e.without_url()))?
    {
        if body.len() + chunk.len() > max {
            bail!("response body too large");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_both_variants() {
        let t = Timeouts {
            total: Duration::from_secs(1),
            connect: Duration::from_secs(1),
        };
        assert!(client(t, true, None).is_ok());
        assert!(client(t, false, None).is_ok());
    }
}
