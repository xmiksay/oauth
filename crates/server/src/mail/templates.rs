//! Plain-text email templates. Every interpolated value is either from the
//! database (names and addresses, which never contain control characters)
//! or passed through [`clean`], so nothing can inject headers or lines.

use chrono::Duration;
use entity::enums::{EmailTokenPurpose, NotifyEvent};
use sea_orm::ActiveEnum;
use zeroize::Zeroizing;

/// A rendered message; `kind` is stored on the outbox row (never the body).
pub struct Rendered {
    pub kind: String,
    pub subject: String,
    pub body: Zeroizing<String>,
}

/// Who the message is about, for salutations and subjects.
pub struct Ctx<'a> {
    pub tenant_name: &'a str,
    pub user_name: &'a str,
    /// The account's current address.
    pub user_email: &'a str,
}

/// "30 minutes", "24 hours", "7 days".
fn human(ttl: Duration) -> String {
    let plural = |n: i64, unit: &str| format!("{n} {unit}{}", if n == 1 { "" } else { "s" });
    if ttl.num_days() >= 2 && ttl.num_hours() % 24 == 0 {
        plural(ttl.num_days(), "day")
    } else if ttl.num_hours() >= 1 && ttl.num_minutes() % 60 == 0 {
        plural(ttl.num_hours(), "hour")
    } else {
        plural(ttl.num_minutes().max(1), "minute")
    }
}

/// One line of untrusted text (e.g. a user agent): control characters
/// dropped, length bounded.
pub fn clean(value: &str) -> String {
    value
        .chars()
        .filter(|c| !c.is_control())
        .take(200)
        .collect()
}

/// `j***@example.com`: enough for the owner to recognise, little for anyone
/// else reading the mail.
pub fn mask_email(email: &str) -> String {
    match email.split_once('@') {
        Some((local, domain)) => {
            let first: String = local.chars().take(1).collect();
            format!("{first}***@{domain}")
        }
        None => "***".to_owned(),
    }
}

/// The message carrying an email link (`link` already contains its token).
pub fn link_message(
    ctx: &Ctx<'_>,
    purpose: EmailTokenPurpose,
    link: &str,
    ttl: Duration,
    new_email: Option<&str>,
) -> Rendered {
    let (tenant, expires) = (ctx.tenant_name, human(ttl));
    let (subject, intro, outro) = match purpose {
        EmailTokenPurpose::Verify => (
            format!("Verify your email address for {tenant}"),
            format!(
                "Please confirm that this is the email address of your {tenant} account by \
                 opening this link:"
            ),
            format!("The link expires in {expires}. If you didn't expect this message, ignore it."),
        ),
        EmailTokenPurpose::Reset => (
            format!("Reset your {tenant} password"),
            format!(
                "Someone (hopefully you) asked to reset the password of your {tenant} account. \
                 To choose a new password, open:"
            ),
            format!(
                "The link expires in {expires} and works once. Resetting the password signs you \
                 out everywhere; your second factor stays required.\nIf you didn't ask for this, \
                 ignore this message: your password is unchanged."
            ),
        ),
        EmailTokenPurpose::Invite => (
            format!("You're invited to {tenant}"),
            format!(
                "An administrator created a {tenant} account for you. To set your password and \
                 start using it, open:"
            ),
            format!("The link expires in {expires} and works once."),
        ),
        EmailTokenPurpose::Change => (
            format!("Confirm your new email address for {tenant}"),
            format!(
                "Someone asked to make {} the email address of the {tenant} account {}. To \
                 confirm, open:",
                new_email.unwrap_or("this address"),
                mask_email(ctx.user_email),
            ),
            format!(
                "The link expires in {expires}. If you didn't request this, ignore it: nothing \
                 changes."
            ),
        ),
    };
    // A change link goes to an address nobody has proven yet: it must not
    // carry text the requester chose (the display name).
    let greeting = if purpose == EmailTokenPurpose::Change {
        "Hello,".to_owned()
    } else {
        format!("Hello {},", ctx.user_name)
    };
    Rendered {
        kind: purpose.to_value(),
        subject,
        body: Zeroizing::new(format!("{greeting}\n\n{intro}\n\n{link}\n\n{outro}\n")),
    }
}

/// A security notice. `facts` are label / value lines (values [`clean`]ed);
/// `account_url` is where the user reviews their account.
pub fn notice(
    ctx: &Ctx<'_>,
    event: NotifyEvent,
    facts: &[(&str, String)],
    account_url: &str,
) -> Rendered {
    let tenant = ctx.tenant_name;
    let (subject, intro) = match event {
        NotifyEvent::PasswordChanged => (
            format!("Your {tenant} password was changed"),
            "The password of your account was changed.",
        ),
        NotifyEvent::MfaChanged => (
            format!("Your {tenant} sign-in methods changed"),
            "The second-factor sign-in methods of your account changed.",
        ),
        NotifyEvent::EmailChanged => (
            format!("Your {tenant} email address was changed"),
            "The email address of your account was changed; this address no longer receives \
             its messages.",
        ),
        NotifyEvent::NewSignIn => (
            format!("New sign-in to your {tenant} account"),
            "Your account was signed in to from a browser it hasn't been used from before.",
        ),
        NotifyEvent::TokenReuse => (
            format!("Suspicious activity on your {tenant} account"),
            "A sign-in token of an application was used twice, which can mean it was stolen. \
             The application was signed out.",
        ),
    };
    let mut body = format!("Hello {},\n\n{intro}\n\n", ctx.user_name);
    for (label, value) in facts {
        body.push_str(&format!("  {label}: {}\n", clean(value)));
    }
    if !facts.is_empty() {
        body.push('\n');
    }
    body.push_str(&format!(
        "If this was you, no action is needed. If not, reset your password and review your \
         sign-in methods at:\n\n{account_url}\n"
    ));
    Rendered {
        kind: format!("notice_{}", event.to_value()),
        subject,
        body: Zeroizing::new(body),
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::Iterable;

    use super::*;

    const CTX: Ctx<'static> = Ctx {
        tenant_name: "Contoso",
        user_name: "Ann",
        user_email: "ann@example.com",
    };

    #[test]
    fn emails_are_masked() {
        assert_eq!(mask_email("john@example.com"), "j***@example.com");
        assert_eq!(mask_email("Žofie@x.cz"), "Ž***@x.cz");
        assert_eq!(mask_email("nobody"), "***");
    }

    #[test]
    fn durations_read_naturally() {
        assert_eq!(human(Duration::minutes(30)), "30 minutes");
        assert_eq!(human(Duration::hours(1)), "1 hour");
        assert_eq!(human(Duration::hours(24)), "24 hours");
        assert_eq!(human(Duration::days(7)), "7 days");
        assert_eq!(human(Duration::seconds(5)), "1 minute");
    }

    #[test]
    fn link_messages_carry_the_link_and_expiry() {
        let link = "https://contoso.id.example/login/reset#token=abc";
        for purpose in EmailTokenPurpose::iter() {
            let r = link_message(&CTX, purpose, link, Duration::minutes(30), Some("new@x.io"));
            assert_eq!(r.kind, purpose.to_value());
            assert!(r.subject.contains("Contoso") && !r.subject.contains('\n'));
            let greeting = if purpose == EmailTokenPurpose::Change {
                "Hello,\n\n"
            } else {
                "Hello Ann,\n\n"
            };
            assert!(r.body.starts_with(greeting), "{}", r.body.as_str());
            assert!(r.body.contains(&format!("\n\n{link}\n\n")));
            assert!(r.body.contains("30 minutes"), "{}", r.body.as_str());
        }
        let change = link_message(
            &CTX,
            EmailTokenPurpose::Change,
            link,
            Duration::hours(24),
            Some("new@x.io"),
        );
        assert!(
            change.body.contains(
                "make new@x.io the email address of the Contoso account a***@example.com"
            )
        );
        assert!(
            change
                .body
                .contains("If you didn't request this, ignore it")
        );
        // The requester-chosen display name never reaches an unproven address.
        assert!(!change.body.contains("Ann"), "{}", change.body.as_str());
    }

    #[test]
    fn notices_list_cleaned_facts() {
        for event in NotifyEvent::iter() {
            let r = notice(&CTX, event, &[], "https://c/myaccount");
            assert!(
                r.kind.starts_with("notice_")
                    && r.kind.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
            );
            assert!(r.subject.contains("Contoso"));
            assert!(r.body.ends_with("https://c/myaccount\n"));
        }
        let facts = [
            ("Browser", "Evil\r\nBcc: x@y\u{7}".to_owned()),
            ("IP address", "203.0.113.7".into()),
        ];
        let r = notice(&CTX, NotifyEvent::NewSignIn, &facts, "https://c/myaccount");
        assert!(
            r.body.contains("  Browser: EvilBcc: x@y\n"),
            "{}",
            r.body.as_str()
        );
        assert!(r.body.contains("  IP address: 203.0.113.7\n"));
        assert_eq!(clean(&"x".repeat(500)).len(), 200);
    }
}
