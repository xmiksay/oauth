//! Parsing webhook updates (pure). Only text messages in a private chat
//! with a human are commands; everything else is ignored, because in a
//! group anyone could post another member's `/start` code or `/stop`.

use serde::Deserialize;

#[derive(Deserialize)]
struct Update {
    message: Option<Message>,
}

#[derive(Deserialize)]
struct Message {
    chat: Chat,
    from: Option<Sender>,
    text: Option<String>,
}

#[derive(Deserialize)]
struct Chat {
    id: i64,
    #[serde(rename = "type")]
    kind: String,
}

#[derive(Deserialize)]
struct Sender {
    is_bot: bool,
    username: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    /// `/start <code>`; `None` when the parameter is missing or can't be
    /// a link code.
    Start(Option<String>),
    Stop,
    /// Any other text.
    Other,
}

/// A message the bot acts on.
#[derive(Debug, PartialEq, Eq)]
pub struct Incoming {
    pub chat_id: i64,
    /// The sender's @username (without `@`), when it has one.
    pub username: Option<String>,
    pub command: Command,
}

/// The longest `/start` parameter Telegram passes through deep links.
const MAX_START_PARAM: usize = 64;

fn start_param_ok(param: &str) -> bool {
    (1..=MAX_START_PARAM).contains(&param.len())
        && param
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn username_ok(name: &str) -> bool {
    (1..=64).contains(&name.len()) && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// `/name` or `/name@bot` (only for this bot) → the lower-cased name.
fn command_name<'a>(word: &'a str, bot_username: &str) -> Option<&'a str> {
    let name = word.strip_prefix('/')?;
    match name.split_once('@') {
        Some((name, bot)) if bot.eq_ignore_ascii_case(bot_username) => Some(name),
        Some(_) => None,
        None => Some(name),
    }
}

fn command(text: &str, bot_username: &str) -> Command {
    let mut words = text.split_whitespace();
    let Some(name) = words.next().and_then(|w| command_name(w, bot_username)) else {
        return Command::Other;
    };
    match name.to_ascii_lowercase().as_str() {
        "start" => {
            let param = words.next().filter(|p| start_param_ok(p));
            let single = words.next().is_none();
            Command::Start(param.filter(|_| single).map(str::to_owned))
        }
        "stop" => Command::Stop,
        _ => Command::Other,
    }
}

/// The command in a webhook body; `None` for anything to ignore silently
/// (malformed JSON, no message, non-private chat, bots, non-text).
pub fn parse(body: &[u8], bot_username: &str) -> Option<Incoming> {
    let update: Update = serde_json::from_slice(body).ok()?;
    let message = update.message?;
    let sender = message.from?;
    if message.chat.kind != "private" || sender.is_bot {
        return None;
    }
    let text = message.text?;
    Some(Incoming {
        chat_id: message.chat.id,
        username: sender.username.filter(|u| username_ok(u)),
        command: command(&text, bot_username),
    })
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    const BOT: &str = "oauth_bot";

    fn update(kind: &str, text: Value) -> Vec<u8> {
        json!({
            "update_id": 1,
            "message": {
                "message_id": 5,
                "date": 0,
                "chat": { "id": 42, "type": kind },
                "from": { "id": 42, "is_bot": false, "first_name": "Ann", "username": "ann_t" },
                "text": text,
            }
        })
        .to_string()
        .into_bytes()
    }

    fn cmd(text: &str) -> Command {
        parse(&update("private", json!(text)), BOT).unwrap().command
    }

    #[test]
    fn private_text_messages_are_commands() {
        let incoming = parse(&update("private", json!("/start abc-DEF_1")), BOT).unwrap();
        assert_eq!(
            incoming,
            Incoming {
                chat_id: 42,
                username: Some("ann_t".into()),
                command: Command::Start(Some("abc-DEF_1".into())),
            }
        );
        assert_eq!(
            cmd("  /start@OAuth_Bot   code1 "),
            Command::Start(Some("code1".into()))
        );
        assert_eq!(cmd("/START code1"), Command::Start(Some("code1".into())));
        assert_eq!(cmd("/stop"), Command::Stop);
        assert_eq!(cmd("/stop@oauth_bot please"), Command::Stop);
        assert_eq!(cmd("hello"), Command::Other);
        assert_eq!(cmd("/help"), Command::Other);
        assert_eq!(cmd("/stop@other_bot"), Command::Other);
    }

    #[test]
    fn bad_start_parameters_are_none() {
        for text in [
            "/start",
            "/start a/b",
            "/start two words",
            "/start code\u{0}",
            &format!("/start {}", "a".repeat(65)),
        ] {
            assert_eq!(cmd(text), Command::Start(None), "{text:?}");
        }
        assert_eq!(
            cmd(&format!("/start {}", "a".repeat(64))),
            Command::Start(Some("a".repeat(64)))
        );
    }

    #[test]
    fn everything_but_private_human_text_is_ignored() {
        for kind in ["group", "supergroup", "channel"] {
            assert_eq!(
                parse(&update(kind, json!("/start code")), BOT),
                None,
                "{kind}"
            );
        }
        assert_eq!(parse(&update("private", Value::Null), BOT), None);
        assert_eq!(parse(b"not json", BOT), None);
        assert_eq!(parse(br#"{"update_id":1}"#, BOT), None);
        let bot = json!({ "message": {
            "chat": { "id": 1, "type": "private" },
            "from": { "id": 1, "is_bot": true },
            "text": "/stop",
        }});
        assert_eq!(parse(bot.to_string().as_bytes(), BOT), None);
        let anonymous = json!({ "message": {
            "chat": { "id": 1, "type": "private" }, "text": "/stop",
        }});
        assert_eq!(parse(anonymous.to_string().as_bytes(), BOT), None);
    }

    #[test]
    fn odd_usernames_are_dropped() {
        let body = json!({ "message": {
            "chat": { "id": 1, "type": "private" },
            "from": { "id": 1, "is_bot": false, "username": "bad name" },
            "text": "/stop",
        }});
        assert_eq!(
            parse(body.to_string().as_bytes(), BOT).unwrap().username,
            None
        );
    }
}
