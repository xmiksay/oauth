//! Defensive CBOR access over `ciborium::Value`. Callers bound the input
//! size first; nesting is capped here, so a hostile item costs at most
//! O(input) memory and never recurses deeply.

use ciborium::Value;

use super::WebauthnError;

/// Deepest nesting accepted (attestation statements with certificate
/// chains need 3–4 levels).
const MAX_DEPTH: usize = 16;
/// Largest map whose keys we look up (and check for duplicates).
const MAX_MAP_ENTRIES: usize = 32;

/// Decodes one item from the front of `input`; returns it and the number
/// of bytes it occupied.
pub fn decode_prefix(input: &[u8], what: &'static str) -> Result<(Value, usize), WebauthnError> {
    let mut rest = input;
    let value: Value = ciborium::de::from_reader_with_recursion_limit(&mut rest, MAX_DEPTH)
        .map_err(|_| WebauthnError::Malformed(what))?;
    Ok((value, input.len() - rest.len()))
}

/// Decodes `input`, which must be exactly one item.
pub fn decode_exact(input: &[u8], what: &'static str) -> Result<Value, WebauthnError> {
    let (value, used) = decode_prefix(input, what)?;
    if used != input.len() {
        return Err(WebauthnError::Malformed(what));
    }
    Ok(value)
}

/// A map's entries, refusing oversized maps and duplicate keys (an
/// ambiguous map could be read differently by another parser).
pub fn map<'a>(
    value: &'a Value,
    what: &'static str,
) -> Result<&'a [(Value, Value)], WebauthnError> {
    let entries = value.as_map().ok_or(WebauthnError::Malformed(what))?;
    if entries.len() > MAX_MAP_ENTRIES {
        return Err(WebauthnError::Malformed(what));
    }
    for (i, (key, _)) in entries.iter().enumerate() {
        if entries.iter().skip(i + 1).any(|(other, _)| other == key) {
            return Err(WebauthnError::Malformed(what));
        }
    }
    Ok(entries)
}

/// The value under integer key `key`.
pub fn int_key(entries: &[(Value, Value)], key: i64) -> Option<&Value> {
    entries
        .iter()
        .find(|(k, _)| k.as_integer().map(i128::from) == Some(i128::from(key)))
        .map(|(_, v)| v)
}

/// The value under text key `key`.
pub fn text_key<'a>(entries: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    entries
        .iter()
        .find(|(k, _)| k.as_text() == Some(key))
        .map(|(_, v)| v)
}

pub fn int(value: Option<&Value>, what: &'static str) -> Result<i64, WebauthnError> {
    value
        .and_then(Value::as_integer)
        .and_then(|i| i64::try_from(i).ok())
        .ok_or(WebauthnError::Malformed(what))
}

pub fn bytes<'a>(value: Option<&'a Value>, what: &'static str) -> Result<&'a [u8], WebauthnError> {
    value
        .and_then(Value::as_bytes)
        .map(Vec::as_slice)
        .ok_or(WebauthnError::Malformed(what))
}

pub fn text<'a>(value: Option<&'a Value>, what: &'static str) -> Result<&'a str, WebauthnError> {
    value
        .and_then(Value::as_text)
        .ok_or(WebauthnError::Malformed(what))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode(value: &Value) -> Vec<u8> {
        let mut out = Vec::new();
        ciborium::ser::into_writer(value, &mut out).unwrap();
        out
    }

    #[test]
    fn prefix_reports_consumed_length() {
        let mut input = encode(&Value::Map(vec![(
            Value::Integer(1.into()),
            Value::Bytes(vec![7; 40]),
        )]));
        let item_len = input.len();
        input.extend_from_slice(&[0xa0, 0xff]);
        let (value, used) = decode_prefix(&input, "x").unwrap();
        assert_eq!(used, item_len);
        let entries = map(&value, "x").unwrap();
        assert_eq!(bytes(int_key(entries, 1), "x").unwrap(), &[7; 40]);
        assert!(int_key(entries, 2).is_none());
        assert!(decode_exact(&input, "x").is_err());
        assert!(decode_exact(&input[..item_len], "x").is_ok());
    }

    #[test]
    fn duplicate_and_oversized_maps_are_rejected() {
        let one = || (Value::Integer(1.into()), Value::Null);
        assert!(map(&Value::Map(vec![one(), one()]), "x").is_err());
        let big = (0..33)
            .map(|i| (Value::Integer(i.into()), Value::Null))
            .collect();
        assert!(map(&Value::Map(big), "x").is_err());
        assert!(map(&Value::Array(vec![]), "x").is_err());
    }

    #[test]
    fn deep_nesting_is_rejected() {
        // 64 nested one-element arrays: 0x81 0x81 … 0x00.
        let mut deep = vec![0x81; 64];
        deep.push(0x00);
        assert!(decode_exact(&deep, "x").is_err());
        let mut shallow = vec![0x81; 8];
        shallow.push(0x00);
        assert!(decode_exact(&shallow, "x").is_ok());
    }

    #[test]
    fn declared_lengths_beyond_the_input_fail_without_allocating() {
        // Byte string claiming 2^63 bytes; array claiming 2^32 items.
        let huge_bytes = [0x5b, 0x80, 0, 0, 0, 0, 0, 0, 0, 1];
        assert!(decode_exact(&huge_bytes, "x").is_err());
        let huge_array = [0x9a, 0xff, 0xff, 0xff, 0xff, 0x00];
        assert!(decode_exact(&huge_array, "x").is_err());
        assert!(decode_exact(&[], "x").is_err());
    }

    #[test]
    fn typed_accessors() {
        let entries = vec![
            (Value::Text("fmt".into()), Value::Text("none".into())),
            (Value::Integer(3.into()), Value::Integer((-7).into())),
        ];
        assert_eq!(text(text_key(&entries, "fmt"), "x").unwrap(), "none");
        assert_eq!(int(int_key(&entries, 3), "x").unwrap(), -7);
        assert!(int(text_key(&entries, "fmt"), "x").is_err());
        assert!(bytes(None, "x").is_err());
    }
}
