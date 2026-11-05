//! Bounded structural decoding that preserves duplicate-key failures across Serde formats.

use std::fmt;

use serde::Deserializer;
use serde::de::{DeserializeSeed, Error, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

use super::{
    MAX_DIRECT_EXCEPTIONS, MAX_POLICY_INPUT_BYTES, MAX_PORT_RANGES, MAX_RULES, PolicyError,
    PolicyErrorCode,
};

struct Budget {
    bytes: usize,
    nodes: usize,
    error: Option<PolicyError>,
}

impl Budget {
    fn new(limit: usize) -> Self {
        Self {
            bytes: limit,
            nodes: limit,
            error: None,
        }
    }

    fn reject<E: Error>(&mut self, error: PolicyError) -> E {
        let message = error.to_string();
        if self.error.is_none() {
            self.error = Some(error);
        }
        E::custom(message)
    }

    fn charge<E: Error>(&mut self, bytes: usize, path: &str) -> Result<(), E> {
        if bytes > self.bytes || self.nodes == 0 {
            return Err(self.reject(PolicyError::new(PolicyErrorCode::InputTooLarge, path)));
        }
        self.bytes -= bytes;
        self.nodes -= 1;
        Ok(())
    }
}

struct Seed<'a> {
    budget: &'a mut Budget,
    path: String,
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = Value;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        if self.depth > 32 {
            return Err(self
                .budget
                .reject(PolicyError::new(PolicyErrorCode::InvalidSyntax, &self.path)));
        }
        self.budget.charge::<D::Error>(1, &self.path)?;
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Seed<'_> {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded policy data")
    }

    fn visit_bool<E: Error>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }
    fn visit_i64<E: Error>(self, value: i64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }
    fn visit_u64<E: Error>(self, value: u64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }
    fn visit_f64<E: Error>(self, value: f64) -> Result<Value, E> {
        match Number::from_f64(value) {
            Some(value) => Ok(Value::Number(value)),
            None => Err(self
                .budget
                .reject(PolicyError::new(PolicyErrorCode::InvalidSyntax, &self.path))),
        }
    }
    fn visit_unit<E: Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_none<E: Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_str<E: Error>(self, value: &str) -> Result<Value, E> {
        self.budget.charge::<E>(value.len(), &self.path)?;
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E: Error>(self, value: String) -> Result<Value, E> {
        self.budget.charge::<E>(value.len(), &self.path)?;
        Ok(Value::String(value))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Value, A::Error> {
        let limit = if self.path == "config.rules" {
            MAX_RULES
        } else if self.path == "config.direct_exceptions" {
            MAX_DIRECT_EXCEPTIONS
        } else if self.path == "authorizations.proxy_uid_grants"
            || self.path == "authorizations.system_profiles"
            || self.path.starts_with("authorizations.") && self.path.ends_with(".recipes")
        {
            4
        } else if self.path.starts_with("authorizations.")
            && (self.path.ends_with(".families") || self.path.ends_with(".protocols"))
        {
            2
        } else if self.path.ends_with(".source_ports") || self.path.ends_with(".destination_ports")
        {
            MAX_PORT_RANGES
        } else {
            MAX_RULES
        };
        let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(limit));
        loop {
            // Decode at most one extra bounded item to distinguish an exact bound from overflow.
            let next = sequence.next_element_seed(Seed {
                budget: self.budget,
                path: format!("{}[{}]", self.path, values.len()),
                depth: self.depth + 1,
            })?;
            let Some(value) = next else {
                break;
            };
            if values.len() == limit {
                return Err(self.budget.reject(PolicyError::bounded(
                    PolicyErrorCode::TooManyItems,
                    &self.path,
                    limit,
                    limit + 1,
                )));
            }
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            self.budget.charge::<A::Error>(key.len(), &self.path)?;
            if values.contains_key(&key) {
                return Err(self
                    .budget
                    .reject(PolicyError::new(PolicyErrorCode::InvalidSyntax, &self.path)));
            }
            let value = map.next_value_seed(Seed {
                budget: self.budget,
                path: field_path(&self.path, &key),
                depth: self.depth + 1,
            })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

fn field_path(parent: &str, key: &str) -> String {
    const FIELDS: &[&str] = &[
        "schema_version",
        "desired",
        "rules",
        "direct_exceptions",
        "id",
        "priority",
        "action",
        "destination",
        "protocol",
        "source_ports",
        "destination_ports",
        "icmp_type",
        "icmp_code",
        "start",
        "end",
        "purpose",
        "description",
        "egress_profile",
        "proxy_uid_grants",
        "system_profiles",
        "uid",
        "protocols",
        "families",
        "recipes",
    ];
    let label = if FIELDS.contains(&key) {
        key
    } else {
        "<unknown>"
    };
    format!("{parent}.{label}")
}

pub(super) fn deserialize_value<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Value, D::Error> {
    deserialize_with_limit(deserializer, MAX_POLICY_INPUT_BYTES, "config")
}

pub(crate) fn deserialize_with_limit<'de, D: Deserializer<'de>>(
    deserializer: D,
    limit: usize,
    root: &str,
) -> Result<Value, D::Error> {
    let mut budget = Budget::new(limit);
    Seed {
        budget: &mut budget,
        path: root.into(),
        depth: 0,
    }
    .deserialize(deserializer)
}

fn text<'a>(input: &'a [u8], limit: usize, root: &str) -> Result<&'a str, PolicyError> {
    if input.len() > limit {
        return Err(PolicyError::bounded(
            PolicyErrorCode::InputTooLarge,
            root,
            limit,
            input.len(),
        ));
    }
    std::str::from_utf8(input).map_err(|_| PolicyError::new(PolicyErrorCode::InvalidEncoding, root))
}

pub(super) fn toml(input: &[u8]) -> Result<Value, PolicyError> {
    toml_with_limit(input, MAX_POLICY_INPUT_BYTES, "config")
}

pub(crate) fn toml_with_limit(
    input: &[u8],
    limit: usize,
    root: &str,
) -> Result<Value, PolicyError> {
    let source = text(input, limit, root)?;
    let deserializer = toml::Deserializer::parse(source)
        .map_err(|_| PolicyError::new(PolicyErrorCode::InvalidSyntax, root))?;
    let mut budget = Budget::new(limit);
    match (Seed {
        budget: &mut budget,
        path: root.into(),
        depth: 0,
    })
    .deserialize(deserializer)
    {
        Ok(value) => Ok(value),
        Err(_) => Err(match budget.error {
            Some(error) => error,
            None => PolicyError::new(PolicyErrorCode::InvalidSyntax, root),
        }),
    }
}

pub(super) fn json(input: &[u8]) -> Result<Value, PolicyError> {
    json_with_limit(input, MAX_POLICY_INPUT_BYTES, "config")
}

pub(crate) fn json_with_limit(
    input: &[u8],
    limit: usize,
    root: &str,
) -> Result<Value, PolicyError> {
    let source = text(input, limit, root)?;
    check_surrogates(source).map_err(|error| PolicyError::new(error.code(), root))?;
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    let mut budget = Budget::new(limit);
    let result = (Seed {
        budget: &mut budget,
        path: root.into(),
        depth: 0,
    })
    .deserialize(&mut deserializer);
    match result {
        Ok(value) => {
            deserializer
                .end()
                .map_err(|_| PolicyError::new(PolicyErrorCode::InvalidSyntax, root))?;
            Ok(value)
        }
        Err(_) => Err(match budget.error {
            Some(error) => error,
            None => PolicyError::new(PolicyErrorCode::InvalidSyntax, root),
        }),
    }
}

fn hex4(bytes: &[u8], offset: usize) -> Option<u16> {
    let digits = bytes.get(offset..offset.checked_add(4)?)?;
    let mut value = 0_u16;
    for digit in digits {
        let nibble = match digit {
            b'0'..=b'9' => u16::from(*digit - b'0'),
            b'a'..=b'f' => u16::from(*digit - b'a' + 10),
            b'A'..=b'F' => u16::from(*digit - b'A' + 10),
            _ => return None,
        };
        value = value * 16 + nibble;
    }
    Some(value)
}

fn check_surrogates(source: &str) -> Result<(), PolicyError> {
    // Only classify valid \uXXXX escape spelling inside strings. Serde still owns JSON syntax;
    // this preflight provides a typed encoding error without matching parser error strings.
    let bytes = source.as_bytes();
    let mut offset = 0;
    let mut in_string = false;
    while let Some(&byte) = bytes.get(offset) {
        if byte == b'"' {
            in_string = !in_string;
            offset += 1;
            continue;
        }
        if in_string && byte == b'\\' {
            if bytes.get(offset + 1) == Some(&b'u')
                && let Some(unit) = hex4(bytes, offset + 2)
            {
                if (0xD800..=0xDBFF).contains(&unit) {
                    let pair = bytes.get(offset + 6..offset + 8) == Some(&b"\\u"[..]);
                    let low = hex4(bytes, offset + 8);
                    if !pair || !low.is_some_and(|value| (0xDC00..=0xDFFF).contains(&value)) {
                        return Err(PolicyError::new(PolicyErrorCode::InvalidEncoding, "config"));
                    }
                    offset += 12;
                    continue;
                }
                if (0xDC00..=0xDFFF).contains(&unit) {
                    return Err(PolicyError::new(PolicyErrorCode::InvalidEncoding, "config"));
                }
                offset += 6;
                continue;
            }
            offset += 2;
        } else {
            offset += 1;
        }
    }
    Ok(())
}
