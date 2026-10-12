//! A minimal JSON Schema validator for the keywords docs/report.schema.json
//! uses: type, properties, required, additionalProperties (boolean), items,
//! enum, const, minimum, maximum, maxLength, $ref (local "#/$defs/..."),
//! $defs. Written for the tests to avoid another dependency; anything else
//! in a schema is reported as unsupported so it cannot be silently ignored.

use serde_json::Value;

const KNOWN: [&str; 16] = [
    "$schema",
    "$id",
    "$defs",
    "$ref",
    "title",
    "description",
    "type",
    "properties",
    "required",
    "additionalProperties",
    "items",
    "enum",
    "const",
    "minimum",
    "maximum",
    "maxLength",
];

/// Returns a list of errors, each with a JSON-pointer-like path.
pub fn validate(schema_root: &Value, instance: &Value) -> Vec<String> {
    let mut errors = Vec::new();
    check(schema_root, schema_root, instance, "$", &mut errors);
    errors
}

fn type_matches(name: &str, v: &Value) -> bool {
    match name {
        "object" => v.is_object(),
        "array" => v.is_array(),
        "string" => v.is_string(),
        "boolean" => v.is_boolean(),
        "null" => v.is_null(),
        "number" => v.is_number(),
        "integer" => v.is_i64() || v.is_u64(),
        _ => false,
    }
}

fn check(root: &Value, schema: &Value, v: &Value, path: &str, errors: &mut Vec<String>) {
    let Some(obj) = schema.as_object() else {
        errors.push(format!("{path}: schema is not an object"));
        return;
    };
    for key in obj.keys() {
        if !KNOWN.contains(&key.as_str()) {
            errors.push(format!("{path}: unsupported schema keyword {key}"));
        }
    }
    if let Some(reference) = obj.get("$ref").and_then(Value::as_str) {
        // "#/$defs/finding" -> root["$defs"]["finding"]; `try_fold` stops at
        // the first missing segment.
        let target = reference
            .strip_prefix("#/")
            .and_then(|p| p.split('/').try_fold(root, |node, part| node.get(part)));
        match target {
            Some(t) => check(root, t, v, path, errors),
            None => errors.push(format!("{path}: unresolvable $ref {reference}")),
        }
    }
    if let Some(t) = obj.get("type") {
        let names: Vec<&str> = match t {
            Value::String(s) => vec![s.as_str()],
            Value::Array(a) => a.iter().filter_map(Value::as_str).collect(),
            _ => vec![],
        };
        if !names.iter().any(|n| type_matches(n, v)) {
            errors.push(format!("{path}: expected type {names:?}, got {v}"));
            return;
        }
    }
    if let Some(c) = obj.get("const") {
        if c != v {
            errors.push(format!("{path}: expected {c}, got {v}"));
        }
    }
    if let Some(Value::Array(options)) = obj.get("enum") {
        if !options.contains(v) {
            errors.push(format!("{path}: {v} is not one of {options:?}"));
        }
    }
    if let (Some(min), Some(n)) = (obj.get("minimum").and_then(Value::as_f64), v.as_f64()) {
        if n < min {
            errors.push(format!("{path}: {n} < minimum {min}"));
        }
    }
    if let (Some(max), Some(n)) = (obj.get("maximum").and_then(Value::as_f64), v.as_f64()) {
        if n > max {
            errors.push(format!("{path}: {n} > maximum {max}"));
        }
    }
    if let (Some(max), Some(s)) = (obj.get("maxLength").and_then(Value::as_u64), v.as_str()) {
        if s.chars().count() as u64 > max {
            errors.push(format!("{path}: string longer than {max}"));
        }
    }
    if let Some(map) = v.as_object() {
        if let Some(Value::Array(required)) = obj.get("required") {
            for r in required.iter().filter_map(Value::as_str) {
                if !map.contains_key(r) {
                    errors.push(format!("{path}: missing required property {r}"));
                }
            }
        }
        let props = obj.get("properties").and_then(Value::as_object);
        for (k, child) in map {
            match props.and_then(|p| p.get(k)) {
                Some(s) => check(root, s, child, &format!("{path}.{k}"), errors),
                None if obj.get("additionalProperties") == Some(&Value::Bool(false)) => {
                    errors.push(format!("{path}: unexpected property {k}"));
                }
                None => {}
            }
        }
    }
    if let (Some(items), Some(arr)) = (obj.get("items"), v.as_array()) {
        for (i, item) in arr.iter().enumerate() {
            check(root, items, item, &format!("{path}[{i}]"), errors);
        }
    }
}
